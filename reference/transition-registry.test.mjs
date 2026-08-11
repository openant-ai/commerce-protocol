import assert from "node:assert/strict";
import test from "node:test";

import {
  IllegalTransitionError,
  transition,
} from "./transition-registry.mjs";

test("PaymentIntent registry requires an explicit known authorization profile", () => {
  for (const authorizationProfile of [undefined, "UNKNOWN_PROFILE"]) {
    const projection = { state: "CREATED" };
    assert.throws(
      () =>
        transition(projection, "paymentIntent", "RESERVED", [], {
          authorizationProfile,
        }),
      IllegalTransitionError,
    );
    assert.equal(projection.state, "CREATED");
  }
});

test("MANDATE_PROTECTED selects the reservation-first draft.4 profile", () => {
  const projection = { state: "CREATED" };
  const trace = [];
  transition(projection, "paymentIntent", "RESERVED", trace, {
    authorizationProfile: "MANDATE_PROTECTED",
  });
  transition(projection, "paymentIntent", "AUTHORIZING", trace, {
    authorizationProfile: "MANDATE_PROTECTED",
  });

  assert.equal(projection.state, "AUTHORIZING");
  assert.deepEqual(
    trace.map(({ from, to }) => ({ from, to })),
    [
      { from: "CREATED", to: "RESERVED" },
      { from: "RESERVED", to: "AUTHORIZING" },
    ],
  );
});
