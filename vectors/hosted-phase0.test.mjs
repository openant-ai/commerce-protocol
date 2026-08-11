import assert from "node:assert/strict";
import test from "node:test";

import {
  PROTOCOL_DIGEST,
  PROTOCOL_VERSION,
  REFERENCE_PRECONDITION,
} from "../reference/index.mjs";
import { BOUNDARIES, VECTORS } from "./hosted-phase0.mjs";

test("the public vector registry is unique, explicit, pinned, and has no private skips", () => {
  assert.equal(VECTORS.length, 53);
  assert.equal(new Set(VECTORS.map(({ id }) => id)).size, VECTORS.length);

  for (const vector of VECTORS) {
    assert.match(vector.id, /^HOSTED(?:\.[A-Z0-9_]+)+\.001$/);
    assert.equal(vector.protocolVersion, PROTOCOL_VERSION);
    assert.equal(vector.protocolDigest, PROTOCOL_DIGEST);
    assert.deepEqual(
      { ...vector.precondition, listingState: "ACTIVE" },
      REFERENCE_PRECONDITION,
    );
    assert.ok(["ACTIVE", "EMERGENCY_REVOKED"].includes(vector.precondition.listingState));
    assert.ok(vector.action.steps.length > 0);
    assert.ok(vector.expected.state.invocationState);
    assert.ok(Object.hasOwn(vector.expected, "errorCode"));
    assert.equal(vector.expected.observations.length, vector.action.steps.length);
    assert.ok(Number.isSafeInteger(vector.expected.transitionJournal.count));
    assert.match(vector.expected.transitionJournal.digest, /^sha256:[0-9a-f]{64}$/);
    assert.ok(vector.expected.normalizedState);
    assert.equal(Object.hasOwn(vector, "skip"), false);
  }
});

test("VERIFY vectors bind proof claims and reject illegal registry macros", () => {
  for (const id of [
    "HOSTED.VERIFY.PROOF_CHANGED_FINGERPRINT.001",
    "HOSTED.VERIFY.PROOF_CHANGED_AUTHORITY.001",
    "HOSTED.VERIFY.PROOF_CHANGED_SCOPE.001",
    "HOSTED.VERIFY.MACRO_UNKNOWN_TRANSITION.001",
    "HOSTED.VERIFY.MACRO_SKIP_REQUIRED_STATE.001",
    "HOSTED.VERIFY.MACRO_SKIP_RESERVATION.001",
    "HOSTED.VERIFY.REVOKED_REPLAY.001",
  ]) {
    assert.ok(VECTORS.some((vector) => vector.id === id), `${id} is missing`);
  }
});

test("every post-VERIFY boundary rejects a same-proof scope mutation", () => {
  for (const boundary of BOUNDARIES.slice(1)) {
    assert.ok(
      VECTORS.some(({ id }) => id === `HOSTED.${boundary}.PROOF_CHANGED_SCOPE.001`),
      `${boundary} is missing changed-scope proof coverage`,
    );
  }
});

test("every Hosted commit boundary has the complete malicious matrix", () => {
  for (const boundary of BOUNDARIES) {
    for (const suffix of [
      "TIMEOUT_BEFORE_COMMIT",
      "TIMEOUT_AFTER_COMMIT_REPLAY",
      "DUPLICATE",
      "OUT_OF_ORDER",
      "PROOF_MISMATCH",
    ]) {
      assert.ok(
        VECTORS.some(({ id }) => id === `HOSTED.${boundary}.${suffix}.001`),
        `${boundary} is missing ${suffix}`,
      );
    }
  }
});

test("vectors are metadata-only", () => {
  const serialized = JSON.stringify(VECTORS);
  for (const forbidden of [
    "prompt",
    "toolArguments",
    "requestBody",
    "responseBody",
    "artifactBytes",
    "token",
    "cookie",
    "credential",
    "privateKey",
  ]) {
    assert.equal(serialized.includes(`\"${forbidden}\"`), false);
  }
});
