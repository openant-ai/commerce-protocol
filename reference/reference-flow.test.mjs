import assert from "node:assert/strict";
import test from "node:test";

import { digestCanonical, fixtureDigest } from "./canonical.mjs";
import {
  PROTOCOL_DIGEST,
  PROTOCOL_VERSION,
  REFERENCE_FIXTURE,
  REFERENCE_PRECONDITION,
  boundaryProofDigest,
  createBoundaryBinding,
  createVerifyBinding,
  digestTransitionTrace,
  runScenario,
  verifyProofDigest,
} from "./index.mjs";

const action = (type, suffix = "1") => {
  const fingerprintDigest =
    type === "VERIFY"
      ? REFERENCE_PRECONDITION.paymentIntentFingerprintDigest
      : fixtureDigest(`fingerprint-${type.toLowerCase()}-${suffix}`);
  const verifyBinding = type === "VERIFY" ? createVerifyBinding(fingerprintDigest) : undefined;
  const boundaryBinding = type === "VERIFY" ? undefined : createBoundaryBinding(type);
  return {
    actionId: `${type.toLowerCase()}-${suffix}`,
    type,
    idempotencyKey: `${type.toLowerCase()}-key-${suffix}`,
    fingerprintDigest,
    proofDigest:
      type === "VERIFY"
        ? verifyProofDigest(verifyBinding)
        : boundaryProofDigest(boundaryBinding),
    ...(verifyBinding === undefined ? {} : { verifyBinding }),
    ...(boundaryBinding === undefined ? {} : { boundaryBinding }),
  };
};

const boundaries = ["VERIFY", "EXECUTE", "STAGE", "SETTLE", "DELIVER", "ACK"];
const finalStates = [
  "PAYMENT_AUTHORIZED",
  "EXECUTING",
  "OUTPUT_STAGED",
  "DELIVERABLE",
  "DELIVERED",
  "ACKED",
];
const effectNames = [
  "authorizations",
  "executions",
  "stagings",
  "settlements",
  "deliveries",
  "acknowledgements",
];

test("Hosted Phase 0 converges from verify through acknowledgement without real money", () => {
  const result = runScenario({
    vectorId: "HOSTED.HAPPY.001",
    protocolVersion: PROTOCOL_VERSION,
    protocolDigest: PROTOCOL_DIGEST,
    precondition: REFERENCE_PRECONDITION,
    actions: [
      action("VERIFY"),
      action("EXECUTE"),
      action("STAGE"),
      action("SETTLE"),
      action("DELIVER"),
      action("ACK"),
    ],
  });

  assert.equal(result.vectorId, "HOSTED.HAPPY.001");
  assert.equal(result.finalState.capabilities.realMoney, false);
  assert.equal(result.finalState.listing.state, "ACTIVE");
  assert.equal(result.finalState.invocation.state, "ACKED");
  assert.equal(result.finalState.paymentIntent.state, "FINALIZED");
  assert.equal(result.finalState.transitionJournal.count, 14);
  assert.deepEqual(result.finalState.effects, {
    acknowledgements: 1,
    authorizations: 1,
    deliveries: 1,
    executions: 1,
    settlements: 1,
    stagings: 1,
  });
  assert.deepEqual(
    result.observations.map(({ outcome, errorCode }) => ({ outcome, errorCode })),
    Array.from({ length: 6 }, () => ({ outcome: "COMMITTED", errorCode: null })),
  );
});

test("VERIFY is a registry-valid atomic macro with a committed transition trace", () => {
  const result = runScenario({
    vectorId: "HOSTED.VERIFY.MACRO_TRACE.001",
    protocolVersion: PROTOCOL_VERSION,
    protocolDigest: PROTOCOL_DIGEST,
    precondition: REFERENCE_PRECONDITION,
    actions: [action("VERIFY")],
  });
  const expectedTrace = [
    {
      machine: "invocation",
      from: "CREATED",
      to: "PAYMENT_REQUIRED",
      guard: "signed_challenge_issued",
    },
    {
      machine: "paymentIntent",
      from: "CREATED",
      to: "RESERVED",
      guard: "atomic_budget_reservation_committed",
    },
    {
      machine: "paymentIntent",
      from: "RESERVED",
      to: "AUTHORIZING",
      guard: "authorization_activity_started",
    },
    {
      machine: "paymentIntent",
      from: "AUTHORIZING",
      to: "AUTHORIZED",
      guard: "authorization_and_proof_committed",
    },
    {
      machine: "invocation",
      from: "PAYMENT_REQUIRED",
      to: "PAYMENT_AUTHORIZED",
      guard: "valid_authorization_proof_observed",
    },
  ];

  assert.equal(result.observations[0].transitionCount, expectedTrace.length);
  assert.equal(
    result.observations[0].transitionTraceDigest,
    digestTransitionTrace(expectedTrace),
  );
  assert.equal(
    result.observations[0].transitionTraceDigest,
    digestCanonical({
      domain: "OPENANT_REFERENCE_TRANSITION_TRACE_V1",
      transitions: expectedTrace,
    }),
  );
});

for (const macroMutation of [
  "UNKNOWN_TRANSITION",
  "SKIP_REQUIRED_STATE",
  "SKIP_RESERVATION",
]) {
  test(`VERIFY ${macroMutation} is rejected atomically by the registry`, () => {
    const result = runScenario({
      vectorId: `HOSTED.VERIFY.MACRO_${macroMutation}.001`,
      protocolVersion: PROTOCOL_VERSION,
      protocolDigest: PROTOCOL_DIGEST,
      precondition: REFERENCE_PRECONDITION,
      actions: [{ ...action("VERIFY"), macroMutation }],
    });

    assert.equal(result.observations[0].errorCode, "ILLEGAL_STATE_TRANSITION");
    assert.equal(result.observations[0].transitionCount, 0);
    assert.equal(result.finalState.invocation.state, "CREATED");
    assert.equal(result.finalState.paymentIntent, null);
    assert.deepEqual(result.finalState.effects, {
      acknowledgements: 0,
      authorizations: 0,
      deliveries: 0,
      executions: 0,
      settlements: 0,
      stagings: 0,
    });
  });
}

for (const mutation of ["FINGERPRINT", "AUTHORITY", "SCOPE"]) {
  test(`VERIFY rejects the same proof after ${mutation} binding changes`, () => {
    const verify = action("VERIFY");
    const mutated = structuredClone(verify);
    if (mutation === "FINGERPRINT") {
      mutated.fingerprintDigest =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    } else if (mutation === "AUTHORITY") {
      mutated.verifyBinding.authorizationAuthority.issuer = "did:0xkey:attacker";
    } else {
      mutated.verifyBinding.invocationId = "inv_attacker_scope";
    }
    const result = runScenario({
      vectorId: `HOSTED.VERIFY.PROOF_CHANGED_${mutation}.001`,
      protocolVersion: PROTOCOL_VERSION,
      protocolDigest: PROTOCOL_DIGEST,
      precondition: REFERENCE_PRECONDITION,
      actions: [mutated],
    });

    assert.equal(result.observations[0].errorCode, "PROOF_BINDING_MISMATCH");
    assert.equal(result.finalState.invocation.state, "CREATED");
    assert.equal(result.finalState.paymentIntent, null);
  });
}

for (const [index, boundary] of boundaries.slice(1).entries()) {
  test(`${boundary} proof rejects changed Invocation/SKU lineage`, () => {
    const actualIndex = index + 1;
    const prefix = boundaries.slice(0, actualIndex).map((type) => action(type));
    const changed = action(boundary, "changed-lineage");
    changed.boundaryBinding.serviceSkuId = "sku_attacker_scope";
    const result = runScenario({
      vectorId: `HOSTED.${boundary}.PROOF_CHANGED_SCOPE.001`,
      protocolVersion: PROTOCOL_VERSION,
      protocolDigest: PROTOCOL_DIGEST,
      precondition: REFERENCE_PRECONDITION,
      actions: [...prefix, changed],
    });

    assert.equal(result.observations.at(-1).errorCode, "PROOF_BINDING_MISMATCH");
    assert.equal(
      result.finalState.invocation.state,
      finalStates[actualIndex - 1],
    );
  });
}

test("a revoked Listing rejection is an atomic idempotent result", () => {
  const precondition = {
    ...structuredClone(REFERENCE_PRECONDITION),
    listingState: "EMERGENCY_REVOKED",
  };
  const verify = action("VERIFY", "revoked");
  const result = runScenario({
    vectorId: "HOSTED.VERIFY.REVOKED_REPLAY.001",
    protocolVersion: PROTOCOL_VERSION,
    protocolDigest: PROTOCOL_DIGEST,
    precondition,
    actions: [verify, { ...structuredClone(verify), actionId: "verify-revoked-replay" }],
  });

  assert.equal(result.finalState.invocation.state, "FAILED_BEFORE_SETTLEMENT");
  assert.equal(result.finalState.paymentIntent, null);
  assert.equal(result.finalState.transitionJournal.count, 1);
  assert.deepEqual(
    result.observations.map(({ outcome, errorCode }) => ({ outcome, errorCode })),
    [
      { outcome: "REJECTED", errorCode: "LISTING_REVOKED" },
      { outcome: "IDEMPOTENT_REPLAY", errorCode: "LISTING_REVOKED" },
    ],
  );
});

test("a duplicate boundary call replays its committed result without a second effect", () => {
  const verify = action("VERIFY");
  const result = runScenario({
    vectorId: "HOSTED.VERIFY.DUPLICATE.001",
    protocolVersion: PROTOCOL_VERSION,
    protocolDigest: PROTOCOL_DIGEST,
    precondition: REFERENCE_PRECONDITION,
    actions: [verify, { ...verify, actionId: "verify-duplicate" }],
  });

  assert.equal(result.finalState.invocation.state, "PAYMENT_AUTHORIZED");
  assert.equal(result.finalState.effects.authorizations, 1);
  assert.deepEqual(
    result.observations.map(({ outcome, errorCode }) => ({ outcome, errorCode })),
    [
      { outcome: "COMMITTED", errorCode: null },
      { outcome: "IDEMPOTENT_REPLAY", errorCode: null },
    ],
  );
});

for (const [index, boundary] of boundaries.entries()) {
  test(`${boundary} can retry a pre-commit timeout without losing exactly-once effects`, () => {
    const prefix = boundaries.slice(0, index).map((type) => action(type));
    const target = action(boundary);
    const result = runScenario({
      vectorId: `HOSTED.${boundary}.TIMEOUT_BEFORE_COMMIT.001`,
      protocolVersion: PROTOCOL_VERSION,
      protocolDigest: PROTOCOL_DIGEST,
      precondition: REFERENCE_PRECONDITION,
      actions: [
        ...prefix,
        { ...target, fault: "TIMEOUT_BEFORE_COMMIT" },
        { ...target, actionId: `${target.actionId}-retry` },
      ],
    });

    assert.equal(result.finalState.invocation.state, finalStates[index]);
    assert.equal(result.finalState.effects[effectNames[index]], 1);
    assert.deepEqual(
      result.observations.slice(-2).map(({ outcome, errorCode }) => ({
        outcome,
        errorCode,
      })),
      [
        { outcome: "TIMEOUT_BEFORE_COMMIT", errorCode: null },
        { outcome: "COMMITTED", errorCode: null },
      ],
    );
  });

  test(`${boundary} resolves a lost post-commit response by replaying the same operation`, () => {
    const prefix = boundaries.slice(0, index).map((type) => action(type));
    const target = action(boundary);
    const result = runScenario({
      vectorId: `HOSTED.${boundary}.TIMEOUT_AFTER_COMMIT.001`,
      protocolVersion: PROTOCOL_VERSION,
      protocolDigest: PROTOCOL_DIGEST,
      precondition: REFERENCE_PRECONDITION,
      actions: [
        ...prefix,
        { ...target, fault: "TIMEOUT_AFTER_COMMIT" },
        { ...target, actionId: `${target.actionId}-replay` },
      ],
    });

    assert.equal(result.finalState.invocation.state, finalStates[index]);
    assert.equal(result.finalState.effects[effectNames[index]], 1);
    assert.deepEqual(
      result.observations.slice(-2).map(({ outcome, errorCode }) => ({
        outcome,
        errorCode,
      })),
      [
        { outcome: "TIMEOUT_AFTER_COMMIT", errorCode: null },
        { outcome: "IDEMPOTENT_REPLAY", errorCode: null },
      ],
    );
  });
}

for (const [index, boundary] of boundaries.entries()) {
  test(`${boundary} rejects a validly shaped but out-of-order call`, () => {
    const actions =
      boundary === "VERIFY"
        ? [action("VERIFY"), action("VERIFY", "out-of-order")]
        : [action(boundary, "out-of-order")];
    const result = runScenario({
      vectorId: `HOSTED.${boundary}.OUT_OF_ORDER.001`,
      protocolVersion: PROTOCOL_VERSION,
      protocolDigest: PROTOCOL_DIGEST,
      precondition: REFERENCE_PRECONDITION,
      actions,
    });

    assert.equal(result.observations.at(-1).outcome, "REJECTED");
    assert.equal(result.observations.at(-1).errorCode, "ILLEGAL_STATE_TRANSITION");
    assert.equal(
      result.finalState.invocation.state,
      boundary === "VERIFY" ? "PAYMENT_AUTHORIZED" : "CREATED",
    );
  });

  test(`${boundary} rejects proof bound to a different commit boundary`, () => {
    const prefix = boundaries.slice(0, index).map((type) => action(type));
    const result = runScenario({
      vectorId: `HOSTED.${boundary}.PROOF_MISMATCH.001`,
      protocolVersion: PROTOCOL_VERSION,
      protocolDigest: PROTOCOL_DIGEST,
      precondition: REFERENCE_PRECONDITION,
      actions: [
        ...prefix,
        {
          ...action(boundary, "mismatch"),
          proofDigest: REFERENCE_FIXTURE.proofs[boundaries[(index + 1) % boundaries.length]],
        },
      ],
    });

    assert.equal(result.observations.at(-1).outcome, "REJECTED");
    assert.equal(result.observations.at(-1).errorCode, "PROOF_BINDING_MISMATCH");
    assert.equal(
      result.finalState.invocation.state,
      index === 0 ? "CREATED" : finalStates[index - 1],
    );
  });
}

test("reusing a commit key with another fingerprint is a fixed conflict", () => {
  const verify = action("VERIFY");
  const result = runScenario({
    vectorId: "HOSTED.VERIFY.FINGERPRINT_CONFLICT.001",
    protocolVersion: PROTOCOL_VERSION,
    protocolDigest: PROTOCOL_DIGEST,
    precondition: REFERENCE_PRECONDITION,
    actions: [
      verify,
      {
        ...verify,
        actionId: "verify-conflict",
        fingerprintDigest: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      },
    ],
  });

  assert.equal(result.observations.at(-1).errorCode, "IDEMPOTENCY_FINGERPRINT_CONFLICT");
  assert.equal(result.finalState.effects.authorizations, 1);
});

for (const sellerOutcome of ["HTTP_5XX", "TIMEOUT", "SCHEMA_ERROR"]) {
  test(`Seller ${sellerOutcome} fails before settlement and never exposes output`, () => {
    const result = runScenario({
      vectorId: `HOSTED.EXECUTE.SELLER_${sellerOutcome}.001`,
      protocolVersion: PROTOCOL_VERSION,
      protocolDigest: PROTOCOL_DIGEST,
      precondition: REFERENCE_PRECONDITION,
      actions: [action("VERIFY"), { ...action("EXECUTE"), sellerOutcome }],
    });

    assert.equal(result.observations.at(-1).errorCode, "OUTPUT_NOT_CHARGEABLE");
    assert.equal(result.observations.at(-1).reasonCode, `SELLER_${sellerOutcome}`);
    assert.equal(result.finalState.invocation.state, "FAILED_BEFORE_SETTLEMENT");
    assert.equal(result.finalState.paymentIntent.state, "AUTHORIZED");
    assert.equal(result.finalState.output.buffered, false);
    assert.equal(result.finalState.effects.settlements, 0);
  });
}

test("emergency listing revocation before settlement fails closed", () => {
  const result = runScenario({
    vectorId: "HOSTED.LISTING.REVOKE_BEFORE_SETTLEMENT.001",
    protocolVersion: PROTOCOL_VERSION,
    protocolDigest: PROTOCOL_DIGEST,
    precondition: REFERENCE_PRECONDITION,
    actions: [
      action("VERIFY"),
      action("EXECUTE"),
      action("STAGE"),
      action("REVOKE_LISTING"),
    ],
  });

  assert.equal(result.observations.at(-1).errorCode, "LISTING_REVOKED");
  assert.equal(result.finalState.listing.state, "EMERGENCY_REVOKED");
  assert.equal(result.finalState.invocation.state, "FAILED_BEFORE_SETTLEMENT");
  assert.equal(result.finalState.effects.settlements, 0);
});

test("listing revocation after final settlement still permits delivery convergence", () => {
  const result = runScenario({
    vectorId: "HOSTED.LISTING.REVOKE_AFTER_SETTLEMENT.001",
    protocolVersion: PROTOCOL_VERSION,
    protocolDigest: PROTOCOL_DIGEST,
    precondition: REFERENCE_PRECONDITION,
    actions: [
      ...boundaries.slice(0, 4).map((type) => action(type)),
      action("REVOKE_LISTING"),
      action("DELIVER"),
      action("ACK"),
    ],
  });

  assert.equal(result.finalState.listing.state, "EMERGENCY_REVOKED");
  assert.equal(result.finalState.invocation.state, "ACKED");
  assert.equal(result.finalState.paymentIntent.state, "FINALIZED");
});

test("settlement UNKNOWN requires a signed observation and deadline before reconciliation", () => {
  const settleUnknown = {
    ...action("SETTLE"),
    settlementOutcome: "UNKNOWN",
    reconciliationDeadline: "2030-01-01T00:05:00Z",
    unknownObservationDigest: REFERENCE_FIXTURE.proofs.SETTLEMENT_UNKNOWN,
  };
  const pending = runScenario({
    vectorId: "HOSTED.SETTLE.UNKNOWN_PENDING.001",
    protocolVersion: PROTOCOL_VERSION,
    protocolDigest: PROTOCOL_DIGEST,
    precondition: REFERENCE_PRECONDITION,
    actions: [...boundaries.slice(0, 3).map((type) => action(type)), settleUnknown],
  });
  assert.equal(pending.finalState.invocation.state, "PAYMENT_UNKNOWN");
  assert.equal(pending.finalState.paymentIntent.state, "SETTLEMENT_UNKNOWN");
  assert.equal(
    pending.finalState.invocation.fundingUnknownObservationDigest,
    REFERENCE_FIXTURE.proofs.SETTLEMENT_UNKNOWN,
  );
  assert.equal(pending.finalState.invocation.reconciliationDeadline, "2030-01-01T00:05:00Z");
  assert.equal(
    pending.finalState.paymentIntent.fundingUnknownObservationDigest,
    pending.finalState.invocation.fundingUnknownObservationDigest,
  );
  assert.equal(
    pending.finalState.paymentIntent.reconciliationDeadline,
    pending.finalState.invocation.reconciliationDeadline,
  );
  const result = runScenario({
    vectorId: "HOSTED.SETTLE.UNKNOWN_RESOLVED.001",
    protocolVersion: PROTOCOL_VERSION,
    protocolDigest: PROTOCOL_DIGEST,
    precondition: REFERENCE_PRECONDITION,
    actions: [
      ...boundaries.slice(0, 3).map((type) => action(type)),
      settleUnknown,
      action("RESOLVE_SETTLEMENT"),
    ],
  });

  assert.equal(result.observations.at(-2).errorCode, "SETTLEMENT_UNKNOWN");
  assert.equal(result.observations.at(-2).outcome, "RECONCILIATION_REQUIRED");
  assert.equal(result.finalState.invocation.state, "DELIVERABLE");
  assert.equal(result.finalState.paymentIntent.state, "FINALIZED");
  assert.equal(result.finalState.effects.settlements, 1);
});

for (const missingField of ["reconciliationDeadline", "unknownObservationDigest"]) {
  test(`settlement UNKNOWN is rejected without ${missingField}`, () => {
    const settleUnknown = {
      ...action("SETTLE"),
      settlementOutcome: "UNKNOWN",
      reconciliationDeadline: "2030-01-01T00:05:00Z",
      unknownObservationDigest: REFERENCE_FIXTURE.proofs.SETTLEMENT_UNKNOWN,
    };
    delete settleUnknown[missingField];
    const result = runScenario({
      vectorId: `HOSTED.SETTLE.UNKNOWN_MISSING_${missingField}.001`,
      protocolVersion: PROTOCOL_VERSION,
      protocolDigest: PROTOCOL_DIGEST,
      precondition: REFERENCE_PRECONDITION,
      actions: [...boundaries.slice(0, 3).map((type) => action(type)), settleUnknown],
    });

    assert.equal(result.observations.at(-1).errorCode, "PROOF_INCOMPLETE");
    assert.equal(result.finalState.invocation.state, "OUTPUT_STAGED");
    assert.equal(result.finalState.paymentIntent.state, "AUTHORIZED");
  });
}
