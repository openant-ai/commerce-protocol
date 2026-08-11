import {
  PROTOCOL_DIGEST,
  PROTOCOL_VERSION,
  REFERENCE_FIXTURE,
  REFERENCE_PRECONDITION,
  boundaryProofDigest,
  createBoundaryBinding,
  createVerifyBinding,
  digestTransitionTrace,
  verifyProofDigest,
} from "../reference/index.mjs";
import { fixtureDigest } from "../reference/canonical.mjs";

export const BOUNDARIES = Object.freeze([
  "VERIFY",
  "EXECUTE",
  "STAGE",
  "SETTLE",
  "DELIVER",
  "ACK",
]);

const INVOCATION_STATES = Object.freeze([
  "PAYMENT_AUTHORIZED",
  "EXECUTING",
  "OUTPUT_STAGED",
  "DELIVERABLE",
  "DELIVERED",
  "ACKED",
]);

const EFFECT_NAMES = Object.freeze([
  "authorizations",
  "executions",
  "stagings",
  "settlements",
  "deliveries",
  "acknowledgements",
]);

const emptyEffects = () => ({
  acknowledgements: 0,
  authorizations: 0,
  deliveries: 0,
  executions: 0,
  settlements: 0,
  stagings: 0,
});

export function referenceAction(type, suffix = "1", overrides = {}) {
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
    ...overrides,
  };
}

const edge = (machine, from, to, guard) => ({ machine, from, to, guard });

const expectedTransitionTrace = (action, outcome, errorCode, reasonCode) => {
  if (action.type === "VERIFY" && errorCode === "LISTING_REVOKED") {
    return [
      edge(
        "invocation",
        "CREATED",
        "FAILED_BEFORE_SETTLEMENT",
        "input_or_listing_rejected",
      ),
    ];
  }
  if (
    outcome === "TIMEOUT_BEFORE_COMMIT" ||
    [
      "ILLEGAL_STATE_TRANSITION",
      "PROOF_BINDING_MISMATCH",
      "IDEMPOTENCY_FINGERPRINT_CONFLICT",
      "PROOF_INCOMPLETE",
    ].includes(errorCode)
  ) {
    return [];
  }
  if (action.type === "VERIFY") {
    return [
      edge("invocation", "CREATED", "PAYMENT_REQUIRED", "signed_challenge_issued"),
      edge("paymentIntent", "CREATED", "RESERVED", "atomic_budget_reservation_committed"),
      edge("paymentIntent", "RESERVED", "AUTHORIZING", "authorization_activity_started"),
      edge("paymentIntent", "AUTHORIZING", "AUTHORIZED", "authorization_and_proof_committed"),
      edge(
        "invocation",
        "PAYMENT_REQUIRED",
        "PAYMENT_AUTHORIZED",
        "valid_authorization_proof_observed",
      ),
    ];
  }
  if (action.type === "EXECUTE") {
    return action.sellerOutcome
      ? [
          edge(
            "invocation",
            "PAYMENT_AUTHORIZED",
            "FAILED_BEFORE_SETTLEMENT",
            "verification_or_execution_start_failed",
          ),
        ]
      : [
          edge(
            "invocation",
            "PAYMENT_AUTHORIZED",
            "EXECUTING",
            "payment_verified_and_execution_started",
          ),
        ];
  }
  if (action.type === "STAGE") {
    return [
      edge(
        "invocation",
        "EXECUTING",
        "OUTPUT_STAGED",
        "chargeable_output_bytes_staged_and_verified",
      ),
    ];
  }
  if (action.type === "SETTLE" && action.settlementOutcome === "UNKNOWN") {
    return [
      edge("invocation", "OUTPUT_STAGED", "SETTLEMENT_PENDING", "settlement_submitted"),
      edge(
        "paymentIntent",
        "AUTHORIZED",
        "SUBMITTED",
        "settlement_broadcast_or_facilitator_acceptance",
      ),
      edge(
        "paymentIntent",
        "SUBMITTED",
        "SETTLEMENT_UNKNOWN",
        "settlement_commit_point_uncertain",
      ),
      edge(
        "invocation",
        "SETTLEMENT_PENDING",
        "PAYMENT_UNKNOWN",
        "settlement_outcome_unknown",
      ),
    ];
  }
  if (action.type === "SETTLE") {
    return [
      edge("invocation", "OUTPUT_STAGED", "SETTLEMENT_PENDING", "settlement_submitted"),
      edge(
        "paymentIntent",
        "AUTHORIZED",
        "SUBMITTED",
        "settlement_broadcast_or_facilitator_acceptance",
      ),
      edge("paymentIntent", "SUBMITTED", "CONFIRMED", "chain_confirmation_observed"),
      edge("paymentIntent", "CONFIRMED", "FINALIZED", "finality_policy_satisfied"),
      edge(
        "invocation",
        "SETTLEMENT_PENDING",
        "DELIVERABLE",
        "final_settlement_receipt_observed",
      ),
    ];
  }
  if (action.type === "DELIVER") {
    return [edge("invocation", "DELIVERABLE", "DELIVERED", "exact_bytes_sent")];
  }
  if (action.type === "ACK") {
    return [
      edge(
        "invocation",
        "DELIVERED",
        "ACKED",
        "buyer_delivery_acknowledgement_verified",
      ),
    ];
  }
  if (action.type === "RESOLVE_SETTLEMENT") {
    return [
      edge(
        "paymentIntent",
        "SETTLEMENT_UNKNOWN",
        "CONFIRMED",
        "reconciliation_finds_confirmed_transfer",
      ),
      edge("paymentIntent", "CONFIRMED", "FINALIZED", "finality_policy_satisfied"),
      edge(
        "invocation",
        "PAYMENT_UNKNOWN",
        "DELIVERABLE",
        "reconciliation_proves_final_settlement",
      ),
    ];
  }
  if (action.type === "REVOKE_LISTING") {
    const trace = [
      edge(
        "listing",
        "ACTIVE",
        "EMERGENCY_REVOKED",
        "key_payout_or_mandate_compromise",
      ),
    ];
    if (reasonCode === "REVOKED_BEFORE_SETTLEMENT") {
      trace.push(
        edge(
          "invocation",
          "OUTPUT_STAGED",
          "FAILED_BEFORE_SETTLEMENT",
          "settlement_known_rejected",
        ),
      );
    }
    return trace;
  }
  return [];
};

const observation = (action, outcome, errorCode = null, reasonCode = null) => {
  const trace = expectedTransitionTrace(action, outcome, errorCode, reasonCode);
  const value = {
    actionId: action.actionId,
    type: action.type,
    outcome,
    errorCode,
    transitionCount: trace.length,
    transitionTraceDigest: digestTransitionTrace(trace),
  };
  if (reasonCode !== null) value.reasonCode = reasonCode;
  return value;
};

const committedPrefix = (count) =>
  BOUNDARIES.slice(0, count).map((type) => {
    const step = referenceAction(type);
    return { action: step, observation: observation(step, "COMMITTED") };
  });

const effectsThrough = (count) => {
  const effects = emptyEffects();
  for (const name of EFFECT_NAMES.slice(0, count)) effects[name] = 1;
  return effects;
};

const paymentStateFor = (invocationState) => {
  if (invocationState === "CREATED") return null;
  if (["DELIVERABLE", "DELIVERED", "ACKED"].includes(invocationState)) return "FINALIZED";
  if (invocationState === "PAYMENT_UNKNOWN") return "SETTLEMENT_UNKNOWN";
  return "AUTHORIZED";
};

function expectedNormalizedState({
  actions,
  observations,
  precondition,
  listingState,
  invocationState,
  paymentIntentState,
  effects,
  transitionJournal,
}) {
  const committedAction = (type, predicate = () => true) => {
    const index = actions.findIndex(
      (action, candidateIndex) =>
        action.type === type &&
        observations[candidateIndex].transitionCount > 0 &&
        observations[candidateIndex].outcome !== "IDEMPOTENT_REPLAY" &&
        predicate(action, observations[candidateIndex]),
    );
    return index === -1 ? null : actions[index];
  };
  const verify =
    paymentIntentState === null
      ? null
      : committedAction("VERIFY", (_action, result) => result.errorCode === null);
  const execution = committedAction(
    "EXECUTE",
    (action, result) => action.sellerOutcome === undefined && result.errorCode === null,
  );
  const staging = committedAction("STAGE", (_action, result) => result.errorCode === null);
  const settlement = committedAction(
    "SETTLE",
    (action, result) => action.settlementOutcome !== "UNKNOWN" && result.errorCode === null,
  );
  const unknownSettlement = committedAction(
    "SETTLE",
    (action) => action.settlementOutcome === "UNKNOWN",
  );
  const resolution = committedAction(
    "RESOLVE_SETTLEMENT",
    (_action, result) => result.errorCode === null,
  );
  const delivery = committedAction("DELIVER", (_action, result) => result.errorCode === null);
  const acknowledgement = committedAction(
    "ACK",
    (_action, result) => result.errorCode === null,
  );
  const pendingUnknown = paymentIntentState === "SETTLEMENT_UNKNOWN";
  const settlementProof = resolution?.proofDigest ?? settlement?.proofDigest ?? null;

  return {
    capabilities: {
      realMoney: false,
      warning: "REFERENCE_ONLY_NO_REAL_FUNDS",
    },
    listing: {
      state: listingState,
      serviceSkuId: precondition.serviceSkuId,
      skuVersionDigest: precondition.skuVersionDigest,
      issuer: REFERENCE_FIXTURE.catalogIssuer,
    },
    invocation: {
      invocationId: precondition.invocationId,
      mode: "HOSTED",
      serviceSkuId: precondition.serviceSkuId,
      skuVersionDigest: precondition.skuVersionDigest,
      requestDigest: REFERENCE_FIXTURE.requestDigest,
      commercialIssuer: REFERENCE_FIXTURE.commercialIssuer,
      paymentIntentRef: verify === null ? null : REFERENCE_FIXTURE.paymentIntentId,
      paymentProofDigest: verify?.proofDigest ?? null,
      outputStagingReceiptDigest: staging?.proofDigest ?? null,
      settlementReceiptDigest: settlementProof,
      fundingUnknownObservationDigest:
        pendingUnknown ? unknownSettlement.unknownObservationDigest : null,
      reconciliationDeadline:
        pendingUnknown ? unknownSettlement.reconciliationDeadline : null,
      deliveryReceiptDigest: delivery?.proofDigest ?? null,
      acknowledgementDigest: acknowledgement?.proofDigest ?? null,
      state: invocationState,
    },
    paymentIntent:
      verify === null
        ? null
        : {
            paymentIntentId: REFERENCE_FIXTURE.paymentIntentId,
            invocationRef: precondition.invocationId,
            skuVersionDigest: precondition.skuVersionDigest,
            fingerprintDigest: verify.fingerprintDigest,
            authorizationProfile: precondition.authorizationProfile,
            fundingAuthority: structuredClone(precondition.authorizationAuthority),
            settlementAuthority: structuredClone(REFERENCE_FIXTURE.settlementAuthority),
            observationAuthority: structuredClone(REFERENCE_FIXTURE.observationAuthority),
            state: paymentIntentState,
            authorizationProofDigest: verify.proofDigest,
            settlementReceiptDigest: settlementProof,
            fundingUnknownObservationDigest:
              pendingUnknown ? unknownSettlement.unknownObservationDigest : null,
            reconciliationDeadline:
              pendingUnknown ? unknownSettlement.reconciliationDeadline : null,
          },
    output: {
      buffered: staging !== null,
      byteCount: execution === null ? null : REFERENCE_FIXTURE.outputByteCount,
      responseDigest: execution === null ? null : REFERENCE_FIXTURE.responseDigest,
    },
    effects,
    transitionJournal,
  };
}

const vector = ({
  id,
  actions,
  invocationState,
  paymentIntentState,
  listingState = "ACTIVE",
  precondition = REFERENCE_PRECONDITION,
  observations,
  effects,
  errorCode = null,
}) => {
  const journalTransitions = [];
  for (const [index, action] of actions.entries()) {
    const expectedObservation = observations[index];
    if (expectedObservation.outcome === "IDEMPOTENT_REPLAY") continue;
    journalTransitions.push(
      ...expectedTransitionTrace(
        action,
        expectedObservation.outcome,
        expectedObservation.errorCode,
        expectedObservation.reasonCode ?? null,
      ),
    );
  }
  const transitionJournal = {
    count: journalTransitions.length,
    digest: digestTransitionTrace(journalTransitions),
  };
  const normalizedPrecondition = structuredClone(precondition);
  const normalizedState = expectedNormalizedState({
    actions,
    observations,
    precondition: normalizedPrecondition,
    listingState,
    invocationState,
    paymentIntentState,
    effects,
    transitionJournal,
  });
  return {
    id,
    protocolVersion: PROTOCOL_VERSION,
    protocolDigest: PROTOCOL_DIGEST,
    precondition: normalizedPrecondition,
    action: { steps: actions },
    expected: {
      state: { listingState, invocationState, paymentIntentState },
      errorCode,
      observations,
      effects,
      transitionJournal,
      normalizedState,
    },
  };
};

const happySteps = committedPrefix(BOUNDARIES.length);
const generated = [
  vector({
    id: "HOSTED.HAPPY.001",
    actions: happySteps.map(({ action }) => action),
    invocationState: "ACKED",
    paymentIntentState: "FINALIZED",
    observations: happySteps.map(({ observation: value }) => value),
    effects: effectsThrough(6),
  }),
];

for (const [index, boundary] of BOUNDARIES.entries()) {
  const prefix = committedPrefix(index);
  const target = referenceAction(boundary);
  const finalState = INVOCATION_STATES[index];

  const beforeTimeout = { ...target, fault: "TIMEOUT_BEFORE_COMMIT" };
  const beforeRetry = { ...target, actionId: `${target.actionId}-retry` };
  generated.push(
    vector({
      id: `HOSTED.${boundary}.TIMEOUT_BEFORE_COMMIT.001`,
      actions: [...prefix.map(({ action }) => action), beforeTimeout, beforeRetry],
      invocationState: finalState,
      paymentIntentState: paymentStateFor(finalState),
      observations: [
        ...prefix.map(({ observation: value }) => value),
        observation(beforeTimeout, "TIMEOUT_BEFORE_COMMIT"),
        observation(beforeRetry, "COMMITTED"),
      ],
      effects: effectsThrough(index + 1),
    }),
  );

  const afterTimeout = { ...target, fault: "TIMEOUT_AFTER_COMMIT" };
  const afterReplay = { ...target, actionId: `${target.actionId}-replay` };
  generated.push(
    vector({
      id: `HOSTED.${boundary}.TIMEOUT_AFTER_COMMIT_REPLAY.001`,
      actions: [...prefix.map(({ action }) => action), afterTimeout, afterReplay],
      invocationState: finalState,
      paymentIntentState: paymentStateFor(finalState),
      observations: [
        ...prefix.map(({ observation: value }) => value),
        observation(afterTimeout, "TIMEOUT_AFTER_COMMIT"),
        observation(afterReplay, "IDEMPOTENT_REPLAY"),
      ],
      effects: effectsThrough(index + 1),
    }),
  );

  const duplicate = { ...target, actionId: `${target.actionId}-duplicate` };
  generated.push(
    vector({
      id: `HOSTED.${boundary}.DUPLICATE.001`,
      actions: [...prefix.map(({ action }) => action), target, duplicate],
      invocationState: finalState,
      paymentIntentState: paymentStateFor(finalState),
      observations: [
        ...prefix.map(({ observation: value }) => value),
        observation(target, "COMMITTED"),
        observation(duplicate, "IDEMPOTENT_REPLAY"),
      ],
      effects: effectsThrough(index + 1),
    }),
  );

  const outOfOrder = referenceAction(boundary, "out-of-order");
  const outOfOrderPrefix = boundary === "VERIFY" ? committedPrefix(1) : [];
  generated.push(
    vector({
      id: `HOSTED.${boundary}.OUT_OF_ORDER.001`,
      actions: [...outOfOrderPrefix.map(({ action }) => action), outOfOrder],
      invocationState: boundary === "VERIFY" ? "PAYMENT_AUTHORIZED" : "CREATED",
      paymentIntentState: boundary === "VERIFY" ? "AUTHORIZED" : null,
      observations: [
        ...outOfOrderPrefix.map(({ observation: value }) => value),
        observation(outOfOrder, "REJECTED", "ILLEGAL_STATE_TRANSITION"),
      ],
      effects: effectsThrough(boundary === "VERIFY" ? 1 : 0),
      errorCode: "ILLEGAL_STATE_TRANSITION",
    }),
  );

  const mismatch = referenceAction(boundary, "proof-mismatch", {
    proofDigest: REFERENCE_FIXTURE.proofs[BOUNDARIES[(index + 1) % BOUNDARIES.length]],
  });
  const stateBefore = index === 0 ? "CREATED" : INVOCATION_STATES[index - 1];
  generated.push(
    vector({
      id: `HOSTED.${boundary}.PROOF_MISMATCH.001`,
      actions: [...prefix.map(({ action }) => action), mismatch],
      invocationState: stateBefore,
      paymentIntentState: paymentStateFor(stateBefore),
      observations: [
        ...prefix.map(({ observation: value }) => value),
        observation(mismatch, "REJECTED", "PROOF_BINDING_MISMATCH"),
      ],
      effects: effectsThrough(index),
      errorCode: "PROOF_BINDING_MISMATCH",
    }),
  );

  if (boundary !== "VERIFY") {
    const changedScope = referenceAction(boundary, "changed-scope");
    changedScope.boundaryBinding.serviceSkuId = "sku_attacker_scope";
    generated.push(
      vector({
        id: `HOSTED.${boundary}.PROOF_CHANGED_SCOPE.001`,
        actions: [...prefix.map(({ action }) => action), changedScope],
        invocationState: stateBefore,
        paymentIntentState: paymentStateFor(stateBefore),
        observations: [
          ...prefix.map(({ observation: value }) => value),
          observation(changedScope, "REJECTED", "PROOF_BINDING_MISMATCH"),
        ],
        effects: effectsThrough(index),
        errorCode: "PROOF_BINDING_MISMATCH",
      }),
    );
  }
}

for (const sellerOutcome of ["HTTP_5XX", "TIMEOUT", "SCHEMA_ERROR"]) {
  const prefix = committedPrefix(1);
  const sellerFailure = referenceAction("EXECUTE", `seller-${sellerOutcome.toLowerCase()}`, {
    sellerOutcome,
  });
  const effects = effectsThrough(1);
  effects.executions = 1;
  generated.push(
    vector({
      id: `HOSTED.EXECUTE.SELLER_${sellerOutcome}.001`,
      actions: [...prefix.map(({ action }) => action), sellerFailure],
      invocationState: "FAILED_BEFORE_SETTLEMENT",
      paymentIntentState: "AUTHORIZED",
      observations: [
        ...prefix.map(({ observation: value }) => value),
        observation(
          sellerFailure,
          "REJECTED",
          "OUTPUT_NOT_CHARGEABLE",
          `SELLER_${sellerOutcome}`,
        ),
      ],
      effects,
      errorCode: "OUTPUT_NOT_CHARGEABLE",
    }),
  );
}

{
  const prefix = committedPrefix(3);
  const revoke = referenceAction("REVOKE_LISTING", "before-settlement");
  generated.push(
    vector({
      id: "HOSTED.LISTING.REVOKE_BEFORE_SETTLEMENT.001",
      actions: [...prefix.map(({ action }) => action), revoke],
      invocationState: "FAILED_BEFORE_SETTLEMENT",
      paymentIntentState: "AUTHORIZED",
      listingState: "EMERGENCY_REVOKED",
      observations: [
        ...prefix.map(({ observation: value }) => value),
        observation(revoke, "REJECTED", "LISTING_REVOKED", "REVOKED_BEFORE_SETTLEMENT"),
      ],
      effects: effectsThrough(3),
      errorCode: "LISTING_REVOKED",
    }),
  );
}

{
  const prefix = committedPrefix(4);
  const revoke = referenceAction("REVOKE_LISTING", "after-settlement");
  const deliver = referenceAction("DELIVER");
  const ack = referenceAction("ACK");
  generated.push(
    vector({
      id: "HOSTED.LISTING.REVOKE_AFTER_SETTLEMENT.001",
      actions: [...prefix.map(({ action }) => action), revoke, deliver, ack],
      invocationState: "ACKED",
      paymentIntentState: "FINALIZED",
      listingState: "EMERGENCY_REVOKED",
      observations: [
        ...prefix.map(({ observation: value }) => value),
        observation(revoke, "COMMITTED", null, "SETTLED_INVOCATION_CONVERGES"),
        observation(deliver, "COMMITTED"),
        observation(ack, "COMMITTED"),
      ],
      effects: effectsThrough(6),
    }),
  );
}

{
  const verify = referenceAction("VERIFY");
  const conflict = {
    ...verify,
    actionId: "verify-conflicting-fingerprint",
    fingerprintDigest:
      "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  };
  generated.push(
    vector({
      id: "HOSTED.VERIFY.FINGERPRINT_CONFLICT.001",
      actions: [verify, conflict],
      invocationState: "PAYMENT_AUTHORIZED",
      paymentIntentState: "AUTHORIZED",
      observations: [
        observation(verify, "COMMITTED"),
        observation(conflict, "REJECTED", "IDEMPOTENCY_FINGERPRINT_CONFLICT"),
      ],
      effects: effectsThrough(1),
      errorCode: "IDEMPOTENCY_FINGERPRINT_CONFLICT",
    }),
  );
}

for (const macroMutation of [
  "UNKNOWN_TRANSITION",
  "SKIP_REQUIRED_STATE",
  "SKIP_RESERVATION",
]) {
  const invalidMacro = referenceAction("VERIFY", `macro-${macroMutation.toLowerCase()}`, {
    macroMutation,
  });
  generated.push(
    vector({
      id: `HOSTED.VERIFY.MACRO_${macroMutation}.001`,
      actions: [invalidMacro],
      invocationState: "CREATED",
      paymentIntentState: null,
      observations: [
        observation(invalidMacro, "REJECTED", "ILLEGAL_STATE_TRANSITION"),
      ],
      effects: emptyEffects(),
      errorCode: "ILLEGAL_STATE_TRANSITION",
    }),
  );
}

{
  const revokedPrecondition = {
    ...structuredClone(REFERENCE_PRECONDITION),
    listingState: "EMERGENCY_REVOKED",
  };
  const verify = referenceAction("VERIFY", "revoked");
  const replay = { ...structuredClone(verify), actionId: "verify-revoked-replay" };
  generated.push(
    vector({
      id: "HOSTED.VERIFY.REVOKED_REPLAY.001",
      precondition: revokedPrecondition,
      actions: [verify, replay],
      invocationState: "FAILED_BEFORE_SETTLEMENT",
      paymentIntentState: null,
      listingState: "EMERGENCY_REVOKED",
      observations: [
        observation(verify, "REJECTED", "LISTING_REVOKED", "REVOKED_LISTING"),
        observation(replay, "IDEMPOTENT_REPLAY", "LISTING_REVOKED", "REVOKED_LISTING"),
      ],
      effects: emptyEffects(),
      errorCode: "LISTING_REVOKED",
    }),
  );
}

for (const mutation of ["FINGERPRINT", "AUTHORITY", "SCOPE"]) {
  const changed = referenceAction("VERIFY", `changed-${mutation.toLowerCase()}`);
  if (mutation === "FINGERPRINT") {
    changed.fingerprintDigest =
      "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  } else if (mutation === "AUTHORITY") {
    changed.verifyBinding.authorizationAuthority.issuer = "did:0xkey:attacker";
  } else {
    changed.verifyBinding.invocationId = "inv_attacker_scope";
  }
  generated.push(
    vector({
      id: `HOSTED.VERIFY.PROOF_CHANGED_${mutation}.001`,
      actions: [changed],
      invocationState: "CREATED",
      paymentIntentState: null,
      observations: [
        observation(changed, "REJECTED", "PROOF_BINDING_MISMATCH"),
      ],
      effects: emptyEffects(),
      errorCode: "PROOF_BINDING_MISMATCH",
    }),
  );
}

{
  const prefix = committedPrefix(3);
  const settleUnknown = referenceAction("SETTLE", "unknown", {
    settlementOutcome: "UNKNOWN",
    reconciliationDeadline: "2030-01-01T00:05:00Z",
    unknownObservationDigest: REFERENCE_FIXTURE.proofs.SETTLEMENT_UNKNOWN,
  });
  const resolve = referenceAction("RESOLVE_SETTLEMENT");
  generated.push(
    vector({
      id: "HOSTED.SETTLE.UNKNOWN_PENDING.001",
      actions: [...prefix.map(({ action }) => action), settleUnknown],
      invocationState: "PAYMENT_UNKNOWN",
      paymentIntentState: "SETTLEMENT_UNKNOWN",
      observations: [
        ...prefix.map(({ observation: value }) => value),
        observation(settleUnknown, "RECONCILIATION_REQUIRED", "SETTLEMENT_UNKNOWN"),
      ],
      effects: effectsThrough(3),
      errorCode: "SETTLEMENT_UNKNOWN",
    }),
  );
  generated.push(
    vector({
      id: "HOSTED.SETTLE.UNKNOWN_RESOLVED.001",
      actions: [...prefix.map(({ action }) => action), settleUnknown, resolve],
      invocationState: "DELIVERABLE",
      paymentIntentState: "FINALIZED",
      observations: [
        ...prefix.map(({ observation: value }) => value),
        observation(settleUnknown, "RECONCILIATION_REQUIRED", "SETTLEMENT_UNKNOWN"),
        observation(resolve, "COMMITTED"),
      ],
      effects: effectsThrough(4),
    }),
  );

  for (const missingField of ["reconciliationDeadline", "unknownObservationDigest"]) {
    const incomplete = { ...settleUnknown, actionId: `settle-unknown-missing-${missingField}` };
    delete incomplete[missingField];
    generated.push(
      vector({
        id: `HOSTED.SETTLE.UNKNOWN_MISSING_${missingField.toUpperCase()}.001`,
        actions: [...prefix.map(({ action }) => action), incomplete],
        invocationState: "OUTPUT_STAGED",
        paymentIntentState: "AUTHORIZED",
        observations: [
          ...prefix.map(({ observation: value }) => value),
          observation(incomplete, "REJECTED", "PROOF_INCOMPLETE"),
        ],
        effects: effectsThrough(3),
        errorCode: "PROOF_INCOMPLETE",
      }),
    );
  }
}

export const VECTORS = Object.freeze(generated.map(Object.freeze));
