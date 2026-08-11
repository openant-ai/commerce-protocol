import {
  PROTOCOL_DIGEST,
  PROTOCOL_VERSION,
  REFERENCE_FIXTURE,
} from "./constants.mjs";
import { validateScenario } from "./validation.mjs";
import {
  isExpectedBoundaryBinding,
  isExpectedVerifyBinding,
} from "./proof-binding.mjs";
import {
  IllegalTransitionError,
  digestTransitionTrace,
  transition,
} from "./transition-registry.mjs";

export { PROTOCOL_DIGEST, PROTOCOL_VERSION, REFERENCE_FIXTURE } from "./constants.mjs";
export { REFERENCE_PRECONDITION } from "./constants.mjs";
export {
  boundaryProofDigest,
  createBoundaryBinding,
  createVerifyBinding,
  verifyProofDigest,
} from "./proof-binding.mjs";
export { digestTransitionTrace } from "./transition-registry.mjs";

function emptyEffects() {
  return {
    acknowledgements: 0,
    authorizations: 0,
    deliveries: 0,
    executions: 0,
    settlements: 0,
    stagings: 0,
  };
}

function createState(precondition) {
  return {
    capabilities: {
      realMoney: false,
      warning: "REFERENCE_ONLY_NO_REAL_FUNDS",
    },
    listing: {
      state: precondition.listingState,
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
      paymentIntentRef: null,
      paymentProofDigest: null,
      outputStagingReceiptDigest: null,
      settlementReceiptDigest: null,
      fundingUnknownObservationDigest: null,
      reconciliationDeadline: null,
      deliveryReceiptDigest: null,
      acknowledgementDigest: null,
      state: "CREATED",
    },
    paymentIntent: null,
    output: {
      buffered: false,
      byteCount: null,
      responseDigest: null,
    },
    effects: emptyEffects(),
    transitionJournal: {
      count: 0,
      digest: digestTransitionTrace([]),
    },
  };
}

function observe(
  action,
  outcome = "COMMITTED",
  errorCode = null,
  reasonCode = null,
  trace = [],
) {
  const observation = {
    actionId: action.actionId,
    type: action.type,
    outcome,
    errorCode,
    transitionCount: trace.length,
    transitionTraceDigest: digestTransitionTrace(trace),
  };
  if (reasonCode !== null) observation.reasonCode = reasonCode;
  return observation;
}

function createPaymentIntent(action, state) {
  return {
    paymentIntentId: REFERENCE_FIXTURE.paymentIntentId,
    invocationRef: state.invocation.invocationId,
    skuVersionDigest: state.invocation.skuVersionDigest,
    fingerprintDigest: action.fingerprintDigest,
    authorizationProfile: action.verifyBinding.authorizationProfile,
    fundingAuthority: {
      ...action.verifyBinding.authorizationAuthority,
    },
    settlementAuthority: {
      ...REFERENCE_FIXTURE.settlementAuthority,
    },
    observationAuthority: {
      ...REFERENCE_FIXTURE.observationAuthority,
    },
    state: "CREATED",
    authorizationProofDigest: null,
    settlementReceiptDigest: null,
    fundingUnknownObservationDigest: null,
    reconciliationDeadline: null,
  };
}

function transitionPayment(paymentIntent, to, trace) {
  transition(paymentIntent, "paymentIntent", to, trace, {
    authorizationProfile: paymentIntent.authorizationProfile,
  });
}

function applyMacro(state, action) {
  const candidate = structuredClone(state);
  const trace = [];
  let outcome = "COMMITTED";
  let errorCode = null;
  let reasonCode = null;

  switch (action.type) {
    case "VERIFY": {
      if (action.macroMutation === "UNKNOWN_TRANSITION") {
        transition(candidate.invocation, "invocation", "UNKNOWN_STATE", trace);
      }
      if (action.macroMutation === "SKIP_REQUIRED_STATE") {
        transition(candidate.invocation, "invocation", "PAYMENT_AUTHORIZED", trace);
      }
      transition(candidate.invocation, "invocation", "PAYMENT_REQUIRED", trace);
      candidate.paymentIntent = createPaymentIntent(action, candidate);
      if (action.macroMutation === "SKIP_RESERVATION") {
        transitionPayment(candidate.paymentIntent, "AUTHORIZING", trace);
      }
      transitionPayment(candidate.paymentIntent, "RESERVED", trace);
      transitionPayment(candidate.paymentIntent, "AUTHORIZING", trace);
      transitionPayment(candidate.paymentIntent, "AUTHORIZED", trace);
      transition(candidate.invocation, "invocation", "PAYMENT_AUTHORIZED", trace);
      candidate.invocation.paymentIntentRef = REFERENCE_FIXTURE.paymentIntentId;
      candidate.invocation.paymentProofDigest = action.proofDigest;
      candidate.paymentIntent.authorizationProofDigest = action.proofDigest;
      candidate.effects.authorizations += 1;
      break;
    }
    case "EXECUTE": {
      if (action.sellerOutcome) {
        transition(candidate.invocation, "invocation", "FAILED_BEFORE_SETTLEMENT", trace);
        candidate.effects.executions += 1;
        outcome = "REJECTED";
        errorCode = "OUTPUT_NOT_CHARGEABLE";
        reasonCode = `SELLER_${action.sellerOutcome}`;
        break;
      }
      transition(candidate.invocation, "invocation", "EXECUTING", trace);
      candidate.output.responseDigest = REFERENCE_FIXTURE.responseDigest;
      candidate.output.byteCount = REFERENCE_FIXTURE.outputByteCount;
      candidate.effects.executions += 1;
      break;
    }
    case "STAGE":
      transition(candidate.invocation, "invocation", "OUTPUT_STAGED", trace);
      candidate.invocation.outputStagingReceiptDigest = action.proofDigest;
      candidate.output.buffered = true;
      candidate.effects.stagings += 1;
      break;
    case "SETTLE": {
      transition(candidate.invocation, "invocation", "SETTLEMENT_PENDING", trace);
      transitionPayment(candidate.paymentIntent, "SUBMITTED", trace);
      if (action.settlementOutcome === "UNKNOWN") {
        transitionPayment(candidate.paymentIntent, "SETTLEMENT_UNKNOWN", trace);
        transition(candidate.invocation, "invocation", "PAYMENT_UNKNOWN", trace);
        candidate.paymentIntent.fundingUnknownObservationDigest =
          action.unknownObservationDigest;
        candidate.paymentIntent.reconciliationDeadline = action.reconciliationDeadline;
        candidate.invocation.fundingUnknownObservationDigest = action.unknownObservationDigest;
        candidate.invocation.reconciliationDeadline = action.reconciliationDeadline;
        outcome = "RECONCILIATION_REQUIRED";
        errorCode = "SETTLEMENT_UNKNOWN";
        break;
      }
      transitionPayment(candidate.paymentIntent, "CONFIRMED", trace);
      transitionPayment(candidate.paymentIntent, "FINALIZED", trace);
      transition(candidate.invocation, "invocation", "DELIVERABLE", trace);
      candidate.paymentIntent.settlementReceiptDigest = action.proofDigest;
      candidate.invocation.settlementReceiptDigest = action.proofDigest;
      candidate.effects.settlements += 1;
      break;
    }
    case "DELIVER":
      transition(candidate.invocation, "invocation", "DELIVERED", trace);
      candidate.invocation.deliveryReceiptDigest = action.proofDigest;
      candidate.effects.deliveries += 1;
      break;
    case "ACK":
      transition(candidate.invocation, "invocation", "ACKED", trace);
      candidate.invocation.acknowledgementDigest = action.proofDigest;
      candidate.effects.acknowledgements += 1;
      break;
    case "RESOLVE_SETTLEMENT":
      transitionPayment(candidate.paymentIntent, "CONFIRMED", trace);
      transitionPayment(candidate.paymentIntent, "FINALIZED", trace);
      transition(candidate.invocation, "invocation", "DELIVERABLE", trace);
      candidate.paymentIntent.fundingUnknownObservationDigest = null;
      candidate.paymentIntent.reconciliationDeadline = null;
      candidate.paymentIntent.settlementReceiptDigest = action.proofDigest;
      candidate.invocation.fundingUnknownObservationDigest = null;
      candidate.invocation.reconciliationDeadline = null;
      candidate.invocation.settlementReceiptDigest = action.proofDigest;
      candidate.effects.settlements += 1;
      break;
    case "REVOKE_LISTING": {
      transition(candidate.listing, "listing", "EMERGENCY_REVOKED", trace);
      const settlementFinal = ["DELIVERABLE", "DELIVERED", "ACKED"].includes(
        candidate.invocation.state,
      );
      if (!settlementFinal) {
        transition(
          candidate.invocation,
          "invocation",
          "FAILED_BEFORE_SETTLEMENT",
          trace,
        );
        outcome = "REJECTED";
        errorCode = "LISTING_REVOKED";
        reasonCode = "REVOKED_BEFORE_SETTLEMENT";
      } else {
        reasonCode = "SETTLED_INVOCATION_CONVERGES";
      }
      break;
    }
    default:
      throw new Error(`unknown action type: ${action.type}`);
  }
  return { candidate, trace, outcome, errorCode, reasonCode };
}

export function runScenario(scenario) {
  return runValidatedScenario(scenario);
}

function runValidatedScenario(scenario) {
  validateScenario(scenario);
  let state = createState(scenario.precondition);
  const observations = [];
  const committedOperations = new Map();
  const transitionJournal = [];
  for (const action of scenario.actions) {
    const committed = committedOperations.get(action.idempotencyKey);
    if (committed) {
      if (
        committed.type === action.type &&
        committed.fingerprintDigest === action.fingerprintDigest
      ) {
        observations.push(
          observe(
            action,
            "IDEMPOTENT_REPLAY",
            committed.errorCode,
            committed.reasonCode,
            committed.trace,
          ),
        );
      } else {
        observations.push(
          observe(action, "REJECTED", "IDEMPOTENCY_FINGERPRINT_CONFLICT"),
        );
      }
      continue;
    }
    if (action.type === "VERIFY" && state.listing.state !== "ACTIVE") {
      const trace = [];
      const candidate = structuredClone(state);
      transition(candidate.invocation, "invocation", "FAILED_BEFORE_SETTLEMENT", trace);
      transitionJournal.push(...trace);
      candidate.transitionJournal = {
        count: transitionJournal.length,
        digest: digestTransitionTrace(transitionJournal),
      };
      state = candidate;
      committedOperations.set(action.idempotencyKey, {
        type: action.type,
        fingerprintDigest: action.fingerprintDigest,
        trace,
        errorCode: "LISTING_REVOKED",
        reasonCode: "REVOKED_LISTING",
      });
      observations.push(
        observe(
          action,
          "REJECTED",
          "LISTING_REVOKED",
          "REVOKED_LISTING",
          trace,
        ),
      );
      continue;
    }
    const proofMatches =
      action.type === "VERIFY"
        ? isExpectedVerifyBinding(action, scenario.precondition)
        : isExpectedBoundaryBinding(action, state, scenario.precondition);
    if (!proofMatches) {
      observations.push(observe(action, "REJECTED", "PROOF_BINDING_MISMATCH"));
      continue;
    }
    if (action.fault === "TIMEOUT_BEFORE_COMMIT") {
      observations.push(observe(action, "TIMEOUT_BEFORE_COMMIT"));
      continue;
    }
    if (action.type === "SETTLE" && action.settlementOutcome === "UNKNOWN") {
      if (
        !action.reconciliationDeadline ||
        action.unknownObservationDigest !== REFERENCE_FIXTURE.proofs.SETTLEMENT_UNKNOWN
      ) {
        observations.push(observe(action, "REJECTED", "PROOF_INCOMPLETE"));
        continue;
      }
    }
    let macroResult;
    try {
      macroResult = applyMacro(state, action);
    } catch (error) {
      if (!(error instanceof IllegalTransitionError)) throw error;
      observations.push(observe(action, "REJECTED", "ILLEGAL_STATE_TRANSITION"));
      continue;
    }
    transitionJournal.push(...macroResult.trace);
    macroResult.candidate.transitionJournal = {
      count: transitionJournal.length,
      digest: digestTransitionTrace(transitionJournal),
    };
    state = macroResult.candidate;
    committedOperations.set(action.idempotencyKey, {
      type: action.type,
      fingerprintDigest: action.fingerprintDigest,
      trace: macroResult.trace,
      errorCode: macroResult.errorCode,
      reasonCode: macroResult.reasonCode,
    });
    observations.push(
      observe(
        action,
        action.fault === "TIMEOUT_AFTER_COMMIT"
          ? "TIMEOUT_AFTER_COMMIT"
          : macroResult.outcome,
        macroResult.errorCode,
        macroResult.reasonCode,
        macroResult.trace,
      ),
    );
  }
  return { vectorId: scenario.vectorId, finalState: state, observations };
}
