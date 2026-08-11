import { digestCanonical } from "./canonical.mjs";
import { REFERENCE_PRECONDITION } from "./constants.mjs";

export function createVerifyBinding(
  paymentIntentFingerprintDigest,
  overrides = {},
  precondition = REFERENCE_PRECONDITION,
) {
  return {
    invocationId: precondition.invocationId,
    serviceSkuId: precondition.serviceSkuId,
    skuVersionDigest: precondition.skuVersionDigest,
    paymentIntentFingerprintDigest,
    authorizationProfile: precondition.authorizationProfile,
    authorizationAuthority: {
      ...precondition.authorizationAuthority,
    },
    ...overrides,
  };
}

export function verifyProofDigest(binding) {
  return digestCanonical({
    domain: "OPENANT_REFERENCE_VERIFY_BINDING_V1",
    claims: binding,
  });
}

export function isExpectedVerifyBinding(action, precondition) {
  if (action.verifyBinding === null || typeof action.verifyBinding !== "object") return false;
  const expected = createVerifyBinding(action.fingerprintDigest, {}, precondition);
  return (
    action.fingerprintDigest === precondition.paymentIntentFingerprintDigest &&
    verifyProofDigest(action.verifyBinding) === action.proofDigest &&
    verifyProofDigest(expected) === action.proofDigest
  );
}

export function createBoundaryBinding(
  boundary,
  overrides = {},
  precondition = REFERENCE_PRECONDITION,
) {
  return {
    boundary,
    invocationId: precondition.invocationId,
    serviceSkuId: precondition.serviceSkuId,
    skuVersionDigest: precondition.skuVersionDigest,
    paymentIntentFingerprintDigest: precondition.paymentIntentFingerprintDigest,
    authorizationProfile: precondition.authorizationProfile,
    ...overrides,
  };
}

export function boundaryProofDigest(binding) {
  return digestCanonical({
    domain: "OPENANT_REFERENCE_BOUNDARY_BINDING_V1",
    claims: binding,
  });
}

export function isExpectedBoundaryBinding(action, state, precondition) {
  if (action.boundaryBinding === null || typeof action.boundaryBinding !== "object") {
    return false;
  }
  const expected = createBoundaryBinding(action.type, {}, precondition);
  if (
    state.paymentIntent !== null &&
    state.paymentIntent.fingerprintDigest !== expected.paymentIntentFingerprintDigest
  ) {
    return false;
  }
  return (
    boundaryProofDigest(action.boundaryBinding) === action.proofDigest &&
    boundaryProofDigest(expected) === action.proofDigest
  );
}
