import { PROTOCOL_DIGEST, PROTOCOL_VERSION, REFERENCE_FIXTURE } from "./constants.mjs";

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const RFC3339_SECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const FORBIDDEN_KEYS = new Set([
  "prompt",
  "toolArguments",
  "requestBody",
  "responseBody",
  "artifactBytes",
  "token",
  "cookie",
  "credential",
  "privateKey",
  "skip",
]);
const SCENARIO_KEYS = new Set([
  "vectorId",
  "protocolVersion",
  "protocolDigest",
  "precondition",
  "actions",
]);
const ACTION_KEYS = new Set([
  "actionId",
  "type",
  "idempotencyKey",
  "fingerprintDigest",
  "proofDigest",
  "fault",
  "sellerOutcome",
  "settlementOutcome",
  "reconciliationDeadline",
  "unknownObservationDigest",
  "verifyBinding",
  "boundaryBinding",
  "macroMutation",
]);
const ACTION_TYPES = new Set(Object.keys(REFERENCE_FIXTURE.proofs).filter((key) => key !== "SETTLEMENT_UNKNOWN"));

export class ReferenceProtocolError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

const reject = (code = "SCHEMA_INVALID") => {
  throw new ReferenceProtocolError(code);
};

function assertNoForbiddenKeys(value) {
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) assertNoForbiddenKeys(item);
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_KEYS.has(key)) reject();
    assertNoForbiddenKeys(child);
  }
}

function assertExactKeys(value, allowed) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) reject();
  for (const key of Object.keys(value)) if (!allowed.has(key)) reject();
}

function validateAction(action) {
  assertExactKeys(action, ACTION_KEYS);
  if (!IDENTIFIER.test(action.actionId) || !IDENTIFIER.test(action.idempotencyKey)) reject();
  if (!ACTION_TYPES.has(action.type)) reject();
  if (!DIGEST.test(action.fingerprintDigest) || !DIGEST.test(action.proofDigest)) reject();
  if (action.fault !== undefined && !["TIMEOUT_BEFORE_COMMIT", "TIMEOUT_AFTER_COMMIT"].includes(action.fault)) reject();
  if (action.sellerOutcome !== undefined && !["HTTP_5XX", "TIMEOUT", "SCHEMA_ERROR"].includes(action.sellerOutcome)) reject();
  if (action.settlementOutcome !== undefined && action.settlementOutcome !== "UNKNOWN") reject();
  if (action.sellerOutcome !== undefined && action.type !== "EXECUTE") reject();
  if (
    (action.settlementOutcome !== undefined ||
      action.reconciliationDeadline !== undefined ||
      action.unknownObservationDigest !== undefined) &&
    action.type !== "SETTLE"
  ) {
    reject();
  }
  if (
    action.macroMutation !== undefined &&
    !["UNKNOWN_TRANSITION", "SKIP_REQUIRED_STATE", "SKIP_RESERVATION"].includes(
      action.macroMutation,
    )
  ) {
    reject();
  }
  if (action.type === "VERIFY") {
    assertExactKeys(
      action.verifyBinding,
      new Set([
        "invocationId",
        "serviceSkuId",
        "skuVersionDigest",
        "paymentIntentFingerprintDigest",
        "authorizationProfile",
        "authorizationAuthority",
      ]),
    );
    if (
      !IDENTIFIER.test(action.verifyBinding.invocationId) ||
      !IDENTIFIER.test(action.verifyBinding.serviceSkuId) ||
      !DIGEST.test(action.verifyBinding.skuVersionDigest) ||
      !DIGEST.test(action.verifyBinding.paymentIntentFingerprintDigest)
    ) {
      reject();
    }
    if (action.verifyBinding.authorizationProfile !== "MANDATE_PROTECTED") reject();
    assertExactKeys(action.verifyBinding.authorizationAuthority, new Set(["issuer", "keyId"]));
    if (
      !IDENTIFIER.test(action.verifyBinding.authorizationAuthority.issuer) ||
      !IDENTIFIER.test(action.verifyBinding.authorizationAuthority.keyId)
    ) {
      reject();
    }
  } else {
    if (action.verifyBinding !== undefined || action.macroMutation !== undefined) reject();
    assertExactKeys(
      action.boundaryBinding,
      new Set([
        "boundary",
        "invocationId",
        "serviceSkuId",
        "skuVersionDigest",
        "paymentIntentFingerprintDigest",
        "authorizationProfile",
      ]),
    );
    if (
      action.boundaryBinding.boundary !== action.type ||
      !IDENTIFIER.test(action.boundaryBinding.invocationId) ||
      !IDENTIFIER.test(action.boundaryBinding.serviceSkuId) ||
      !DIGEST.test(action.boundaryBinding.skuVersionDigest) ||
      !DIGEST.test(action.boundaryBinding.paymentIntentFingerprintDigest) ||
      action.boundaryBinding.authorizationProfile !== "MANDATE_PROTECTED"
    ) {
      reject();
    }
  }
  if (action.reconciliationDeadline !== undefined) {
    if (!RFC3339_SECONDS.test(action.reconciliationDeadline)) reject();
    const parsed = Date.parse(action.reconciliationDeadline);
    if (!Number.isFinite(parsed)) reject();
  }
  if (
    action.unknownObservationDigest !== undefined &&
    !DIGEST.test(action.unknownObservationDigest)
  ) {
    reject();
  }
}

export function validateScenario(scenario) {
  assertNoForbiddenKeys(scenario);
  assertExactKeys(scenario, SCENARIO_KEYS);
  if (!IDENTIFIER.test(scenario.vectorId)) reject();
  if (
    scenario.protocolVersion !== PROTOCOL_VERSION ||
    scenario.protocolDigest !== PROTOCOL_DIGEST
  ) {
    reject("UNSUPPORTED_PROTOCOL_VERSION");
  }
  assertExactKeys(
    scenario.precondition,
    new Set([
      "listingState",
      "invocationId",
      "serviceSkuId",
      "skuVersionDigest",
      "authorizationAuthority",
      "authorizationProfile",
      "paymentIntentFingerprintDigest",
    ]),
  );
  if (!["ACTIVE", "EMERGENCY_REVOKED"].includes(scenario.precondition.listingState)) reject();
  if (
    !IDENTIFIER.test(scenario.precondition.invocationId) ||
    !IDENTIFIER.test(scenario.precondition.serviceSkuId) ||
    !DIGEST.test(scenario.precondition.skuVersionDigest)
  ) {
    reject();
  }
  if (
    scenario.precondition.authorizationProfile !== "MANDATE_PROTECTED" ||
    !DIGEST.test(scenario.precondition.paymentIntentFingerprintDigest)
  ) {
    reject();
  }
  assertExactKeys(
    scenario.precondition.authorizationAuthority,
    new Set(["issuer", "keyId"]),
  );
  if (
    !IDENTIFIER.test(scenario.precondition.authorizationAuthority.issuer) ||
    !IDENTIFIER.test(scenario.precondition.authorizationAuthority.keyId)
  ) {
    reject();
  }
  if (!Array.isArray(scenario.actions) || scenario.actions.length === 0 || scenario.actions.length > 32) reject();
  for (const action of scenario.actions) validateAction(action);
}
