import { spawn } from "node:child_process";

import { canonicalJson, digestCanonical } from "../../reference/canonical.mjs";

const MAX_ADAPTER_OUTPUT_BYTES = 1024 * 1024;
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
  "skipped",
]);

class AdapterError extends Error {}

const DIGEST = /^sha256:[0-9a-f]{64}$/;

function assertExactObjectKeys(value, keys, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new AdapterError(`${label} is not an object`);
  }
  if (canonicalJson(Object.keys(value).sort()) !== canonicalJson([...keys].sort())) {
    throw new AdapterError(`${label} has unknown fields`);
  }
}

function assertDigestOrNull(value, label) {
  if (value !== null && (typeof value !== "string" || !DIGEST.test(value))) {
    throw new AdapterError(`${label} is not a digest`);
  }
}

function validateNormalizedState(state) {
  assertExactObjectKeys(
    state,
    [
      "capabilities",
      "listing",
      "invocation",
      "paymentIntent",
      "output",
      "effects",
      "transitionJournal",
    ],
    "finalState",
  );
  assertExactObjectKeys(state.capabilities, ["realMoney", "warning"], "capabilities");
  if (
    state.capabilities.realMoney !== false ||
    state.capabilities.warning !== "REFERENCE_ONLY_NO_REAL_FUNDS"
  ) {
    throw new AdapterError("reference conformance must not claim real-money capability");
  }
  assertExactObjectKeys(
    state.listing,
    ["state", "serviceSkuId", "skuVersionDigest", "issuer"],
    "listing",
  );
  assertExactObjectKeys(
    state.invocation,
    [
      "invocationId",
      "mode",
      "serviceSkuId",
      "skuVersionDigest",
      "requestDigest",
      "commercialIssuer",
      "paymentIntentRef",
      "paymentProofDigest",
      "outputStagingReceiptDigest",
      "settlementReceiptDigest",
      "fundingUnknownObservationDigest",
      "reconciliationDeadline",
      "deliveryReceiptDigest",
      "acknowledgementDigest",
      "state",
    ],
    "invocation",
  );
  assertExactObjectKeys(state.output, ["buffered", "byteCount", "responseDigest"], "output");
  assertExactObjectKeys(
    state.effects,
    ["acknowledgements", "authorizations", "deliveries", "executions", "settlements", "stagings"],
    "effects",
  );
  assertExactObjectKeys(
    state.transitionJournal,
    ["count", "digest"],
    "transitionJournal",
  );
  if (
    !Number.isSafeInteger(state.transitionJournal.count) ||
    state.transitionJournal.count < 0
  ) {
    throw new AdapterError("transitionJournal.count is invalid");
  }
  assertDigestOrNull(state.transitionJournal.digest, "transitionJournal.digest");
  for (const field of [
    "skuVersionDigest",
    "requestDigest",
    "paymentProofDigest",
    "outputStagingReceiptDigest",
    "settlementReceiptDigest",
    "fundingUnknownObservationDigest",
    "deliveryReceiptDigest",
    "acknowledgementDigest",
  ]) {
    assertDigestOrNull(state.invocation[field], `invocation.${field}`);
  }
  assertDigestOrNull(state.listing.skuVersionDigest, "listing.skuVersionDigest");
  assertDigestOrNull(state.output.responseDigest, "output.responseDigest");

  if (state.paymentIntent !== null) {
    assertExactObjectKeys(
      state.paymentIntent,
      [
        "paymentIntentId",
        "invocationRef",
        "skuVersionDigest",
        "fingerprintDigest",
        "authorizationProfile",
        "fundingAuthority",
        "settlementAuthority",
        "observationAuthority",
        "state",
        "authorizationProofDigest",
        "settlementReceiptDigest",
        "fundingUnknownObservationDigest",
        "reconciliationDeadline",
      ],
      "paymentIntent",
    );
    for (const authority of ["fundingAuthority", "settlementAuthority", "observationAuthority"]) {
      assertExactObjectKeys(state.paymentIntent[authority], ["issuer", "keyId"], authority);
    }
    if (state.paymentIntent.authorizationProfile !== "MANDATE_PROTECTED") {
      throw new AdapterError("paymentIntent authorization profile mismatch");
    }
    for (const field of [
      "skuVersionDigest",
      "fingerprintDigest",
      "authorizationProofDigest",
      "settlementReceiptDigest",
      "fundingUnknownObservationDigest",
    ]) {
      assertDigestOrNull(state.paymentIntent[field], `paymentIntent.${field}`);
    }
    if (
      state.invocation.paymentIntentRef !== state.paymentIntent.paymentIntentId ||
      state.paymentIntent.invocationRef !== state.invocation.invocationId ||
      state.paymentIntent.skuVersionDigest !== state.invocation.skuVersionDigest ||
      state.paymentIntent.authorizationProofDigest !== state.invocation.paymentProofDigest ||
      state.paymentIntent.settlementReceiptDigest !== state.invocation.settlementReceiptDigest ||
      state.paymentIntent.fundingUnknownObservationDigest !==
        state.invocation.fundingUnknownObservationDigest ||
      state.paymentIntent.reconciliationDeadline !== state.invocation.reconciliationDeadline
    ) {
      throw new AdapterError("commercial/funding immutable bindings mismatch");
    }
  } else if (state.invocation.paymentIntentRef !== null) {
    throw new AdapterError("Invocation references a missing PaymentIntent");
  }
}

function assertMetadataOnly(value) {
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) assertMetadataOnly(item);
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_KEYS.has(key)) throw new AdapterError("adapter returned forbidden data");
    assertMetadataOnly(child);
  }
}

function validateAdapterResponse(vector, response) {
  if (response === null || typeof response !== "object" || Array.isArray(response)) {
    throw new AdapterError("adapter response is not an object");
  }
  const keys = Object.keys(response).sort();
  if (canonicalJson(keys) !== canonicalJson(["finalState", "observations", "vectorId"])) {
    throw new AdapterError("adapter response has unknown fields");
  }
  if (response.vectorId !== vector.id) throw new AdapterError("adapter vector mismatch");
  if (
    response.finalState === null ||
    typeof response.finalState !== "object" ||
    Array.isArray(response.finalState) ||
    !Array.isArray(response.observations)
  ) {
    throw new AdapterError("adapter response shape is invalid");
  }
  assertMetadataOnly(response);
  validateNormalizedState(response.finalState);
  for (const item of response.observations) {
    const allowed = item.reasonCode === undefined
      ? [
          "actionId",
          "type",
          "outcome",
          "errorCode",
          "transitionCount",
          "transitionTraceDigest",
        ]
      : [
          "actionId",
          "type",
          "outcome",
          "errorCode",
          "reasonCode",
          "transitionCount",
          "transitionTraceDigest",
        ];
    assertExactObjectKeys(item, allowed, "observation");
    if (!Number.isSafeInteger(item.transitionCount) || item.transitionCount < 0) {
      throw new AdapterError("observation transitionCount is invalid");
    }
    assertDigestOrNull(item.transitionTraceDigest, "observation.transitionTraceDigest");
  }
  const committedTransitionCount = response.observations
    .filter(({ outcome }) => outcome !== "IDEMPOTENT_REPLAY")
    .reduce((sum, { transitionCount }) => sum + transitionCount, 0);
  if (response.finalState.transitionJournal.count !== committedTransitionCount) {
    throw new AdapterError("transition journal count mismatch");
  }
  return response;
}

function stateProjection(state) {
  return {
    listingState: state.listing?.state ?? null,
    invocationState: state.invocation?.state ?? null,
    paymentIntentState: state.paymentIntent?.state ?? null,
  };
}

function lastErrorCode(observations) {
  return observations.length === 0 ? null : (observations.at(-1).errorCode ?? null);
}

export function evaluateVector(vector, response) {
  const validated = validateAdapterResponse(vector, response);
  const actualErrorCode = lastErrorCode(validated.observations);
  const matches =
    canonicalJson(validated.finalState) === canonicalJson(vector.expected.normalizedState) &&
    canonicalJson(stateProjection(validated.finalState)) === canonicalJson(vector.expected.state) &&
    canonicalJson(validated.finalState.effects) === canonicalJson(vector.expected.effects) &&
    canonicalJson(validated.finalState.transitionJournal) ===
      canonicalJson(vector.expected.transitionJournal) &&
    canonicalJson(validated.observations) === canonicalJson(vector.expected.observations) &&
    actualErrorCode === vector.expected.errorCode;

  return {
    vectorId: vector.id,
    result: matches ? "PASS" : "FAIL",
    stateDigest: digestCanonical(validated.finalState),
    errorCode: actualErrorCode,
  };
}

function adapterRequest(vector) {
  return {
    command: "runVector",
    scenario: {
      vectorId: vector.id,
      protocolVersion: vector.protocolVersion,
      protocolDigest: vector.protocolDigest,
      precondition: vector.precondition,
      actions: vector.action.steps,
    },
  };
}

export function invokeAdapter(vector, { executable, args, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      callback(value);
    };
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(reject, new AdapterError("adapter timeout"));
    }, timeoutMs);

    child.on("error", (error) => finish(reject, new AdapterError(error.code ?? "adapter spawn")));
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      if (Buffer.byteLength(stdout) > MAX_ADAPTER_OUTPUT_BYTES) child.kill("SIGKILL");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
      if (Buffer.byteLength(stderr) > MAX_ADAPTER_OUTPUT_BYTES) child.kill("SIGKILL");
    });
    child.on("close", (code, signal) => {
      if (code !== 0 || signal !== null) {
        finish(reject, new AdapterError(`adapter failed: ${code ?? signal}`));
        return;
      }
      let parsed;
      try {
        parsed = JSON.parse(stdout);
      } catch {
        finish(reject, new AdapterError("adapter emitted invalid JSON"));
        return;
      }
      if (stderr !== "") {
        finish(reject, new AdapterError("adapter emitted unexpected stderr"));
        return;
      }
      finish(resolve, parsed);
    });
    child.stdin.end(`${canonicalJson(adapterRequest(vector))}\n`);
  });
}

export async function runConformance(vectors, adapter) {
  const reports = [];
  for (const vector of vectors) {
    try {
      const response = await invokeAdapter(vector, adapter);
      reports.push(evaluateVector(vector, response));
    } catch {
      reports.push({
        vectorId: vector.id,
        result: "FAIL",
        stateDigest: digestCanonical({ adapterResponse: "INVALID", vectorId: vector.id }),
        errorCode: "SCHEMA_INVALID",
      });
    }
  }
  return reports;
}
