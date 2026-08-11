import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";

import { PROJECTIONS, EFFECTS } from "./projections.mjs";

const SCHEMA_VERSION = "openant-commerce-cross-conformance/1";
const PROTOCOL_VERSION = "0.1.0-draft.4";
const PROTOCOL_DIGEST = "sha256:0069b449f4b0f2f2ae88103219a182703498231b3e7cbe6d76cdd7e3f195ff27";

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

async function input() {
  process.stdin.setEncoding("utf8");
  let source = "";
  for await (const chunk of process.stdin) source += chunk;
  return JSON.parse(source);
}

function response(request) {
  const projection = PROJECTIONS.get(request.vectorId);
  if (projection === undefined) throw new Error("unknown vector");
  const [paymentIntentState, errorCode, effectsDigest, lineageDigest, profile] = projection;
  return {
    schemaVersion: SCHEMA_VERSION,
    implementation: "0xkey-commerce-authorization",
    implementationVersion: "0.1.0",
    protocolVersion: PROTOCOL_VERSION,
    protocolDigest: PROTOCOL_DIGEST,
    vectorId: request.vectorId,
    result: "PASS",
    paymentIntentState,
    errorCode,
    effects: { ...EFFECTS[profile] },
    effectsDigest: `sha256:${effectsDigest}`,
    lineageDigest: `sha256:${lineageDigest}`,
  };
}

export async function runFixture(mode) {
  const request = await input();
  const wireAttacks = [
    "invalid-json", "duplicate-key", "unknown-field", "wrong-version",
    "invalid-utf8", "noncanonical", "private-skip", "private-error",
  ];
  const processAttacks = [
    "extra-response", "missing-response", "stderr", "nonzero", "signal",
    "timeout", "oversize", "out-of-order", "duplicate-response",
  ];
  const projectionMutations = ["mutate-state", "mutate-error", "mutate-effects", "mutate-lineage"];
  const vectorIndex = [...PROJECTIONS.keys()].indexOf(request.vectorId);
  const selected = mode === "wire-attacks" ? wireAttacks[vectorIndex]
    : mode === "process-attacks" || mode.startsWith("process-attacks:")
      ? processAttacks[vectorIndex]
    : mode === "projection-mutations" ? projectionMutations[vectorIndex]
    : mode;
  const result = response(request);
  if (selected === "invalid-json") process.stdout.write("{\n");
  else if (selected === "duplicate-key") {
    const encoded = canonicalJson(result).replace(
      `"schemaVersion":"${SCHEMA_VERSION}"`,
      `"schemaVersion":"duplicate","schemaVersion":"${SCHEMA_VERSION}"`,
    );
    process.stdout.write(`${encoded}\n`);
  } else if (selected === "unknown-field") {
    result.unregistered = true;
    process.stdout.write(`${canonicalJson(result)}\n`);
  } else if (selected === "wrong-version") {
    result.protocolVersion = "0.1.0-draft.attacker";
    process.stdout.write(`${canonicalJson(result)}\n`);
  } else if (selected === "invalid-utf8") {
    process.stdout.write(Buffer.from([0xff, 0x0a]));
  } else if (selected === "noncanonical") {
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } else if (selected === "private-skip") {
    result.skipped = true;
    process.stdout.write(`${canonicalJson(result)}\n`);
  } else if (selected === "private-error") {
    result.errorCode = "PRIVATE_SIGNER_TIMEOUT";
    process.stdout.write(`${canonicalJson(result)}\n`);
  } else if (selected === "extra-response") {
    process.stdout.write(`${canonicalJson(result)}\n{}\n`);
  } else if (selected === "missing-response") {
    // A successful process without a response is not a partial pass.
  } else if (selected === "stderr") {
    process.stdout.write(`${canonicalJson(result)}\n`);
    process.stderr.write("unexpected diagnostic\n");
  } else if (selected === "nonzero") {
    process.exitCode = 7;
  } else if (selected === "signal") {
    process.kill(process.pid, "SIGTERM");
  } else if (selected === "timeout") {
    if (mode.startsWith("process-attacks:")) {
      const descendant = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
        stdio: "ignore",
      });
      writeFileSync(mode.slice("process-attacks:".length), `${descendant.pid}\n`);
    }
    setInterval(() => {}, 1_000);
  } else if (selected === "oversize") {
    process.stdout.write(Buffer.alloc(1024 * 1024 + 1, 0x61));
  } else if (selected === "out-of-order") {
    result.vectorId = [...PROJECTIONS.keys()][vectorIndex + 1];
    process.stdout.write(`${canonicalJson(result)}\n`);
  } else if (selected === "duplicate-response") {
    const encoded = canonicalJson(result);
    process.stdout.write(`${encoded}\n${encoded}\n`);
  } else if (selected === "mutate-state") {
    result.paymentIntentState = "AUTHORIZED";
    process.stdout.write(`${canonicalJson(result)}\n`);
  } else if (selected === "mutate-error") {
    result.errorCode = "SETTLEMENT_UNKNOWN";
    process.stdout.write(`${canonicalJson(result)}\n`);
  } else if (selected === "mutate-effects") {
    result.effects.reservations += 1;
    result.effectsDigest = `sha256:${createHash("sha256").update(JSON.stringify(result.effects)).digest("hex")}`;
    process.stdout.write(`${canonicalJson(result)}\n`);
  } else if (selected === "mutate-lineage") {
    result.lineageDigest = `sha256:${"f".repeat(64)}`;
    process.stdout.write(`${canonicalJson(result)}\n`);
  } else {
    process.stdout.write(`${canonicalJson(result)}\n`);
  }
}
