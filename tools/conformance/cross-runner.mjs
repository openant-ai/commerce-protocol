import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ACCEPTED_REPORT_DIGEST,
  CROSS_SCHEMA_VERSION,
  MONEY_KERNEL_VECTOR_IDS,
  MONEY_PROJECTION_BASELINE_DIGEST,
  OPENANT_COMMERCIAL_LEDGER_VECTOR_IDS,
  OX003_CRYPTO_PROOF_DIGEST,
  OWNERSHIP_COUNTS,
  OWNERSHIP_MANIFEST,
  PINNED_ARTIFACTS,
  PROTOCOL_ARCHIVE_DIGEST,
  PROTOCOL_ARCHIVE_INTEGRITY,
  PROTOCOL_DIGEST,
  PROTOCOL_VERSION,
  REFERENCE_HARNESS_ONLY_VECTOR_IDS,
  REFERENCE_SEMANTIC_PROOF_VECTOR_IDS,
} from "./cross-manifest.mjs";
import { assertExactKeys, canonicalJson, digestCanonical, strictJson } from "./cross-wire.mjs";

const MAX_OUTPUT_BYTES = 1024 * 1024;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const EFFECT_KEYS = [
  "reservations", "releases", "authorizations", "settlementBroadcasts",
  "settlements", "budgetConsumptions", "reconciliations", "unknownObservations",
];
const RESPONSE_KEYS = [
  "schemaVersion", "implementation", "implementationVersion", "protocolVersion",
  "protocolDigest", "vectorId", "result", "paymentIntentState", "errorCode",
  "effects", "effectsDigest", "lineageDigest",
];
const BASELINE_KEYS = ["vectorId", "result", "stateDigest", "errorCode"];
const PUBLIC_ERROR_CODES = new Set([
  "SCHEMA_INVALID", "UNSUPPORTED_PROTOCOL_VERSION", "CHALLENGE_INVALID", "CHALLENGE_EXPIRED",
  "LISTING_REVOKED", "MANDATE_NOT_FOUND", "MANDATE_SCOPE_DENIED", "APPROVAL_REQUIRED",
  "BUDGET_EXCEEDED", "RESERVATION_CONFLICT", "IDEMPOTENCY_FINGERPRINT_CONFLICT",
  "AUTHORIZATION_FAILED", "AUTHORIZATION_UNKNOWN", "PAYMENT_PATH_UNAVAILABLE",
  "SETTLEMENT_UNKNOWN", "SETTLEMENT_REJECTED", "OUTPUT_NOT_CHARGEABLE",
  "OUTPUT_NOT_STAGED", "PROOF_INCOMPLETE", "PROOF_BINDING_MISMATCH",
  "TENANT_CONTEXT_MISMATCH", "ILLEGAL_STATE_TRANSITION",
]);
const PROJECTION_KEYS = [
  "vectorId", "result", "paymentIntentState", "errorCode", "effects",
  "effectsDigest", "lineageDigest",
];
const FIXED_ENV = Object.freeze({
  LANG: "C",
  LC_ALL: "C",
  TZ: "UTC",
  PATH: `${dirname(process.execPath)}:/usr/bin:/bin`,
});
const RUNNER_FILES = ["cross-cli.mjs", "cross-manifest.mjs", "cross-runner.mjs", "cross-wire.mjs"];

export class CrossConformanceError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function fail(code) {
  throw new CrossConformanceError(code);
}

async function regularAbsoluteFile(path, code) {
  if (!isAbsolute(path)) fail(code);
  let metadata;
  try { metadata = await lstat(path); } catch { fail(code); }
  if (!metadata.isFile() || metadata.isSymbolicLink()) fail(code);
}

async function hashFile(path, algorithm, encoding = "hex") {
  const hash = createHash(algorithm);
  await new Promise((resolve, reject) => {
    const stream = createReadStream(path);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", resolve);
  });
  return hash.digest(encoding);
}

function hashBytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function spawnCaptured(executable, args, { input = null, cwd, timeoutMs, env = FIXED_ENV }) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      cwd,
      env,
      detached: process.platform !== "win32",
      stdio: ["pipe", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    let bytes = 0;
    let timedOut = false;
    let oversized = false;
    let spawnFailure = false;
    const terminate = () => {
      try {
        if (process.platform !== "win32" && child.pid !== undefined) process.kill(-child.pid, "SIGKILL");
        else child.kill("SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
    };
    const timer = setTimeout(() => {
      timedOut = true;
      terminate();
    }, timeoutMs);
    child.on("error", () => {
      spawnFailure = true;
    });
    const capture = (target) => (chunk) => {
      bytes += chunk.length;
      if (bytes > MAX_OUTPUT_BYTES) {
        oversized = true;
        terminate();
        return;
      }
      if (target === "stdout") stdout.push(chunk);
      else stderr.push(chunk);
    };
    child.stdout.on("data", capture("stdout"));
    child.stderr.on("data", capture("stderr"));
    child.stdin.on("error", () => {});
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (timedOut) reject(new CrossConformanceError("CHILD_TIMEOUT"));
      else if (oversized) reject(new CrossConformanceError("CHILD_OUTPUT_LIMIT"));
      else if (spawnFailure) reject(new CrossConformanceError("CHILD_SPAWN_FAILED"));
      else if (signal !== null) reject(new CrossConformanceError("CHILD_SIGNAL"));
      else if (code !== 0) reject(new CrossConformanceError("CHILD_NONZERO"));
      else {
        try {
          const decoder = new TextDecoder("utf-8", { fatal: true });
          resolve({
            stdout: decoder.decode(Buffer.concat(stdout)),
            stderr: decoder.decode(Buffer.concat(stderr)),
          });
        } catch {
          reject(new CrossConformanceError("CHILD_OUTPUT_ENCODING"));
        }
      }
    });
    child.stdin.end(input ?? "");
  });
}

function assertDigest(value) {
  if (typeof value !== "string" || !DIGEST.test(value)) fail("ADAPTER_PROTOCOL_INVALID");
}

function validateEffects(value) {
  try { assertExactKeys(value, EFFECT_KEYS); } catch { fail("ADAPTER_PROTOCOL_INVALID"); }
  for (const key of EFFECT_KEYS) {
    if (!Number.isSafeInteger(value[key]) || value[key] < 0) fail("ADAPTER_PROTOCOL_INVALID");
  }
}

function effectsDigest(effects) {
  const ordered = Object.fromEntries(EFFECT_KEYS.map((key) => [key, effects[key]]));
  return hashBytes(JSON.stringify(ordered));
}

function validateOwnership(vectorIds) {
  const groups = [
    MONEY_KERNEL_VECTOR_IDS,
    REFERENCE_HARNESS_ONLY_VECTOR_IDS,
    OPENANT_COMMERCIAL_LEDGER_VECTOR_IDS,
  ];
  if (groups[0].length !== 17 || groups[1].length !== 9 || groups[2].length !== 27) {
    fail("OWNERSHIP_MANIFEST_INVALID");
  }
  const flattened = groups.flat();
  if (new Set(flattened).size !== 53 || new Set(vectorIds).size !== 53) {
    fail("OWNERSHIP_MANIFEST_INVALID");
  }
  if (canonicalJson([...flattened].sort()) !== canonicalJson([...vectorIds].sort())) {
    fail("OWNERSHIP_MANIFEST_INVALID");
  }
  for (const group of groups) {
    const acceptedOrder = vectorIds.filter((id) => group.includes(id));
    if (canonicalJson(acceptedOrder) !== canonicalJson(group)) fail("OWNERSHIP_MANIFEST_INVALID");
  }
}

function parseSingleLine(source, code) {
  if (!source.endsWith("\n") || source.slice(0, -1).includes("\n") || source.includes("\r")) {
    fail(code);
  }
  const line = source.slice(0, -1);
  let parsed;
  try { parsed = strictJson(line); } catch { fail(code); }
  if (canonicalJson(parsed) !== line) fail(code);
  return parsed;
}

async function verifyProtocolArchive(path) {
  await regularAbsoluteFile(path, "PROTOCOL_ARCHIVE_INVALID");
  const sha256 = `sha256:${await hashFile(path, "sha256")}`;
  const integrity = `sha512-${await hashFile(path, "sha512", "base64")}`;
  if (sha256 !== PROTOCOL_ARCHIVE_DIGEST || integrity !== PROTOCOL_ARCHIVE_INTEGRITY) {
    fail("PROTOCOL_ARCHIVE_INVALID");
  }
  const temporary = await mkdtemp(join(tmpdir(), "openant-commerce-cross-"));
  try {
    let extracted;
    try {
      extracted = await spawnCaptured("/usr/bin/tar", ["-xzf", path, "-C", temporary], {
        cwd: temporary,
        timeoutMs: 10_000,
      });
    } catch { fail("PROTOCOL_ARCHIVE_INVALID"); }
    if (extracted.stdout !== "" || extracted.stderr !== "") fail("PROTOCOL_ARCHIVE_INVALID");
    const root = join(temporary, "package");
    for (const [relative, expected] of Object.entries(PINNED_ARTIFACTS)) {
      const artifact = join(root, relative);
      await regularAbsoluteFile(artifact, "PROTOCOL_ARCHIVE_INVALID");
      if (`sha256:${await hashFile(artifact, "sha256")}` !== expected) fail("PROTOCOL_ARCHIVE_INVALID");
    }
    let packageDocument;
    try { packageDocument = strictJson(await readFile(join(root, "package.json"), "utf8")); }
    catch { fail("PROTOCOL_ARCHIVE_INVALID"); }
    if (packageDocument.version !== PROTOCOL_VERSION) fail("PROTOCOL_ARCHIVE_INVALID");

    let baseline;
    try {
      baseline = await spawnCaptured(process.execPath, [join(root, "tools/conformance/cli.mjs")], {
        cwd: root,
        timeoutMs: 20_000,
      });
    } catch { fail("REFERENCE_BASELINE_INVALID"); }
    if (baseline.stderr !== "" || hashBytes(baseline.stdout) !== ACCEPTED_REPORT_DIGEST) {
      fail("REFERENCE_BASELINE_INVALID");
    }
    if (!baseline.stdout.endsWith("\n")) fail("REFERENCE_BASELINE_INVALID");
    const lines = baseline.stdout.slice(0, -1).split("\n");
    if (lines.length !== 53) fail("REFERENCE_BASELINE_INVALID");
    const records = lines.map((line) => {
      let record;
      try { record = strictJson(line); assertExactKeys(record, BASELINE_KEYS); }
      catch { fail("REFERENCE_BASELINE_INVALID"); }
      if (record.result !== "PASS" || typeof record.vectorId !== "string") {
        fail("REFERENCE_BASELINE_INVALID");
      }
      assertDigest(record.stateDigest);
      return record;
    });
    const vectorIds = records.map(({ vectorId }) => vectorId);
    validateOwnership(vectorIds);
    for (const id of REFERENCE_SEMANTIC_PROOF_VECTOR_IDS) {
      const record = records.find(({ vectorId }) => vectorId === id);
      if (record?.result !== "PASS" || record.errorCode !== "PROOF_BINDING_MISMATCH") {
        fail("REFERENCE_SEMANTIC_PROOF_INVALID");
      }
    }
    return { vectorIds, records: new Map(records.map((record) => [record.vectorId, record])) };
  } catch (error) {
    if (error instanceof CrossConformanceError) throw error;
    fail("PROTOCOL_ARCHIVE_INVALID");
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

async function loadMoneyProjectionBaseline(path) {
  await regularAbsoluteFile(path, "MONEY_PROJECTION_BASELINE_INVALID");
  if (`sha256:${await hashFile(path, "sha256")}` !== MONEY_PROJECTION_BASELINE_DIGEST) {
    fail("MONEY_PROJECTION_BASELINE_INVALID");
  }
  const source = await readFile(path, "utf8");
  if (Buffer.byteLength(source) > MAX_OUTPUT_BYTES || !source.endsWith("\n")) {
    fail("MONEY_PROJECTION_BASELINE_INVALID");
  }
  const lines = source.slice(0, -1).split("\n");
  if (lines.length !== 17) fail("MONEY_PROJECTION_BASELINE_INVALID");
  const records = lines.map((line, index) => {
    let record;
    try { record = strictJson(line); assertExactKeys(record, PROJECTION_KEYS); }
    catch { fail("MONEY_PROJECTION_BASELINE_INVALID"); }
    if (record.vectorId !== MONEY_KERNEL_VECTOR_IDS[index] || record.result !== "PASS") {
      fail("MONEY_PROJECTION_BASELINE_INVALID");
    }
    validateEffects(record.effects);
    assertDigest(record.effectsDigest);
    assertDigest(record.lineageDigest);
    if (effectsDigest(record.effects) !== record.effectsDigest) {
      fail("MONEY_PROJECTION_BASELINE_INVALID");
    }
    return record;
  });
  return new Map(records.map((record) => [record.vectorId, record]));
}

async function verifyCryptoProof(path) {
  await regularAbsoluteFile(path, "OX003_CRYPTO_PROOF_INVALID");
  if (`sha256:${await hashFile(path, "sha256")}` !== OX003_CRYPTO_PROOF_DIGEST) {
    fail("OX003_CRYPTO_PROOF_INVALID");
  }
  const source = await readFile(path, "utf8");
  if (Buffer.byteLength(source) > MAX_OUTPUT_BYTES || !source.endsWith("\n")) {
    fail("OX003_CRYPTO_PROOF_INVALID");
  }
  let records;
  try { records = strictJson(source.slice(0, -1)); } catch { fail("OX003_CRYPTO_PROOF_INVALID"); }
  if (!Array.isArray(records) || records.length !== 22) fail("OX003_CRYPTO_PROOF_INVALID");
  for (const record of records) {
    try { assertExactKeys(record, ["id", "valid", "claimsHash", "reason"]); }
    catch { fail("OX003_CRYPTO_PROOF_INVALID"); }
    if (typeof record.id !== "string" || typeof record.valid !== "boolean" ||
        (record.claimsHash !== null && !DIGEST.test(record.claimsHash)) ||
        typeof record.reason !== "string") fail("OX003_CRYPTO_PROOF_INVALID");
  }
}

async function verifySourceBundle(path) {
  await regularAbsoluteFile(path, "ADAPTER_COORDINATE_INVALID");
  const archive = await readFile(path);
  if (archive.length === 0 || archive.length > 16 * 1024 * 1024 || archive.length % 512 !== 0) {
    fail("ADAPTER_COORDINATE_INVALID");
  }
  const names = [];
  let offset = 0;
  let zeroBlocks = 0;
  const text = (buffer) => {
    const end = buffer.indexOf(0);
    const slice = end === -1 ? buffer : buffer.subarray(0, end);
    try { return new TextDecoder("utf-8", { fatal: true }).decode(slice); }
    catch { fail("ADAPTER_COORDINATE_INVALID"); }
  };
  const octal = (buffer) => {
    const value = text(buffer).trim();
    if (!/^[0-7]+$/.test(value)) fail("ADAPTER_COORDINATE_INVALID");
    return Number.parseInt(value, 8);
  };
  while (offset < archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      zeroBlocks += 1;
      offset += 512;
      continue;
    }
    if (zeroBlocks !== 0) fail("ADAPTER_COORDINATE_INVALID");
    const name = text(header.subarray(0, 100));
    const prefix = text(header.subarray(345, 500));
    const fullName = prefix === "" ? name : `${prefix}/${name}`;
    const components = fullName.split("/");
    if (fullName === "" || fullName.startsWith("/") || fullName.includes("\\") ||
        components.some((part) => part === "" || part === "." || part === "..") ||
        names.includes(fullName)) fail("ADAPTER_COORDINATE_INVALID");
    const type = header[156];
    if (type !== 0 && type !== 0x30) fail("ADAPTER_COORDINATE_INVALID");
    const checksumHeader = Buffer.from(header);
    checksumHeader.fill(0x20, 148, 156);
    const computedChecksum = checksumHeader.reduce((sum, byte) => sum + byte, 0);
    if (text(header.subarray(257, 263)) !== "ustar" ||
        text(header.subarray(263, 265)) !== "00" ||
        octal(header.subarray(148, 156)) !== computedChecksum) {
      fail("ADAPTER_COORDINATE_INVALID");
    }
    if (octal(header.subarray(100, 108)) !== 0o644 ||
        octal(header.subarray(108, 116)) !== 0 ||
        octal(header.subarray(116, 124)) !== 0 ||
        octal(header.subarray(136, 148)) !== 0 ||
        text(header.subarray(265, 297)) !== "" ||
        text(header.subarray(297, 329)) !== "") fail("ADAPTER_COORDINATE_INVALID");
    const size = octal(header.subarray(124, 136));
    names.push(fullName);
    const contentEnd = offset + 512 + size;
    const paddedEnd = offset + 512 + Math.ceil(size / 512) * 512;
    if (!archive.subarray(contentEnd, paddedEnd).every((byte) => byte === 0)) {
      fail("ADAPTER_COORDINATE_INVALID");
    }
    offset = paddedEnd;
    if (offset > archive.length) fail("ADAPTER_COORDINATE_INVALID");
  }
  if (zeroBlocks < 2 || canonicalJson(names) !== canonicalJson([...names].sort())) {
    fail("ADAPTER_COORDINATE_INVALID");
  }
  return `sha256:${createHash("sha256").update(archive).digest("hex")}`;
}

function validateAdapterResponse(vectorId, response) {
  try { assertExactKeys(response, RESPONSE_KEYS); } catch { fail("ADAPTER_PROTOCOL_INVALID"); }
  if (response.schemaVersion !== CROSS_SCHEMA_VERSION ||
      response.implementation !== "0xkey-commerce-authorization" ||
      response.implementationVersion !== "0.1.0" ||
      response.protocolVersion !== PROTOCOL_VERSION ||
      response.protocolDigest !== PROTOCOL_DIGEST ||
      response.vectorId !== vectorId || response.result !== "PASS") {
    fail("ADAPTER_PROTOCOL_INVALID");
  }
  if (response.paymentIntentState !== null && typeof response.paymentIntentState !== "string") {
    fail("ADAPTER_PROTOCOL_INVALID");
  }
  if (response.errorCode !== null &&
      (typeof response.errorCode !== "string" || !PUBLIC_ERROR_CODES.has(response.errorCode))) {
    fail("ADAPTER_PROTOCOL_INVALID");
  }
  validateEffects(response.effects);
  assertDigest(response.effectsDigest);
  assertDigest(response.lineageDigest);
  if (effectsDigest(response.effects) !== response.effectsDigest) fail("ADAPTER_PROTOCOL_INVALID");
  return response;
}

async function invokeAdapter(vectorId, adapter, timeoutMs) {
  const temporary = await mkdtemp(join(tmpdir(), "openant-commerce-adapter-"));
  try {
    const request = {
      schemaVersion: CROSS_SCHEMA_VERSION,
      command: "runVector",
      protocolVersion: PROTOCOL_VERSION,
      protocolDigest: PROTOCOL_DIGEST,
      vectorId,
    };
    let processResult;
    try {
      processResult = await spawnCaptured(adapter.executable, adapter.args, {
        input: `${canonicalJson(request)}\n`,
        cwd: temporary,
        timeoutMs,
      });
    } catch (error) {
      const mapping = {
        CHILD_TIMEOUT: "ADAPTER_TIMEOUT",
        CHILD_OUTPUT_LIMIT: "ADAPTER_OUTPUT_LIMIT",
        CHILD_SPAWN_FAILED: "ADAPTER_SPAWN_FAILED",
        CHILD_SIGNAL: "ADAPTER_SIGNAL",
        CHILD_NONZERO: "ADAPTER_NONZERO",
        CHILD_OUTPUT_ENCODING: "ADAPTER_PROTOCOL_INVALID",
      };
      fail(mapping[error.code] ?? "ADAPTER_PROTOCOL_INVALID");
    }
    if (processResult.stderr !== "") fail("ADAPTER_STDERR");
    const response = parseSingleLine(processResult.stdout, "ADAPTER_PROTOCOL_INVALID");
    return validateAdapterResponse(vectorId, response);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

function projectionOf(record) {
  return {
    paymentIntentState: record.paymentIntentState,
    errorCode: record.errorCode,
    effects: record.effects,
    effectsDigest: record.effectsDigest,
    lineageDigest: record.lineageDigest,
  };
}

function differences(actual, expected) {
  return ["paymentIntentState", "errorCode", "effects", "effectsDigest", "lineageDigest"]
    .filter((key) => canonicalJson(actual[key]) !== canonicalJson(expected[key]));
}

function reportBase(coordinates, vectorId, openAntRecord) {
  return {
    vectorId,
    ownership: "MONEY_KERNEL_PROJECTION",
    ownershipCounts: OWNERSHIP_COUNTS,
    implementation: "0xkey-commerce-authorization",
    implementationVersion: "0.1.0",
    protocolVersion: PROTOCOL_VERSION,
    protocolDigest: PROTOCOL_DIGEST,
    protocolArchiveDigest: PROTOCOL_ARCHIVE_DIGEST,
    baselineReportDigest: ACCEPTED_REPORT_DIGEST,
    moneyProjectionBaselineDigest: MONEY_PROJECTION_BASELINE_DIGEST,
    referenceSemanticProofDigest: ACCEPTED_REPORT_DIGEST,
    ox003CryptoProofDigest: OX003_CRYPTO_PROOF_DIGEST,
    ownershipManifestDigest: digestCanonical(OWNERSHIP_MANIFEST),
    crossRunnerSourceDigest: coordinates.crossRunnerSourceDigest,
    adapterSourceDigest: coordinates.adapterSourceDigest,
    adapterBinaryDigest: coordinates.adapterBinaryDigest,
    openAntStateDigest: openAntRecord.stateDigest,
  };
}

async function runnerSourceDigest() {
  const root = dirname(fileURLToPath(import.meta.url));
  const entries = [];
  for (const filename of RUNNER_FILES) {
    entries.push([filename, `sha256:${await hashFile(join(root, filename), "sha256")}`]);
  }
  return digestCanonical(entries);
}

export async function runCrossConformance(options) {
  const reference = await verifyProtocolArchive(options.protocolArchive);
  const expected = await loadMoneyProjectionBaseline(options.moneyProjectionBaseline);
  await verifyCryptoProof(options.cryptoProofReport);
  const adapter = typeof options.adapter === "string"
    ? { executable: options.adapter, args: [], coordinatePath: options.adapter }
    : options.adapter;
  if (adapter === null || typeof adapter !== "object" || !Array.isArray(adapter.args)) {
    fail("ADAPTER_COORDINATE_INVALID");
  }
  await regularAbsoluteFile(adapter.executable, "ADAPTER_COORDINATE_INVALID");
  await regularAbsoluteFile(adapter.coordinatePath, "ADAPTER_COORDINATE_INVALID");
  for (const argument of adapter.args) await regularAbsoluteFile(argument, "ADAPTER_COORDINATE_INVALID");
  const adapterSourceDigest = await verifySourceBundle(options.adapterSourceBundle);
  for (const vectorId of MONEY_KERNEL_VECTOR_IDS) {
    const openAntRecord = reference.records.get(vectorId);
    if (openAntRecord?.result !== "PASS" ||
        openAntRecord.errorCode !== expected.get(vectorId)?.errorCode) {
      fail("CROSS_BASELINE_MISMATCH");
    }
  }
  const coordinates = {
    adapterBinaryDigest: `sha256:${await hashFile(adapter.coordinatePath, "sha256")}`,
    adapterSourceDigest,
    crossRunnerSourceDigest: await runnerSourceDigest(),
  };
  const reports = [];
  for (const vectorId of MONEY_KERNEL_VECTOR_IDS) {
    const base = reportBase(coordinates, vectorId, reference.records.get(vectorId));
    try {
      const actual = await invokeAdapter(vectorId, adapter, options.timeoutMs);
      const projection = projectionOf(actual);
      const mismatchFields = differences(projection, expected.get(vectorId));
      reports.push({
        ...base,
        result: mismatchFields.length === 0 ? "PASS" : "FAIL",
        harnessError: null,
        mismatchFields,
        paymentIntentState: projection.paymentIntentState,
        errorCode: projection.errorCode,
        effectsDigest: projection.effectsDigest,
        lineageDigest: projection.lineageDigest,
        projectionDigest: digestCanonical(projection),
      });
    } catch (error) {
      const harnessError = error instanceof CrossConformanceError
        ? error.code
        : "ADAPTER_PROTOCOL_INVALID";
      reports.push({
        ...base,
        result: "FAIL",
        harnessError,
        mismatchFields: [],
        paymentIntentState: null,
        errorCode: null,
        effectsDigest: null,
        lineageDigest: null,
        projectionDigest: digestCanonical({ harnessError, vectorId }),
      });
    }
  }
  return reports;
}
