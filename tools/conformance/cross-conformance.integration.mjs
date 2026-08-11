import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import test, { after } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import { runCrossConformance } from "./cross-runner.mjs";
import { canonicalJson } from "./cross-wire.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const workspace = process.env.OPENANT_COMMERCE_TEST_WORKSPACE;
if (workspace === undefined) {
  throw new Error("OPENANT_COMMERCE_TEST_WORKSPACE is required for cross integration tests");
}
const rc = resolve(workspace, "0xkey/.scratch/agent-commerce/artifacts/protocol-draft4/openant-commerce-protocol-workspace-0.1.0-draft.4.tgz");
const projectionBaseline = resolve(workspace, "0xkey/repos/services/services/coordinator/src/application/services/commerce_authorization/ox002-reference-report.ndjson");
const cryptoProof = resolve(workspace, "0xkey/repos/services/crates/commerce-verifier/artifacts/conformance-report.jsonl");
const fixtureDirectory = mkdtempSync(resolve(tmpdir(), "openant-cross-test-"));
after(() => rmSync(fixtureDirectory, { recursive: true, force: true }));
const sourceBundle = resolve(fixtureDirectory, "adapter-source.tar");
const adapterModule = resolve(fixtureDirectory, "valid-adapter.mjs");
writeFileSync(adapterModule, `import { runFixture } from ${JSON.stringify(pathToFileURL(resolve(here, "cross-test-fixtures/adapter-behaviors.mjs")).href)};\nawait runFixture("valid");\n`);

function sourceTar() {
  const content = readFileSync(resolve(here, "cross-test-fixtures/adapter-behaviors.mjs"));
  const header = Buffer.alloc(512);
  const put = (value, offset, length) => header.write(value, offset, length, "utf8");
  const octal = (value, offset, length) => put(value.toString(8).padStart(length - 1, "0") + "\0", offset, length);
  put("tools/conformance/cross-test-fixtures/adapter-behaviors.mjs", 0, 100);
  octal(0o644, 100, 8);
  octal(0, 108, 8);
  octal(0, 116, 8);
  octal(content.length, 124, 12);
  octal(0, 136, 12);
  header.fill(0x20, 148, 156);
  header[156] = 0x30;
  put("ustar\0", 257, 6);
  put("00", 263, 2);
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  put(checksum.toString(8).padStart(6, "0") + "\0 ", 148, 8);
  return Buffer.concat([
    header,
    content,
    Buffer.alloc((512 - content.length % 512) % 512),
    Buffer.alloc(1024),
  ]);
}
writeFileSync(sourceBundle, sourceTar());

const adapters = new Map();
function adapterFor(mode) {
  if (adapters.has(mode)) return adapters.get(mode);
  const filename = resolve(fixtureDirectory, `adapter-${adapters.size}.mjs`);
  writeFileSync(filename, `import { runFixture } from ${JSON.stringify(pathToFileURL(resolve(here, "cross-test-fixtures/adapter-behaviors.mjs")).href)};\nawait runFixture(${JSON.stringify(mode)});\n`);
  adapters.set(mode, filename);
  return filename;
}

function run(adapterPath = adapterModule, timeoutMs = 5_000) {
  return runCrossConformance({
    protocolArchive: rc,
    moneyProjectionBaseline: projectionBaseline,
    cryptoProofReport: cryptoProof,
    adapterSourceBundle: sourceBundle,
    adapter: {
      executable: process.execPath,
      args: [adapterPath],
      coordinatePath: adapterPath,
    },
    timeoutMs,
  });
}

test("the cross runner verifies the immutable baseline and all 17 money projections", async () => {
  const firstRecords = await run();
  const secondRecords = await run();
  const first = `${firstRecords.map(canonicalJson).join("\n")}\n`;
  const second = `${secondRecords.map(canonicalJson).join("\n")}\n`;

  assert.equal(first, second);
  const records = first.trimEnd().split("\n").map(JSON.parse);
  assert.equal(records.length, 17);
  const reportKeys = [
    "adapterBinaryDigest", "adapterSourceDigest", "baselineReportDigest",
    "crossRunnerSourceDigest", "effectsDigest", "errorCode", "harnessError",
    "implementation", "implementationVersion", "lineageDigest", "mismatchFields",
    "moneyProjectionBaselineDigest", "openAntStateDigest", "ownership", "ownershipCounts",
    "ownershipManifestDigest", "ox003CryptoProofDigest", "paymentIntentState",
    "projectionDigest", "protocolArchiveDigest", "protocolDigest", "protocolVersion",
    "referenceSemanticProofDigest", "result", "vectorId",
  ].sort();
  for (const record of records) {
    assert.deepEqual(Object.keys(record).sort(), reportKeys);
    assert.equal(record.ownership, "MONEY_KERNEL_PROJECTION");
    assert.equal(record.result, "PASS");
    assert.equal(record.harnessError, null);
    assert.deepEqual(record.mismatchFields, []);
    assert.deepEqual(record.ownershipCounts, {
      moneyKernelProjection: 17,
      referenceHarnessOnly: 9,
      openAntCommercialLedger: 27,
    });
    assert.equal(record.protocolArchiveDigest, "sha256:7a4feabe1cdc55804f4333c13f4550a39ce4570c1ce754e1b30c2d9c5e23b797");
    assert.equal(record.baselineReportDigest, "sha256:c11ed834692bae1f99c3ea65b28dd18d7dea04b9a8275bcba0161bfe17c779cb");
    assert.equal(record.moneyProjectionBaselineDigest, "sha256:124c62b05fa7114122d8c5ac51b4ce0ad1c2db243704cd4b8347e7435fb31689");
    assert.equal(record.ox003CryptoProofDigest, "sha256:f17ff6db79340a323dc640aacceb0c251b9c03947cd605c4796e708239ef0b40");
    assert.match(record.adapterSourceDigest, /^sha256:[0-9a-f]{64}$/);
    assert.match(record.adapterBinaryDigest, /^sha256:[0-9a-f]{64}$/);
    assert.match(record.projectionDigest, /^sha256:[0-9a-f]{64}$/);
  }
  for (const forbidden of [
    "requestBody", "responseBody", "artifactBytes", "toolArguments", "privateKey",
    "credential", "/Users/", "repos/services",
  ]) assert.equal(first.includes(forbidden), false);
});

test("wire-level ambiguity and private fields fail closed without error remapping", async () => {
  const records = await run(adapterFor("wire-attacks"));
  const expected = [
    "ADAPTER_PROTOCOL_INVALID",
    "ADAPTER_PROTOCOL_INVALID",
    "ADAPTER_PROTOCOL_INVALID",
    "ADAPTER_PROTOCOL_INVALID",
    "ADAPTER_PROTOCOL_INVALID",
    "ADAPTER_PROTOCOL_INVALID",
    "ADAPTER_PROTOCOL_INVALID",
    "ADAPTER_PROTOCOL_INVALID",
  ];
  assert.deepEqual(records.slice(0, expected.length).map(({ harnessError }) => harnessError), expected);
  assert.ok(records.slice(0, expected.length).every(({ result, errorCode }) =>
    result === "FAIL" && errorCode === null));
  assert.ok(records.slice(expected.length).every(({ result }) => result === "PASS"));
});

test("process framing, termination, timeout, and output limits fail closed", async () => {
  const descendantPidFile = resolve(fixtureDirectory, "timeout-descendant.pid");
  const records = await run(adapterFor(`process-attacks:${descendantPidFile}`), 500);
  const expected = [
    "ADAPTER_PROTOCOL_INVALID",
    "ADAPTER_PROTOCOL_INVALID",
    "ADAPTER_STDERR",
    "ADAPTER_NONZERO",
    "ADAPTER_SIGNAL",
    "ADAPTER_TIMEOUT",
    "ADAPTER_OUTPUT_LIMIT",
    "ADAPTER_PROTOCOL_INVALID",
    "ADAPTER_PROTOCOL_INVALID",
  ];
  assert.deepEqual(records.slice(0, expected.length).map(({ harnessError }) => harnessError), expected);
  assert.ok(records.slice(0, expected.length).every(({ result, errorCode }) =>
    result === "FAIL" && errorCode === null));
  assert.ok(records.slice(expected.length).every(({ result }) => result === "PASS"));
  const descendantPid = Number(readFileSync(descendantPidFile, "utf8"));
  assert.ok(Number.isSafeInteger(descendantPid) && descendantPid > 1);
  let alive = true;
  for (let attempt = 0; attempt < 50 && alive; attempt += 1) {
    try { process.kill(descendantPid, 0); }
    catch (error) {
      if (error.code === "ESRCH") alive = false;
      else throw error;
    }
    if (alive) await new Promise((resolveDelay) => setTimeout(resolveDelay, 20));
  }
  assert.equal(alive, false, `descendant process ${descendantPid} survived timeout cleanup`);
});

test("valid projection mutations produce deterministic minimal diffs", async () => {
  const first = await run(adapterFor("projection-mutations"));
  const second = await run(adapterFor("projection-mutations"));
  assert.equal(first.map(canonicalJson).join("\n"), second.map(canonicalJson).join("\n"));
  assert.deepEqual(first.slice(0, 4).map(({ harnessError, mismatchFields, result }) => ({
    harnessError,
    mismatchFields,
    result,
  })), [
    { harnessError: null, mismatchFields: ["paymentIntentState"], result: "FAIL" },
    { harnessError: null, mismatchFields: ["errorCode"], result: "FAIL" },
    { harnessError: null, mismatchFields: ["effects", "effectsDigest"], result: "FAIL" },
    { harnessError: null, mismatchFields: ["lineageDigest"], result: "FAIL" },
  ]);
  assert.ok(first.slice(4).every(({ result }) => result === "PASS"));
});

test("a source bundle with corrupt USTAR identity or checksum is rejected before execution", async () => {
  for (const [name, mutate] of [
    ["magic", (archive) => { archive[257] ^= 1; }],
    ["checksum", (archive) => { archive[148] = archive[148] === 0x30 ? 0x31 : 0x30; }],
  ]) {
    const archive = sourceTar();
    mutate(archive);
    const filename = resolve(fixtureDirectory, `corrupt-${name}.tar`);
    writeFileSync(filename, archive);
    await assert.rejects(
      runCrossConformance({
        protocolArchive: rc,
        moneyProjectionBaseline: projectionBaseline,
        cryptoProofReport: cryptoProof,
        adapterSourceBundle: filename,
        adapter: { executable: process.execPath, args: [adapterModule], coordinatePath: adapterModule },
        timeoutMs: 500,
      }),
      ({ code }) => code === "ADAPTER_COORDINATE_INVALID",
    );
  }
});
