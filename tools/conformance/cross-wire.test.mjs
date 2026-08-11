import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  ACCEPTED_REPORT_DIGEST,
  MONEY_KERNEL_VECTOR_IDS,
  OPENANT_COMMERCIAL_LEDGER_VECTOR_IDS,
  OWNERSHIP_COUNTS,
  OWNERSHIP_MANIFEST,
  PROTOCOL_ARCHIVE_DIGEST,
  REFERENCE_HARNESS_ONLY_VECTOR_IDS,
  REFERENCE_SEMANTIC_PROOF_VECTOR_IDS,
} from "./cross-manifest.mjs";
import { canonicalJson, digestCanonical, strictJson } from "./cross-wire.mjs";

test("the 17/9/27 ownership manifest is exact, disjoint, and digest-pinned", () => {
  assert.deepEqual(OWNERSHIP_COUNTS, {
    moneyKernelProjection: 17,
    referenceHarnessOnly: 9,
    openAntCommercialLedger: 27,
  });
  const all = [
    ...MONEY_KERNEL_VECTOR_IDS,
    ...REFERENCE_HARNESS_ONLY_VECTOR_IDS,
    ...OPENANT_COMMERCIAL_LEDGER_VECTOR_IDS,
  ];
  assert.equal(all.length, 53);
  assert.equal(new Set(all).size, 53);
  assert.ok(REFERENCE_SEMANTIC_PROOF_VECTOR_IDS.every((id) =>
    REFERENCE_HARNESS_ONLY_VECTOR_IDS.includes(id)));
  assert.equal(
    digestCanonical(OWNERSHIP_MANIFEST),
    "sha256:18f8f80b0e2fbfec860c6306a10a5944c8195419fd2d36a3f57060287ceca36d",
  );
  assert.equal(PROTOCOL_ARCHIVE_DIGEST, "sha256:7a4feabe1cdc55804f4333c13f4550a39ce4570c1ce754e1b30c2d9c5e23b797");
  assert.equal(ACCEPTED_REPORT_DIGEST, "sha256:c11ed834692bae1f99c3ea65b28dd18d7dea04b9a8275bcba0161bfe17c779cb");
});

test("strict wire JSON accepts only RFC JSON whitespace and rejects ambiguity", () => {
  const canonical = '{"a":[true,false,null],"b":1,"c":"value"}';
  assert.equal(canonicalJson(strictJson(canonical)), canonical);
  assert.deepEqual(Object.keys(strictJson(" \t\r\n" + canonical)), ["a", "b", "c"]);
  for (const invalid of [
    '\u00a0{"a":1}',
    '\u2028{"a":1}',
    '{"a":1,"a":2}',
    '{"nested":{"constructor":1}}',
    '{"a":1}{}',
    '{"a":01}',
    '{"a":1e999}',
  ]) assert.throws(() => strictJson(invalid), /invalid JSON/);
});

test("the production CLI exposes no vector, skip, or arbitrary argv option", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const cli = resolve(here, "cross-cli.mjs");
  for (const args of [
    [],
    ["--skip", "1"],
    ["--vector", "HOSTED.HAPPY.001"],
    ["--adapter-arg", "/tmp/fixture"],
  ]) {
    const result = spawnSync(process.execPath, [cli, ...args], { encoding: "utf8", timeout: 5_000 });
    assert.equal(result.status, 2);
    assert.equal(result.stdout, "");
    assert.equal(result.stderr, "USAGE_ERROR\n");
  }
});
