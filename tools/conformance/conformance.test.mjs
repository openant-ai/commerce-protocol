import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { runScenario } from "../../reference/index.mjs";
import { VECTORS } from "../../vectors/hosted-phase0.mjs";
import { evaluateVector } from "./runner.mjs";

const cliPath = new URL("./cli.mjs", import.meta.url).pathname;
const mutantPath = new URL("./test-fixtures/mutant-adapter.mjs", import.meta.url).pathname;
const skipPath = new URL("./test-fixtures/skip-adapter.mjs", import.meta.url).pathname;

const runCli = (args = []) =>
  spawnSync(process.execPath, [cliPath, ...args], {
    encoding: "utf8",
    timeout: 20_000,
  });

test("the conformance report is byte-identical and contains only safe four-field records", () => {
  const first = runCli();
  const second = runCli();

  assert.equal(first.status, 0, first.stderr);
  assert.equal(second.status, 0, second.stderr);
  assert.equal(first.stdout, second.stdout);
  const records = first.stdout.trimEnd().split("\n").map(JSON.parse);
  assert.equal(records.length, VECTORS.length);
  for (const record of records) {
    assert.deepEqual(Object.keys(record).sort(), ["errorCode", "result", "stateDigest", "vectorId"]);
    assert.equal(record.result, "PASS");
    assert.match(record.stateDigest, /^sha256:[0-9a-f]{64}$/);
  }
  for (const forbidden of ["requestBody", "responseBody", "artifactBytes", "prompt"]) {
    assert.equal(first.stdout.includes(forbidden), false);
  }
});

test("an unknown vector and every skip option fail closed", () => {
  const unknown = runCli(["--vector", "HOSTED.DOES_NOT_EXIST.001"]);
  assert.notEqual(unknown.status, 0);
  assert.equal(unknown.stdout, "");
  assert.equal(unknown.stderr, "UNKNOWN_VECTOR\n");

  const skip = runCli(["--skip", "1"]);
  assert.notEqual(skip.status, 0);
  assert.equal(skip.stdout, "");
  assert.equal(skip.stderr, "USAGE_ERROR\n");
});

test("a state mutation makes the suite non-zero", () => {
  const result = runCli([
    "--adapter",
    process.execPath,
    "--adapter-arg",
    mutantPath,
    "--vector",
    "HOSTED.HAPPY.001",
  ]);

  assert.equal(result.status, 1);
  const record = JSON.parse(result.stdout);
  assert.equal(record.vectorId, "HOSTED.HAPPY.001");
  assert.equal(record.result, "FAIL");
});

test("an adapter claiming skipped vectors is invalid, not a partial pass", () => {
  const result = runCli([
    "--adapter",
    process.execPath,
    "--adapter-arg",
    skipPath,
    "--vector",
    "HOSTED.HAPPY.001",
  ]);

  assert.equal(result.status, 1);
  const record = JSON.parse(result.stdout);
  assert.equal(record.result, "FAIL");
  assert.equal(record.errorCode, "SCHEMA_INVALID");
});

test("the normalized Adapter response rejects unregistered state fields", () => {
  const vector = VECTORS[0];
  const response = runScenario({
    vectorId: vector.id,
    protocolVersion: vector.protocolVersion,
    protocolDigest: vector.protocolDigest,
    precondition: vector.precondition,
    actions: vector.action.steps,
  });
  response.finalState.output.unregistered = "opaque-but-not-allowed";

  assert.throws(() => evaluateVector(vector, response), /unknown fields/);
});

for (const [label, mutate] of [
  [
    "funding authority",
    (state) => {
      state.paymentIntent.fundingAuthority.issuer = "did:0xkey:attacker";
    },
  ],
  [
    "PaymentIntent fingerprint",
    (state) => {
      state.paymentIntent.fingerprintDigest =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    },
  ],
  [
    "Invocation identity",
    (state) => {
      state.invocation.invocationId = "inv_attacker";
      state.paymentIntent.invocationRef = "inv_attacker";
    },
  ],
  [
    "SKU lineage",
    (state) => {
      const replacement =
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
      state.listing.skuVersionDigest = replacement;
      state.invocation.skuVersionDigest = replacement;
      state.paymentIntent.skuVersionDigest = replacement;
    },
  ],
  [
    "response digest",
    (state) => {
      state.output.responseDigest =
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    },
  ],
]) {
  test(`vector expectations reject a mutated ${label}`, () => {
    const vector = VECTORS.find(({ id }) => id === "HOSTED.HAPPY.001");
    const response = runScenario({
      vectorId: vector.id,
      protocolVersion: vector.protocolVersion,
      protocolDigest: vector.protocolDigest,
      precondition: vector.precondition,
      actions: vector.action.steps,
    });
    mutate(response.finalState);

    assert.equal(evaluateVector(vector, response).result, "FAIL");
  });
}
