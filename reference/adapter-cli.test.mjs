import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { VECTORS } from "../vectors/hosted-phase0.mjs";

const adapterPath = new URL("./adapter-cli.mjs", import.meta.url);

const invoke = (scenario) =>
  spawnSync(process.execPath, [adapterPath.pathname], {
    encoding: "utf8",
    input: `${JSON.stringify({ command: "runVector", scenario })}\n`,
  });

test("the reference adapter is a one-shot black-box process", () => {
  const vector = VECTORS[0];
  const result = invoke({
    vectorId: vector.id,
    protocolVersion: vector.protocolVersion,
    protocolDigest: vector.protocolDigest,
    precondition: vector.precondition,
    actions: vector.action.steps,
  });

  assert.equal(result.status, 0, result.stderr);
  const response = JSON.parse(result.stdout);
  assert.deepEqual(Object.keys(response).sort(), ["finalState", "observations", "vectorId"]);
  assert.equal(response.vectorId, vector.id);
  assert.equal(response.finalState.capabilities.realMoney, false);
});

test("the adapter rejects raw business content before execution", () => {
  const vector = VECTORS[0];
  const scenario = {
    vectorId: vector.id,
    protocolVersion: vector.protocolVersion,
    protocolDigest: vector.protocolDigest,
    precondition: vector.precondition,
    actions: [{ ...vector.action.steps[0], requestBody: "must never enter reference flow" }],
  };
  const result = invoke(scenario);

  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "SCHEMA_INVALID\n");
});
