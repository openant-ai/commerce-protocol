#!/usr/bin/env node

import { canonicalJson } from "./canonical.mjs";
import { runScenario } from "./index.mjs";
import { ReferenceProtocolError } from "./validation.mjs";

const MAX_INPUT_BYTES = 1024 * 1024;

async function readRequest() {
  process.stdin.setEncoding("utf8");
  let input = "";
  for await (const chunk of process.stdin) {
    input += chunk;
    if (Buffer.byteLength(input) > MAX_INPUT_BYTES) throw new ReferenceProtocolError("SCHEMA_INVALID");
  }
  let request;
  try {
    request = JSON.parse(input);
  } catch {
    throw new ReferenceProtocolError("SCHEMA_INVALID");
  }
  if (
    request === null ||
    typeof request !== "object" ||
    Array.isArray(request) ||
    Object.keys(request).length !== 2 ||
    request.command !== "runVector" ||
    !Object.hasOwn(request, "scenario")
  ) {
    throw new ReferenceProtocolError("SCHEMA_INVALID");
  }
  return request;
}

try {
  const request = await readRequest();
  const response = runScenario(request.scenario);
  process.stdout.write(`${canonicalJson(response)}\n`);
} catch (error) {
  const code = error instanceof ReferenceProtocolError ? error.code : "SCHEMA_INVALID";
  process.stderr.write(`${code}\n`);
  process.exitCode = 1;
}
