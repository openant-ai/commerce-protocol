#!/usr/bin/env node

import { fileURLToPath } from "node:url";

import { canonicalJson } from "../../reference/canonical.mjs";
import { VECTORS } from "../../vectors/hosted-phase0.mjs";
import { runConformance } from "./runner.mjs";

class CliError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function takeValue(argv, index) {
  if (index + 1 >= argv.length || argv[index + 1].startsWith("--")) {
    throw new CliError("USAGE_ERROR");
  }
  return argv[index + 1];
}

function parseArguments(argv) {
  let executable = null;
  const args = [];
  let vectorId = null;
  let timeoutMs = 5_000;
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === "--adapter") {
      executable = takeValue(argv, index);
      index += 1;
    } else if (option === "--adapter-arg") {
      args.push(takeValue(argv, index));
      index += 1;
    } else if (option === "--vector") {
      vectorId = takeValue(argv, index);
      index += 1;
    } else if (option === "--timeout-ms") {
      const value = takeValue(argv, index);
      if (!/^[1-9]\d{0,5}$/.test(value)) throw new CliError("USAGE_ERROR");
      timeoutMs = Number(value);
      index += 1;
    } else {
      throw new CliError("USAGE_ERROR");
    }
  }
  if (executable === null && args.length > 0) throw new CliError("USAGE_ERROR");
  if (executable === null) {
    executable = process.execPath;
    args.push(fileURLToPath(new URL("../../reference/adapter-cli.mjs", import.meta.url)));
  }
  const vectors = vectorId === null ? VECTORS : VECTORS.filter(({ id }) => id === vectorId);
  if (vectors.length === 0) throw new CliError("UNKNOWN_VECTOR");
  return { vectors, adapter: { executable, args, timeoutMs } };
}

try {
  const { vectors, adapter } = parseArguments(process.argv.slice(2));
  const reports = await runConformance(vectors, adapter);
  for (const report of reports) process.stdout.write(`${canonicalJson(report)}\n`);
  if (reports.some(({ result }) => result !== "PASS")) process.exitCode = 1;
} catch (error) {
  process.stderr.write(`${error instanceof CliError ? error.code : "USAGE_ERROR"}\n`);
  process.exitCode = 2;
}
