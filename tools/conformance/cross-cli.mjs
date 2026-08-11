#!/usr/bin/env node

import { runCrossConformance, CrossConformanceError } from "./cross-runner.mjs";
import { canonicalJson } from "./cross-wire.mjs";

function usage() {
  throw new CrossConformanceError("USAGE_ERROR");
}

function argumentsOf(argv) {
  const names = new Map([
    ["--protocol-archive", "protocolArchive"],
    ["--money-projection-baseline", "moneyProjectionBaseline"],
    ["--crypto-proof-report", "cryptoProofReport"],
    ["--adapter-source-bundle", "adapterSourceBundle"],
    ["--adapter", "adapter"],
    ["--timeout-ms", "timeoutMs"],
  ]);
  const values = Object.create(null);
  for (let index = 0; index < argv.length; index += 2) {
    const option = argv[index];
    const name = names.get(option);
    const value = argv[index + 1];
    if (name === undefined || value === undefined || value.startsWith("--") || name in values) usage();
    values[name] = value;
  }
  if (Object.keys(values).length !== names.size) usage();
  if (!/^[1-9]\d{0,5}$/.test(values.timeoutMs)) usage();
  values.timeoutMs = Number(values.timeoutMs);
  return values;
}

try {
  const options = argumentsOf(process.argv.slice(2));
  options.adapter = { executable: options.adapter, args: [], coordinatePath: options.adapter };
  const reports = await runCrossConformance(options);
  for (const report of reports) process.stdout.write(`${canonicalJson(report)}\n`);
  if (reports.some(({ result }) => result !== "PASS")) process.exitCode = 1;
} catch (error) {
  process.stderr.write(`${error instanceof CrossConformanceError ? error.code : "CROSS_CONFORMANCE_FAILED"}\n`);
  process.exitCode = 2;
}
