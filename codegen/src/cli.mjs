#!/usr/bin/env node

import path from "node:path";
import process from "node:process";
import { CodegenError, fail } from "./errors.mjs";
import { check, generate } from "./generator.mjs";
import { readDocument } from "./parser.mjs";

function argumentsFor(argv) {
  const [command, ...tokens] = argv;
  const options = {};
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (!token.startsWith("--")) fail("CLI_ARGUMENT_INVALID", `unexpected argument ${token}`);
    const name = token.slice(2);
    if (Object.hasOwn(options, name)) fail("CLI_ARGUMENT_INVALID", `duplicate option --${name}`);
    const value = tokens[index + 1];
    if (!value || value.startsWith("--")) fail("CLI_ARGUMENT_INVALID", `missing value for --${name}`);
    options[name] = value;
    index += 1;
  }
  return { command, options };
}

function rejectUnknownOptions(options, allowed) {
  const unknown = Object.keys(options).filter((name) => !allowed.includes(name));
  if (unknown.length > 0) fail("CLI_ARGUMENT_INVALID", `unknown option --${unknown[0]}`);
}

async function main() {
  const { command, options } = argumentsFor(process.argv.slice(2));
  if (command === "validate") {
    rejectUnknownOptions(options, ["input"]);
    if (!options.input) fail("CLI_ARGUMENT_INVALID", "validate requires --input");
    readDocument(path.resolve(options.input));
    process.stdout.write(`${JSON.stringify({ valid: true })}\n`);
    return;
  }
  if (command === "generate" || command === "check") {
    rejectUnknownOptions(options, ["root", "out", "descriptions"]);
    const root = path.resolve(options.root ?? path.resolve(import.meta.dirname, "..", ".."));
    const out = path.resolve(options.out ?? path.join(root, "codegen", "generated"));
    const descriptions = options.descriptions ? path.resolve(options.descriptions) : undefined;
    if (command === "generate") {
      const result = generate({ root, out, descriptions });
      process.stdout.write(`${JSON.stringify(result.report)}\n`);
      if (result.hasDrift) {
        fail("GENERATED_OUTPUT_DRIFT", "generated output contains unexpected entries", result.report.differences);
      }
      return;
    }
    const result = check({ root, out, descriptions });
    process.stdout.write(`${JSON.stringify(result.report)}\n`);
    if (result.hasDrift) fail("GENERATED_OUTPUT_DRIFT", "generated outputs differ from source", result.report.differences);
    return;
  }
  fail("CLI_ARGUMENT_INVALID", "expected generate, check, or validate");
}

main().catch((error) => {
  const structured = error instanceof CodegenError
    ? { code: error.code, message: error.message, context: error.context }
    : { code: "CODEGEN_INTERNAL", message: error?.message ?? String(error) };
  process.stderr.write(`${JSON.stringify(structured)}\n`);
  process.exitCode = 1;
});
