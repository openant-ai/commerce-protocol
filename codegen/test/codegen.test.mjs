import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { canonicalJson } from "../src/hash.mjs";

const CODEGEN_DIR = path.resolve(import.meta.dirname, "..");
const REPO_DIR = path.resolve(CODEGEN_DIR, "..");
const CLI = path.join(CODEGEN_DIR, "src", "cli.mjs");
const TSC = path.join(CODEGEN_DIR, "node_modules", "typescript", "bin", "tsc");
const EXPECTED_DIGEST = "sha256:0069b449f4b0f2f2ae88103219a182703498231b3e7cbe6d76cdd7e3f195ff27";

function run(args, options = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd: CODEGEN_DIR,
    encoding: "utf8",
    ...options,
  });
}

function cleanDir() {
  return mkdtempSync(path.join(tmpdir(), "openant-commerce-codegen-"));
}

function recursiveFiles(root, relative = "") {
  const entries = readdirSync(path.join(root, relative), { withFileTypes: true })
    .sort((left, right) => left.name.localeCompare(right.name));
  const files = new Map();
  for (const entry of entries) {
    const child = path.join(relative, entry.name);
    if (entry.isDirectory()) {
      for (const [name, bytes] of recursiveFiles(root, child)) files.set(name, bytes);
    } else {
      files.set(child, readFileSync(path.join(root, child)));
    }
  }
  return files;
}

function assertTreesEqual(left, right) {
  assert.deepEqual([...left.keys()], [...right.keys()]);
  for (const key of left.keys()) assert.deepEqual(left.get(key), right.get(key), key);
}

function json(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}

function typescriptContract(file) {
  const source = readFileSync(file, "utf8");
  const match = source.match(/\/\* COMMERCE_CONTRACT_JSON_START\n(.+)\nCOMMERCE_CONTRACT_JSON_END \*\//);
  assert.ok(match, "generated TypeScript must expose a machine-readable contract projection");
  return JSON.parse(match[1]);
}

async function loadCliSkeleton(file) {
  const module = await import(`${pathToFileURL(file).href}?test=${Date.now()}-${Math.random()}`);
  return module.COMMERCE_CONTRACT;
}

test("generate derives five parity-preserving adapters from accepted draft.4", async (context) => {
  const out = cleanDir();
  context.after(() => rmSync(out, { recursive: true, force: true }));

  const result = run(["generate", "--root", REPO_DIR, "--out", out]);
  assert.equal(result.status, 0, result.stderr);

  const openapi = json(path.join(out, "openapi-3.1.json"));
  const types = typescriptContract(path.join(out, "commerce-types.ts"));
  const mcp = json(path.join(out, "mcp-tools.json"));
  const cli = await loadCliSkeleton(path.join(out, "cli-skeleton.mjs"));
  const skill = json(path.join(out, "skill-metadata.json"));
  const projections = [
    openapi["x-openant-commerce-contract"],
    types,
    mcp.metadata.contract,
    cli,
    skill.metadata.contract,
  ];

  for (const projection of projections) {
    assert.equal(projection.protocolVersion, "0.1.0-draft.4");
    assert.equal(projection.sourceDigest, EXPECTED_DIGEST);
    assert.equal(projection.generatorVersion, "0.1.0");
    assert.deepEqual(projection.operations, projections[0].operations);
    for (const operation of projection.operations) {
      assert.ok(operation.required.length > 0);
      assert.ok(operation.schema);
      assert.ok(operation.errors.every(({ code, retryable, boundary }) =>
        typeof code === "string" && typeof retryable === "boolean" && typeof boundary === "string"));
      assert.ok(operation.limits);
      assert.ok(operation.permissions);
      assert.ok(Object.hasOwn(operation, "chargeableSuccess"));
      assert.ok(Array.isArray(operation.permissions.requiredEvidence));
      assert.equal(typeof operation.chargeableSuccess.applicability.applicable, "boolean");
    }
  }

  const report = json(path.join(out, "codegen-report.json"));
  assert.equal(report.sourceDigest, EXPECTED_DIGEST);
  assert.equal(report.protocolVersion, "0.1.0-draft.4");
  assert.equal(report.generatorVersion, "0.1.0");
  assert.match(report.generatorHash, /^sha256:[a-f0-9]{64}$/);
  assert.equal(report.drift, false);
  assert.deepEqual(Object.keys(report.outputHashes).sort(), [
    "cli-skeleton.mjs",
    "commerce-types.ts",
    "mcp-tools.json",
    "openapi-3.1.json",
    "skill-metadata.json",
  ]);
  assert.doesNotMatch(JSON.stringify(report), /requestBody|responseBody|toolArguments|privateKey/i);

  const typeSource = readFileSync(path.join(out, "commerce-types.ts"), "utf8");
  const acceptance = typeSource.match(/^export type AcceptanceReceipt = (.+);$/m)?.[1] ?? "";
  assert.match(acceptance, /serviceSkuVersionDigest/);
  assert.match(acceptance, /responseDigest/);
  assert.match(acceptance, /artifactManifestDigest/);
});

test("two clean generations are recursively byte-identical", (context) => {
  const left = cleanDir();
  const right = cleanDir();
  context.after(() => rmSync(left, { recursive: true, force: true }));
  context.after(() => rmSync(right, { recursive: true, force: true }));

  assert.equal(run(["generate", "--root", REPO_DIR, "--out", left]).status, 0);
  assert.equal(run(["generate", "--root", REPO_DIR, "--out", right]).status, 0);
  assertTreesEqual(recursiveFiles(left), recursiveFiles(right));
});

test("check is read-only and fails closed for missing, extra, and changed outputs", (context) => {
  const out = cleanDir();
  context.after(() => rmSync(out, { recursive: true, force: true }));
  assert.equal(run(["generate", "--root", REPO_DIR, "--out", out]).status, 0);

  const initial = recursiveFiles(out);
  const clean = run(["check", "--root", REPO_DIR, "--out", out]);
  assert.equal(clean.status, 0, clean.stderr);
  assert.equal(JSON.parse(clean.stdout).drift, false);
  assertTreesEqual(initial, recursiveFiles(out));

  const changed = path.join(out, "mcp-tools.json");
  writeFileSync(changed, `${readFileSync(changed, "utf8")} `);
  const changedBefore = recursiveFiles(out);
  const changedResult = run(["check", "--root", REPO_DIR, "--out", out]);
  assert.notEqual(changedResult.status, 0);
  assert.equal(JSON.parse(changedResult.stdout).drift, true);
  assertTreesEqual(changedBefore, recursiveFiles(out));

  assert.equal(run(["generate", "--root", REPO_DIR, "--out", out]).status, 0);
  writeFileSync(path.join(out, "unexpected.txt"), "unexpected\n");
  mkdirSync(path.join(out, "empty-extra"));
  const extraBefore = recursiveFiles(out);
  assert.notEqual(run(["check", "--root", REPO_DIR, "--out", out]).status, 0);
  assertTreesEqual(extraBefore, recursiveFiles(out));

  rmSync(path.join(out, "unexpected.txt"));
  rmSync(path.join(out, "empty-extra"), { recursive: true });
  assert.equal(run(["generate", "--root", REPO_DIR, "--out", out]).status, 0);
  rmSync(path.join(out, "commerce-types.ts"));
  const missingBefore = recursiveFiles(out);
  assert.notEqual(run(["check", "--root", REPO_DIR, "--out", out]).status, 0);
  assertTreesEqual(missingBefore, recursiveFiles(out));
});

test("manual narrative cannot override structured commerce semantics", (context) => {
  const out = cleanDir();
  context.after(() => rmSync(out, { recursive: true, force: true }));
  const valid = run([
    "generate", "--root", REPO_DIR, "--out", out,
    "--descriptions", path.join(REPO_DIR, "fixtures", "valid", "descriptions.json"),
  ]);
  assert.equal(valid.status, 0, valid.stderr);
  const projection = json(path.join(out, "mcp-tools.json")).metadata.contract;
  assert.equal(projection.operations.find(({ kind }) => kind === "INVOCATION").narrative.summary,
    "Invoke one immutable Service SKU.");

  const invalid = run([
    "generate", "--root", REPO_DIR, "--out", out,
    "--descriptions", path.join(REPO_DIR, "fixtures", "invalid", "semantic-override.json"),
  ]);
  assert.notEqual(invalid.status, 0);
  assert.match(invalid.stderr, /NARRATIVE_OVERRIDE_FORBIDDEN/);
});

test("generated TypeScript preserves oneOf XOR and conditional evidence", () => {
  const result = spawnSync(process.execPath, [
    TSC,
    "--noEmit",
    "--strict",
    "--target", "ES2022",
    "--module", "NodeNext",
    "--moduleResolution", "NodeNext",
    path.join(CODEGEN_DIR, "test", "types", "acceptance-xor.ts"),
    path.join(CODEGEN_DIR, "test", "types", "payment-intent-conditions.ts"),
    path.join(CODEGEN_DIR, "test", "types", "positive-primitives.ts"),
  ], { cwd: CODEGEN_DIR, encoding: "utf8" });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
});

test("source parser rejects ambiguity without treating quoted YAML markers as syntax", () => {
  const invalidFixtures = [
    "duplicate-keys.json",
    "duplicate-keys.yaml",
    "nested-duplicate-keys.yaml",
    "anchor.yaml",
    "inline-anchor.yaml",
    "alias.yaml",
    "unicode-anchor.yaml",
    "unicode-alias.yaml",
    "unicode-anchor-key.yaml",
    "unicode-alias-key.yaml",
    "merge.yaml",
  ];
  for (const name of invalidFixtures) {
    const result = run(["validate", "--input", path.join(REPO_DIR, "fixtures", "invalid", name)]);
    assert.notEqual(result.status, 0, name);
    assert.match(result.stderr, /AMBIGUOUS_SOURCE/, name);
  }

  const quoted = run(["validate", "--input", path.join(REPO_DIR, "fixtures", "valid", "quoted-markers.yaml")]);
  assert.equal(quoted.status, 0, quoted.stderr);
  assert.equal(JSON.parse(quoted.stdout).valid, true);
});

test("prototype-sensitive source keys fail before digest or IR construction", (context) => {
  for (const name of ["prototype-proto.json", "prototype-constructor.yaml", "prototype-prototype.yaml"]) {
    const result = run(["validate", "--input", path.join(REPO_DIR, "fixtures", "invalid", name)]);
    assert.notEqual(result.status, 0, name);
    assert.match(result.stderr, /SOURCE_KEY_FORBIDDEN/, name);
  }

  const root = cleanDir();
  const out = cleanDir();
  context.after(() => rmSync(root, { recursive: true, force: true }));
  context.after(() => rmSync(out, { recursive: true, force: true }));
  mkdirSync(path.join(root, "spec"), { recursive: true });
  mkdirSync(path.join(root, "schemas"), { recursive: true });
  cpSync(path.join(REPO_DIR, "schemas", "commerce-0.1.schema.json"),
    path.join(root, "schemas", "commerce-0.1.schema.json"));
  const source = readFileSync(path.join(REPO_DIR, "spec", "commerce.json"), "utf8")
    .replace('"INVOCATION": {', '"INVOCATION": {\n      "__proto__": {"externalStateMachineRef": "ATTACKER_MACHINE"},');
  writeFileSync(path.join(root, "spec", "commerce.json"), source);
  const result = run(["generate", "--root", root, "--out", out]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /SOURCE_KEY_FORBIDDEN/);
  assert.deepEqual(recursiveFiles(out), new Map());

  const ownProto = Object.create(null);
  Object.defineProperty(ownProto, "__proto__", {
    value: { externalStateMachineRef: "ATTACKER_MACHINE" },
    enumerable: true,
  });
  assert.throws(() => canonicalJson({ nested: ownProto }), (error) =>
    error?.code === "SOURCE_DATA_UNSAFE");

  const polluted = Object.create({ externalStateMachineRef: "ATTACKER_MACHINE" });
  polluted.safe = true;
  assert.throws(() => canonicalJson({ nested: polluted }), (error) =>
    error?.code === "SOURCE_DATA_UNSAFE");

  const accessorArray = [];
  Object.defineProperty(accessorArray, "0", { enumerable: true, get: () => "attacker" });
  accessorArray.length = 1;
  assert.throws(() => canonicalJson({ nested: accessorArray }), (error) =>
    error?.code === "SOURCE_DATA_UNSAFE");
});

test("non-finite YAML numbers fail before canonicalization", () => {
  for (const name of ["non-finite-positive.yaml", "non-finite-negative.yaml"]) {
    const result = run(["validate", "--input", path.join(REPO_DIR, "fixtures", "invalid", name)]);
    assert.notEqual(result.status, 0, name);
    assert.match(result.stderr, /SOURCE_NUMBER_INVALID/, name);
  }
  assert.throws(() => canonicalJson({ value: Number.POSITIVE_INFINITY }), (error) =>
    error?.code === "SOURCE_DATA_UNSAFE");
  assert.throws(() => canonicalJson({ value: Number.NEGATIVE_INFINITY }), (error) =>
    error?.code === "SOURCE_DATA_UNSAFE");
});
