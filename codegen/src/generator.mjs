import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fail } from "./errors.mjs";
import { sha256 } from "./hash.mjs";
import { buildContractIr } from "./ir.mjs";
import { readDocument } from "./parser.mjs";
import { jsonBytes, renderArtifacts } from "./render.mjs";
import { generatorHash, loadProtocolSource } from "./source.mjs";

function reportFor(ir, artifacts, hash, drift = false, differences = undefined) {
  const report = {
    protocolVersion: ir.protocolVersion,
    sourceDigest: ir.sourceDigest,
    generatorVersion: ir.generatorVersion,
    generatorHash: hash,
    outputHashes: Object.fromEntries([...artifacts].map(([name, bytes]) => [name, sha256(bytes)])),
    drift,
  };
  if (differences) report.differences = differences;
  return report;
}

function expectedFiles(root, descriptionsFile) {
  const source = loadProtocolSource(root);
  const narrative = descriptionsFile ? readDocument(path.resolve(descriptionsFile)) : undefined;
  const ir = buildContractIr(source, narrative);
  const hash = generatorHash();
  const artifacts = renderArtifacts(ir, source.schema);
  const report = reportFor(ir, artifacts, hash);
  return { ir, artifacts: new Map([...artifacts, ["codegen-report.json", jsonBytes(report)]]), report };
}

function listFiles(root, relative = "") {
  if (!existsSync(root)) return [];
  const result = [];
  for (const entry of readdirSync(path.join(root, relative), { withFileTypes: true })
    .sort((left, right) => left.name.localeCompare(right.name))) {
    const child = path.join(relative, entry.name);
    if (entry.isDirectory()) result.push(...listFiles(root, child));
    else result.push(child.split(path.sep).join("/"));
  }
  return result;
}

function listDirectories(root, relative = "") {
  if (!existsSync(root)) return [];
  const result = [];
  for (const entry of readdirSync(path.join(root, relative), { withFileTypes: true })
    .sort((left, right) => left.name.localeCompare(right.name))) {
    if (!entry.isDirectory()) continue;
    const child = path.join(relative, entry.name);
    result.push(child.split(path.sep).join("/"));
    result.push(...listDirectories(root, child));
  }
  return result;
}

function safeOutputDirectory(directory) {
  const resolved = path.resolve(directory);
  const filesystemRoot = path.parse(resolved).root;
  if (resolved === filesystemRoot || resolved === path.resolve(".")) {
    fail("OUTPUT_PATH_UNSAFE", "refusing to use a filesystem or working-directory root as generated output");
  }
  return resolved;
}

function differences(expected, outputDirectory) {
  const actualNames = new Set(listFiles(outputDirectory));
  const expectedNames = new Set(expected.keys());
  const expectedDirectories = new Set([...expectedNames].flatMap((name) => {
    const parts = name.split("/").slice(0, -1);
    return parts.map((_, index) => parts.slice(0, index + 1).join("/"));
  }));
  const missing = [...expectedNames].filter((name) => !actualNames.has(name)).sort();
  const extra = [
    ...[...actualNames].filter((name) => !expectedNames.has(name)),
    ...listDirectories(outputDirectory).filter((name) => !expectedDirectories.has(name)).map((name) => `${name}/`),
  ].sort();
  const changed = [...expectedNames].filter((name) => actualNames.has(name) &&
    !readFileSync(path.join(outputDirectory, name)).equals(Buffer.from(expected.get(name)))).sort();
  return { missing, extra, changed };
}

export function generate({ root, out, descriptions }) {
  const outputDirectory = safeOutputDirectory(out);
  const expected = expectedFiles(root, descriptions);
  mkdirSync(outputDirectory, { recursive: true });
  for (const [name, bytes] of expected.artifacts) {
    const destination = path.join(outputDirectory, name);
    mkdirSync(path.dirname(destination), { recursive: true });
    writeFileSync(destination, bytes);
  }
  const drift = differences(expected.artifacts, outputDirectory);
  const hasDrift = Object.values(drift).some((names) => names.length > 0);
  return {
    report: {
      ...expected.report,
      drift: hasDrift,
      ...(hasDrift ? { differences: drift } : {}),
    },
    hasDrift,
  };
}

export function check({ root, out, descriptions }) {
  const outputDirectory = safeOutputDirectory(out);
  const expected = expectedFiles(root, descriptions);
  const drift = differences(expected.artifacts, outputDirectory);
  const hasDrift = Object.values(drift).some((names) => names.length > 0);
  return {
    report: {
      ...expected.report,
      drift: hasDrift,
      ...(hasDrift ? { differences: drift } : {}),
    },
    hasDrift,
  };
}
