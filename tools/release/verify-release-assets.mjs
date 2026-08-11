#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstat, readFile, readdir } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { assertExactKeys, canonicalJson, strictJson } from "../conformance/cross-wire.mjs";

const MANIFEST_KEYS = [
  "artifacts", "crossReportDigest", "crossRunnerSourceDigest", "generatorHash",
  "generatorVersion", "ownershipManifestDigest", "protocolSourceDigest",
  "protocolVersion", "referenceReportDigest", "releaseUrl", "runtimeImage",
  "schemaVersion", "sourceCommit", "sourceTag",
];
const ARTIFACT_KEYS = ["name", "sha256", "size"];
const HEX_256 = /^[0-9a-f]{64}$/;

function fail(message) {
  throw new Error(`RELEASE_ASSET_INVALID: ${message}`);
}

async function sha256(path) {
  const hash = createHash("sha256");
  hash.update(await readFile(path));
  return hash.digest("hex");
}

export async function verifyReleaseAssets(directory) {
  const root = resolve(directory);
  const manifestPath = join(root, "release-manifest.json");
  const manifestSource = await readFile(manifestPath, "utf8");
  const manifest = strictJson(manifestSource);
  assertExactKeys(manifest, MANIFEST_KEYS);
  if (`${canonicalJson(manifest)}\n` !== manifestSource) fail("manifest is not canonical JSON plus LF");
  if (manifest.schemaVersion !== "openant-commerce-release-manifest/1") fail("schema version");
  if (manifest.protocolVersion !== "0.1.0-draft.4") fail("protocol version");
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length === 0) fail("artifacts");

  const names = new Set();
  for (const artifact of manifest.artifacts) {
    assertExactKeys(artifact, ARTIFACT_KEYS);
    if (typeof artifact.name !== "string" || artifact.name !== basename(artifact.name) ||
        artifact.name === "release-manifest.json" || artifact.name === "SHA256SUMS" || names.has(artifact.name)) {
      fail("artifact name");
    }
    if (typeof artifact.sha256 !== "string" || !HEX_256.test(artifact.sha256)) fail("artifact digest");
    if (!Number.isSafeInteger(artifact.size) || artifact.size <= 0) fail("artifact size");
    names.add(artifact.name);
    const path = join(root, artifact.name);
    const metadata = await lstat(path);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size !== artifact.size) fail(`size ${artifact.name}`);
    if (await sha256(path) !== artifact.sha256) fail(`digest ${artifact.name}`);
  }

  const expectedFiles = [...names, "release-manifest.json", "SHA256SUMS"].sort();
  const actualFiles = (await readdir(root)).sort();
  if (canonicalJson(actualFiles) !== canonicalJson(expectedFiles)) fail("unexpected or missing files");

  const checksumLines = [
    ...manifest.artifacts.map(({ name, sha256: digest }) => `${digest}  ${name}`),
    `${await sha256(manifestPath)}  release-manifest.json`,
  ].sort();
  const checksumSource = await readFile(join(root, "SHA256SUMS"), "utf8");
  if (`${checksumLines.join("\n")}\n` !== checksumSource) fail("SHA256SUMS");
  return manifest;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    const directory = process.argv[2];
    if (!directory || process.argv.length !== 3) fail("usage");
    const manifest = await verifyReleaseAssets(directory);
    process.stdout.write(`${canonicalJson({
      artifacts: manifest.artifacts.length,
      protocolVersion: manifest.protocolVersion,
      sourceTag: manifest.sourceTag,
    })}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "RELEASE_ASSET_INVALID"}\n`);
    process.exitCode = 1;
  }
}
