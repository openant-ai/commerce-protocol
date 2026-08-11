import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { canonicalJson } from "../conformance/cross-wire.mjs";
import { verifyReleaseAssets } from "./verify-release-assets.mjs";

const digest = (value) => createHash("sha256").update(value).digest("hex");

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "openant-release-assets-"));
  const body = Buffer.from("artifact\n");
  await writeFile(join(root, "artifact.bin"), body);
  const manifest = {
    artifacts: [{ name: "artifact.bin", sha256: digest(body), size: body.length }],
    crossReportDigest: `sha256:${"1".repeat(64)}`,
    crossRunnerSourceDigest: `sha256:${"2".repeat(64)}`,
    generatorHash: `sha256:${"3".repeat(64)}`,
    generatorVersion: "0.1.0",
    ownershipManifestDigest: `sha256:${"4".repeat(64)}`,
    protocolSourceDigest: `sha256:${"5".repeat(64)}`,
    protocolVersion: "0.1.0-draft.4",
    referenceReportDigest: `sha256:${"6".repeat(64)}`,
    releaseUrl: "https://github.com/openant-ai/commerce-protocol/releases/tag/v0.1.0-draft.4",
    runtimeImage: `node:20-bookworm-slim@sha256:${"7".repeat(64)}`,
    schemaVersion: "openant-commerce-release-manifest/1",
    sourceCommit: "8".repeat(40),
    sourceTag: "v0.1.0-draft.4",
  };
  const source = `${canonicalJson(manifest)}\n`;
  await writeFile(join(root, "release-manifest.json"), source);
  await writeFile(join(root, "SHA256SUMS"), [
    `${digest(body)}  artifact.bin`,
    `${digest(source)}  release-manifest.json`,
  ].sort().join("\n") + "\n");
  return root;
}

test("release assets require exact canonical bytes and checksums", async () => {
  const root = await fixture();
  const manifest = await verifyReleaseAssets(root);
  assert.equal(manifest.artifacts.length, 1);
});

test("release assets reject a post-manifest mutation", async () => {
  const root = await fixture();
  await writeFile(join(root, "artifact.bin"), "mutated\n");
  await assert.rejects(verifyReleaseAssets(root), /RELEASE_ASSET_INVALID/);
  assert.equal((await readFile(join(root, "release-manifest.json"), "utf8")).endsWith("\n"), true);
});
