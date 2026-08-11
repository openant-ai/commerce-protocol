"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");

const REPO_DIR = path.resolve(__dirname, "..", "..");
const contract = JSON.parse(
  fs.readFileSync(path.join(REPO_DIR, "spec", "commerce.json"), "utf8"),
);

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

function sourceDigest() {
  const hash = crypto.createHash("sha256");
  for (const relativePath of contract.digest.files) {
    const absolutePath = path.join(REPO_DIR, relativePath);
    const document = JSON.parse(fs.readFileSync(absolutePath, "utf8"));
    hash.update(relativePath, "utf8");
    hash.update("\n", "utf8");
    hash.update(canonicalJson(document), "utf8");
    hash.update("\n", "utf8");
  }
  return `sha256:${hash.digest("hex")}`;
}

test("protocol source digest is reproducible", () => {
  const expected = fs
    .readFileSync(path.join(__dirname, "expected-digest.txt"), "utf8")
    .trim();
  const first = sourceDigest();
  const second = sourceDigest();
  assert.equal(first, second);
  assert.equal(first, expected);
});

if (require.main === module) {
  process.stdout.write(`${sourceDigest()}\n`);
}

module.exports = { canonicalJson, sourceDigest };
