import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fail } from "./errors.mjs";
import { framedDigest, sha256 } from "./hash.mjs";
import { readDocument } from "./parser.mjs";

export const GENERATOR_VERSION = "0.1.0";
export const SUPPORTED_PROTOCOL_VERSION = "0.1.0-draft.4";
export const SUPPORTED_SOURCE_DIGEST =
  "sha256:0069b449f4b0f2f2ae88103219a182703498231b3e7cbe6d76cdd7e3f195ff27";

function containedPath(root, relativePath) {
  const absolute = path.resolve(root, relativePath);
  const relative = path.relative(root, absolute);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    fail("SOURCE_PATH_INVALID", `source path escapes repository root: ${relativePath}`);
  }
  return absolute;
}

function sourceContractPath(root) {
  const candidates = ["spec/commerce.json", "spec/commerce.yaml", "spec/commerce.yml"]
    .filter((relativePath) => existsSync(path.join(root, relativePath)));
  if (candidates.length !== 1) {
    fail("SOURCE_SET_AMBIGUOUS", "exactly one spec/commerce.json|yaml|yml is required", { candidates });
  }
  return candidates[0];
}

export function loadProtocolSource(rootDirectory) {
  const root = path.resolve(rootDirectory);
  const contractRelativePath = sourceContractPath(root);
  const contractPath = containedPath(root, contractRelativePath);
  const contract = readDocument(contractPath);
  if (!contract?.digest || !Array.isArray(contract.digest.files) || contract.digest.files.length < 2) {
    fail("SOURCE_CONTRACT_INVALID", "commerce source must declare digest.files");
  }
  if (!contract.digest.files.includes(contractRelativePath)) {
    fail("SOURCE_CONTRACT_INVALID", "digest.files must include the commerce source itself");
  }

  const documents = contract.digest.files.map((relativePath) => {
    if (typeof relativePath !== "string" || relativePath.includes("\\")) {
      fail("SOURCE_PATH_INVALID", "digest file paths must be POSIX relative strings");
    }
    const absolutePath = containedPath(root, relativePath);
    if (!existsSync(absolutePath)) fail("SOURCE_FILE_MISSING", `missing digest source ${relativePath}`);
    return { relativePath, absolutePath, document: readDocument(absolutePath) };
  });

  const schemaAbsolutePath = path.resolve(path.dirname(contractPath), contract.protocol?.schema ?? "");
  const schemaRelativePath = path.relative(root, schemaAbsolutePath).split(path.sep).join("/");
  const schemaEntry = documents.find(({ relativePath }) => relativePath === schemaRelativePath);
  if (!schemaEntry) fail("SOURCE_CONTRACT_INVALID", "protocol.schema must be one of digest.files");

  const sourceDigest = framedDigest(documents);
  if (contract.protocol?.version !== SUPPORTED_PROTOCOL_VERSION || sourceDigest !== SUPPORTED_SOURCE_DIGEST) {
    fail("SOURCE_VERSION_UNSUPPORTED", "generator is pinned to the accepted draft.4 source", {
      expectedProtocolVersion: SUPPORTED_PROTOCOL_VERSION,
      actualProtocolVersion: contract.protocol?.version,
      expectedSourceDigest: SUPPORTED_SOURCE_DIGEST,
      actualSourceDigest: sourceDigest,
    });
  }
  return { root, contract, schema: schemaEntry.document, sourceDigest };
}

export function generatorHash() {
  const sourceDirectory = path.resolve(import.meta.dirname);
  const files = readdirSync(sourceDirectory)
    .filter((name) => name.endsWith(".mjs"))
    .sort();
  const framed = files.map((name) => `${name}\n${readFileSync(path.join(sourceDirectory, name), "utf8")}\n`).join("");
  return sha256(framed);
}
