import crypto from "node:crypto";
import { fail } from "./errors.mjs";

const FORBIDDEN_SOURCE_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function unsafe(message, context = {}) {
  fail("SOURCE_DATA_UNSAFE", message, context);
}

function assertSafeData(value, path = "$") {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) unsafe("canonical source numbers must be finite", { path });
    return;
  }
  if (typeof value !== "object") {
    unsafe(`canonical source contains unsupported ${typeof value}`, { path });
  }

  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype || Object.getOwnPropertySymbols(value).length > 0) {
      unsafe("canonical source arrays must be ordinary plain arrays", { path });
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Object.keys(descriptors).filter((key) => key !== "length");
    if (keys.length !== value.length || keys.some((key, index) => key !== String(index))) {
      unsafe("canonical source arrays must be dense and contain only indexed elements", { path });
    }
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[index];
      if (!descriptor?.enumerable || !("value" in descriptor)) {
        unsafe("canonical source arrays must contain only enumerable data elements", {
          path: `${path}[${index}]`,
        });
      }
      assertSafeData(descriptor.value, `${path}[${index}]`);
    }
    return;
  }

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    unsafe("canonical source objects must have Object.prototype or null prototype", { path });
  }
  if (Object.getOwnPropertySymbols(value).length > 0) {
    unsafe("canonical source objects cannot contain symbol keys", { path });
  }
  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
    if (FORBIDDEN_SOURCE_KEYS.has(key)) {
      unsafe(`prototype-sensitive canonical source key ${JSON.stringify(key)} is forbidden`, { path });
    }
    if (!descriptor.enumerable || !("value" in descriptor)) {
      unsafe("canonical source objects must contain only enumerable data properties", {
        path: `${path}.${key}`,
      });
    }
    assertSafeData(descriptor.value, `${path}.${key}`);
  }
}

export function canonicalJson(value) {
  assertSafeData(value);
  return canonicalJsonUnsafe(value);
}

function canonicalJsonUnsafe(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJsonUnsafe).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJsonUnsafe(value[key])}`)
    .join(",")}}`;
}

export function sha256(value) {
  return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

export function framedDigest(documents) {
  const hash = crypto.createHash("sha256");
  for (const { relativePath, document } of documents) {
    hash.update(relativePath, "utf8");
    hash.update("\n", "utf8");
    hash.update(canonicalJson(document), "utf8");
    hash.update("\n", "utf8");
  }
  return `sha256:${hash.digest("hex")}`;
}
