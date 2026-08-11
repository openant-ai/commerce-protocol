import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { canonicalizeJcs, digestStructured, type JsonValue } from "../src/index.js";

const fixture = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../../verifier/test-vectors/jcs-v1.json", import.meta.url)),
    "utf8",
  ),
) as {
  wireVersion: string;
  profile: string;
  value: JsonValue;
  canonical: string;
  digest: `sha256:${string}`;
  unicodeSortingValue: JsonValue;
  unicodeSortingCanonical: string;
  rfc8785AppendixB: readonly { ieee754: string; canonical: string }[];
  invalidJsonTexts: readonly { name: string; json: string }[];
  rfc8785InvalidNumbers: readonly { ieee754: string; name: string }[];
};

describe("RFC 8785 structured digest", () => {
  it("matches the RFC number/string example and protocol framing", () => {
    expect(new TextDecoder().decode(canonicalizeJcs(fixture.value))).toBe(fixture.canonical);
    expect(digestStructured(fixture.profile, fixture.value, fixture.wireVersion)).toBe(
      fixture.digest,
    );
  });

  it("sorts object properties by UTF-16 code units recursively", () => {
    const canonical = new TextDecoder().decode(canonicalizeJcs(fixture.unicodeSortingValue));
    expect(canonical).toBe(fixture.unicodeSortingCanonical);
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])(
    "rejects non-I-JSON number %s",
    (value) => {
      expect(() => canonicalizeJcs({ value })).toThrow();
    },
  );

  it("rejects lone UTF-16 surrogates", () => {
    expect(() => canonicalizeJcs({ value: "\ud800" })).toThrow();
  });

  it("matches every finite RFC 8785 Appendix B sample", () => {
    for (const sample of fixture.rfc8785AppendixB) {
      const bits = BigInt(`0x${sample.ieee754}`);
      const bytes = new Uint8Array(8);
      new DataView(bytes.buffer).setBigUint64(0, bits);
      const number = new DataView(bytes.buffer).getFloat64(0);
      expect(new TextDecoder().decode(canonicalizeJcs(number))).toBe(sample.canonical);
    }
  });

  it.each(fixture.invalidJsonTexts)("rejects shared invalid JSON: $name", ({ json }) => {
    const parsed = JSON.parse(json) as JsonValue;
    expect(() => canonicalizeJcs(parsed)).toThrow();
  });

  it("rejects the non-finite RFC 8785 Appendix B bit patterns", () => {
    for (const sample of fixture.rfc8785InvalidNumbers) {
      const bytes = new Uint8Array(8);
      new DataView(bytes.buffer).setBigUint64(0, BigInt(`0x${sample.ieee754}`));
      const number = new DataView(bytes.buffer).getFloat64(0);
      expect(() => canonicalizeJcs(number), sample.name).toThrow();
    }
  });
});
