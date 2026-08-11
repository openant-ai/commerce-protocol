import {
  createPublicKey,
  verify as cryptoVerify,
  type JsonWebKey,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { signDigestJws, type DetachedJwsAlgorithm } from "../src/index.js";

const P256_ORDER = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const digest = `sha256:${"ab".repeat(32)}` as const;

const p256PrivateJwk: JsonWebKey = {
  kty: "EC",
  crv: "P-256",
  x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
  d: "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
};

const ed25519PrivateJwk: JsonWebKey = {
  kty: "OKP",
  crv: "Ed25519",
  d: "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
  x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
};

function base64url(input: Uint8Array | string): string {
  return Buffer.from(input).toString("base64url");
}

function signingInput(detachedJws: string, payload = digest): { input: Buffer; signature: Buffer; header: unknown } {
  const [protectedHeader, detachedPayload, encodedSignature, extra] = detachedJws.split(".");
  expect(extra).toBeUndefined();
  expect(detachedPayload).toBe("");
  expect(protectedHeader).toBeTruthy();
  expect(encodedSignature).toBeTruthy();
  return {
    input: Buffer.from(`${protectedHeader}.${base64url(payload)}`, "ascii"),
    signature: Buffer.from(encodedSignature!, "base64url"),
    header: JSON.parse(Buffer.from(protectedHeader!, "base64url").toString("utf8")),
  };
}

it("verifies the same ES256, EdDSA, and rotated-kid golden vectors as Rust", () => {
  const fixture = JSON.parse(
    readFileSync(
      fileURLToPath(new URL("../../verifier/test-vectors/jws-v1.json", import.meta.url)),
      "utf8",
    ),
  ) as {
    es256: { signature: string; signedObjectDigest: string };
    eddsa: { signature: string; signedObjectDigest: string };
    rotatedEddsa: { signature: string; signedObjectDigest: string };
  };
  const cases = [
    ["ES256", fixture.es256, p256PrivateJwk],
    ["EdDSA", fixture.eddsa, ed25519PrivateJwk],
    [
      "EdDSA",
      fixture.rotatedEddsa,
      {
        kty: "OKP",
        crv: "Ed25519",
        x: "KgqvVKQHd5gox2bT1imb9oG4RR5U6Om_n1RPmBYRIks",
      } satisfies JsonWebKey,
    ],
  ] as const;

  for (const [algorithm, envelope, jwk] of cases) {
    const parsed = signingInput(envelope.signature, envelope.signedObjectDigest);
    const publicKey = createPublicKey({ key: jwk, format: "jwk" });
    expect(
      algorithm === "ES256"
        ? cryptoVerify("sha256", parsed.input, { key: publicKey, dsaEncoding: "ieee-p1363" }, parsed.signature)
        : cryptoVerify(null, parsed.input, publicKey, parsed.signature),
    ).toBe(true);
  }
});

describe.each([
  ["ES256", p256PrivateJwk],
  ["EdDSA", ed25519PrivateJwk],
] satisfies readonly (readonly [DetachedJwsAlgorithm, JsonWebKey])[])(
  "detached %s JWS",
  (algorithm, privateKey) => {
    it("binds alg/aud/iss/kid and signs the literal object digest", () => {
      const envelope = signDigestJws({
        algorithm,
        audience: "openant-commerce-verifier",
        issuer: "issuer:openant:example",
        keyId: "key-2026-08",
        signedObjectDigest: digest,
        privateKey,
      });

      expect(envelope).toMatchObject({
        scheme: algorithm === "ES256" ? "DETACHED_JWS_ES256" : "DETACHED_JWS_EDDSA",
        issuer: "issuer:openant:example",
        keyId: "key-2026-08",
        signedObjectDigest: digest,
      });
      const parsed = signingInput(envelope.signature);
      expect(parsed.header).toEqual({
        alg: algorithm,
        aud: "openant-commerce-verifier",
        iss: "issuer:openant:example",
        kid: "key-2026-08",
        typ: "openant-commerce+jws",
      });
      expect(parsed.signature).toHaveLength(64);

      const publicKey = createPublicKey({ key: privateKey, format: "jwk" });
      expect(
        algorithm === "ES256"
          ? cryptoVerify("sha256", parsed.input, { key: publicKey, dsaEncoding: "ieee-p1363" }, parsed.signature)
          : cryptoVerify(null, parsed.input, publicKey, parsed.signature),
      ).toBe(true);

      if (algorithm === "ES256") {
        const s = BigInt(`0x${parsed.signature.subarray(32).toString("hex")}`);
        expect(s).toBeLessThanOrEqual(P256_ORDER / 2n);
      }
    });
  },
);

it.each([
  ["empty audience", { audience: "" }],
  ["invalid digest", { signedObjectDigest: "sha256:ABC" }],
  ["NUL issuer", { issuer: "issuer:openant\0attacker" }],
] as const)("rejects %s", (_name, override) => {
  expect(() =>
    signDigestJws({
      algorithm: "EdDSA",
      audience: "openant-commerce-verifier",
      issuer: "issuer:openant:example",
      keyId: "key-2026-08",
      signedObjectDigest: digest,
      privateKey: ed25519PrivateJwk,
      ...override,
    }),
  ).toThrow();
});
