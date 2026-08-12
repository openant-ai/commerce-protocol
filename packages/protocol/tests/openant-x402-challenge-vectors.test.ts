import {
  createHash,
  createPublicKey,
  verify as cryptoVerify,
  type JsonWebKey,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { expect, it } from "vitest";

import {
  digestStructured,
  type JsonValue,
  type SignatureEnvelope,
} from "../src/index.js";

const vectorPath = fileURLToPath(
  new URL("../../../vectors/openant-x402-challenge-v1.json", import.meta.url),
);
const vectorBytes = readFileSync(vectorPath);
const vector = JSON.parse(vectorBytes.toString("utf8")) as {
  id: string;
  audience: string;
  keys: readonly {
    issuer: string;
    kid: string;
    role: string;
    notBeforeUnixMs: number;
    notAfterUnixMs: number | null;
    revokedAtUnixMs: number | null;
    jwk: JsonWebKey;
  }[];
  resolvedCatalog: {
    serviceDefinitionVersion: Record<string, JsonValue> & { versionDigest: string };
    offerVersion: Record<string, JsonValue> & { versionDigest: string };
    endpointDescriptorVersion: Record<string, JsonValue> & { versionDigest: string };
    serviceSkuVersion: Record<string, JsonValue> & { skuVersionDigest: string };
  };
  listingMandate: Record<string, JsonValue> & { signature: SignatureEnvelope };
  paymentRequiredOutcome: {
    paymentRequired: {
      resource: { url: string; description: string; mimeType: string };
      accepts: readonly JsonValue[];
      extensions: {
        openant: Record<string, JsonValue> & { signature: SignatureEnvelope };
      };
    };
  };
  standardX402WithoutExtension: Record<string, JsonValue>;
};

function withoutSignature<T extends { signature: SignatureEnvelope }>(value: T): JsonValue {
  const { signature: _signature, ...preimage } = value;
  return preimage as JsonValue;
}

function withoutDigest(value: Record<string, JsonValue>, field: string): JsonValue {
  const preimage = { ...value };
  delete preimage[field];
  return preimage;
}

function catalogAndChallengeBindingsHold(candidate = vector): boolean {
  const catalog = candidate.resolvedCatalog;
  const definition = catalog.serviceDefinitionVersion;
  const offer = catalog.offerVersion;
  const endpoint = catalog.endpointDescriptorVersion;
  const sku = catalog.serviceSkuVersion;
  const listing = candidate.listingMandate;
  const required = candidate.paymentRequiredOutcome.paymentRequired;
  const extension = required.extensions.openant;
  const challengeIssuer = endpoint.challengeIssuer as { issuer: string; keyId: string };
  return definition.versionDigest === digestStructured(
    "SERVICE_DEFINITION_VERSION",
    withoutDigest(definition, "versionDigest"),
  ) && offer.versionDigest === digestStructured(
    "OFFER_VERSION",
    withoutDigest(offer, "versionDigest"),
  ) && endpoint.versionDigest === digestStructured(
    "ENDPOINT_DESCRIPTOR_VERSION",
    withoutDigest(endpoint, "versionDigest"),
  ) && sku.skuVersionDigest === digestStructured(
    "SERVICE_SKU_VERSION",
    withoutDigest(sku, "skuVersionDigest"),
  ) && sku.serviceDefinitionVersionDigest === definition.versionDigest
    && sku.offerVersionDigest === offer.versionDigest
    && sku.endpointDescriptorVersionDigest === endpoint.versionDigest
    && sku.operationId === definition.operationId
    && listing.serviceSkuId === sku.serviceSkuId
    && listing.skuVersionDigest === sku.skuVersionDigest
    && listing.sellerIdentityRef === sku.sellerIdentityRef
    && extension.serviceSkuId === sku.serviceSkuId
    && extension.skuVersionDigest === sku.skuVersionDigest
    && extension.operationId === definition.operationId
    && required.resource.mimeType === definition.outputMediaType
    && extension.amountAtomic === offer.amountAtomic
    && JSON.stringify(extension.asset) === JSON.stringify(offer.asset)
    && (extension.payoutAddress as string).toLowerCase()
      === (offer.payoutAddress as string).toLowerCase()
    && JSON.stringify(extension.assurance) === JSON.stringify(offer.minimumAssurance)
    && extension.mode === endpoint.mode
    && required.resource.url === endpoint.invokeUri
    && extension.signature.issuer === challengeIssuer.issuer
    && extension.signature.keyId === challengeIssuer.keyId;
}

function verifyDetachedEd25519(
  envelope: SignatureEnvelope,
  publicJwk: JsonWebKey,
): boolean {
  const [protectedHeader, detachedPayload, signature, extra] = envelope.signature.split(".");
  expect(extra).toBeUndefined();
  expect(detachedPayload).toBe("");
  const payload = Buffer.from(envelope.signedObjectDigest, "utf8").toString("base64url");
  return cryptoVerify(
    null,
    Buffer.from(`${protectedHeader}.${payload}`, "ascii"),
    createPublicKey({ key: publicJwk, format: "jwk" }),
    Buffer.from(signature!, "base64url"),
  );
}

it("publishes literal draft.4 Listing and Challenge digests with real Ed25519 signatures", () => {
  const listing = vector.listingMandate;
  const extension = vector.paymentRequiredOutcome.paymentRequired.extensions.openant;

  expect(vector.id).toBe("OPENANT.X402.CHALLENGE.SIGNED.001");
  expect(listing.signature.signedObjectDigest).toBe(
    "sha256:25787e4299e4dbef8ecced473b6b14b3343c7224516053d94886347512afd301",
  );
  expect(extension.signature.signedObjectDigest).toBe(
    "sha256:8ffc7ec5bbaf923e1e0868d3c78e45c4969250d3629f17cb3c658b0be6bf813e",
  );
  expect(extension.paymentTermsDigest).toBe(
    "sha256:ad14e71ba0b9fee14157d94371dbbfb8f91a6b8b0b11ae596ca57613d7a095d0",
  );
  expect(digestStructured("LISTING_MANDATE", withoutSignature(listing))).toBe(
    listing.signature.signedObjectDigest,
  );
  expect(digestStructured("OPENANT_X402_EXTENSION", withoutSignature(extension))).toBe(
    extension.signature.signedObjectDigest,
  );
  expect(
    digestStructured("PAYMENT_TERMS", vector.paymentRequiredOutcome.paymentRequired.accepts[0]!),
  ).toBe(extension.paymentTermsDigest);
  expect(verifyDetachedEd25519(listing.signature, vector.keys[0]!.jwk)).toBe(true);
  expect(verifyDetachedEd25519(extension.signature, vector.keys[1]!.jwk)).toBe(true);
});

it("pins the immutable public artifact bytes and contains verification material only", () => {
  expect(createHash("sha256").update(vectorBytes).digest("hex")).toBe(
    "cc45f2e5d3566c3756c522d20f9eb978d086256980af59957d780eda7699996e",
  );
  const forbiddenNames = [
    String.fromCharCode(100),
    ["private", "Key"].join(""),
    String.fromCharCode(115, 101, 101, 100),
  ];
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) {
      for (const child of value) visit(child);
      return;
    }
    if (value !== null && typeof value === "object") {
      for (const [name, child] of Object.entries(value)) {
        expect(forbiddenNames).not.toContain(name);
        visit(child);
      }
    }
  };
  visit(vector);
});

it("resolves the complete immutable Definition, Offer, Endpoint, and SKU catalog root", () => {
  const { serviceDefinitionVersion, offerVersion, endpointDescriptorVersion, serviceSkuVersion } =
    vector.resolvedCatalog;
  expect(serviceDefinitionVersion.versionDigest).toBe(
    "sha256:1dcfaa44e9a460cfcd2d605fd52493e76ae49bd9906e9a02ce19691223d2af4f",
  );
  expect(offerVersion.versionDigest).toBe(
    "sha256:fafc26e77ee2096e66b6dd6db16d8ea7a207b895d3ed4d383571d71de276480f",
  );
  expect(endpointDescriptorVersion.versionDigest).toBe(
    "sha256:db4a404c753783222c1607ca20be67e6419d615c59c04ed551bf3368eea165e7",
  );
  expect(serviceSkuVersion.skuVersionDigest).toBe(
    "sha256:430f5d2026a37e3ec4ed3ac4db18142402d05969fdffc83a52add9a9579c1d30",
  );
  expect(catalogAndChallengeBindingsHold()).toBe(true);
});

it.each([
  ["URL", (candidate: typeof vector) => {
    candidate.paymentRequiredOutcome.paymentRequired.resource.url = "https://attacker.invalid/tool";
  }],
  ["mime", (candidate: typeof vector) => {
    candidate.paymentRequiredOutcome.paymentRequired.resource.mimeType = "application/octet-stream";
  }],
  ["tool", (candidate: typeof vector) => {
    candidate.resolvedCatalog.serviceDefinitionVersion.operationId = "operation_attacker";
  }],
  ["mode", (candidate: typeof vector) => {
    candidate.resolvedCatalog.endpointDescriptorVersion.mode = "DIRECT";
  }],
  ["amount", (candidate: typeof vector) => {
    candidate.resolvedCatalog.offerVersion.amountAtomic = "100001";
  }],
  ["payout", (candidate: typeof vector) => {
    candidate.resolvedCatalog.offerVersion.payoutAddress =
      "0x2222222222222222222222222222222222222222";
  }],
] as const)("rejects %s tamper through catalog resolution while JWS remains valid", (_name, attack) => {
  const attacked = structuredClone(vector);
  attack(attacked);
  expect(
    verifyDetachedEd25519(
      attacked.paymentRequiredOutcome.paymentRequired.extensions.openant.signature,
      attacked.keys[1]!.jwk,
    ),
  ).toBe(true);
  expect(catalogAndChallengeBindingsHold(attacked)).toBe(false);
});

it.each([
  ["amount", "amountAtomic", "100001"],
  ["payout", "payoutAddress", "0x2222222222222222222222222222222222222222"],
  ["SKU", "skuVersionDigest", `sha256:${"45".repeat(32)}`],
  ["request", "requestDigest", `sha256:${"67".repeat(32)}`],
  ["nonce", "nonce", "challenge_nonce_2026_08_13_attacker"],
  ["expiry", "expiresAt", "2098-12-30T23:59:59Z"],
  ["Listing digest", "listingMandateDigest", `sha256:${"99".repeat(32)}`],
] as const)("binds %s into OPENANT_X402_EXTENSION", (_name, field, changed) => {
  const extension = vector.paymentRequiredOutcome.paymentRequired.extensions.openant;
  const attacked = { ...withoutSignature(extension), [field]: changed } as JsonValue;
  expect(digestStructured("OPENANT_X402_EXTENSION", attacked)).not.toBe(
    extension.signature.signedObjectDigest,
  );
});

it("binds Listing SKU, seller, signer, window, and authorized Challenge key", () => {
  const listing = vector.listingMandate;
  const extension = vector.paymentRequiredOutcome.paymentRequired.extensions.openant;
  const listedChallengeKeys = listing.authorizedChallengeIssuers as readonly {
    issuer: string;
    keyId: string;
  }[];
  expect(listing.sellerIdentityRef).toBe(listing.signature.issuer);
  expect(listing.serviceSkuId).toBe(extension.serviceSkuId);
  expect(listing.skuVersionDigest).toBe(extension.skuVersionDigest);
  expect(listing.signature.signedObjectDigest).toBe(extension.listingMandateDigest);
  expect(listedChallengeKeys).toContainEqual({
    issuer: extension.signature.issuer,
    keyId: extension.signature.keyId,
  });
  expect(Date.parse(extension.issuedAt as string)).toBeGreaterThanOrEqual(
    Date.parse(listing.validFrom as string),
  );
  // Adapter policy is separate from selecting ValidFrom as the signature lifecycle field.
  expect(Date.parse(extension.expiresAt as string)).toBeLessThanOrEqual(
    Date.parse(listing.validUntil as string),
  );
});

it.each([
  ["amount", "amount", "100001"],
  ["payout", "payTo", "0x2222222222222222222222222222222222222222"],
] as const)("binds standard x402 %s back to signed payment terms", (_name, field, changed) => {
  const acceptance = vector.paymentRequiredOutcome.paymentRequired.accepts[0]! as Record<
    string,
    JsonValue
  >;
  const extension = vector.paymentRequiredOutcome.paymentRequired.extensions.openant;
  expect(digestStructured("PAYMENT_TERMS", { ...acceptance, [field]: changed })).not.toBe(
    extension.paymentTermsDigest,
  );
});

it("never treats standard x402 without the signed OpenAnt extension as mandate-protected", () => {
  expect(vector.standardX402WithoutExtension.extensions).toBeUndefined();
  expect(JSON.stringify(vector.standardX402WithoutExtension)).not.toContain("MANDATE_PROTECTED");
});
