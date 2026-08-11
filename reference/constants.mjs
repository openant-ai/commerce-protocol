import { fixtureDigest } from "./canonical.mjs";

export const PROTOCOL_VERSION = "0.1.0-draft.4";
export const PROTOCOL_DIGEST =
  "sha256:0069b449f4b0f2f2ae88103219a182703498231b3e7cbe6d76cdd7e3f195ff27";

export const REFERENCE_FIXTURE = Object.freeze({
  invocationId: "inv_hosted_reference_001",
  paymentIntentId: "pi_hosted_reference_001",
  serviceSkuId: "sku_hosted_reference_001",
  skuVersionDigest: fixtureDigest("sku-version"),
  requestDigest: fixtureDigest("request"),
  responseDigest: fixtureDigest("response"),
  paymentIntentFingerprintDigest: fixtureDigest("fingerprint-verify-1"),
  outputByteCount: "128",
  fundingAuthority: Object.freeze({
    issuer: "did:0xkey:reference-funding",
    keyId: "reference-funding-key-1",
  }),
  settlementAuthority: Object.freeze({
    issuer: "did:0xkey:reference-settlement",
    keyId: "reference-settlement-key-1",
  }),
  observationAuthority: Object.freeze({
    issuer: "did:0xkey:reference-observation",
    keyId: "reference-observation-key-1",
  }),
  catalogIssuer: "did:openant:reference-catalog",
  commercialIssuer: "did:openant:reference-commerce",
  proofs: Object.freeze(
    Object.fromEntries(
      [
        "VERIFY",
        "EXECUTE",
        "STAGE",
        "SETTLE",
        "DELIVER",
        "ACK",
        "REVOKE_LISTING",
        "SETTLEMENT_UNKNOWN",
        "RESOLVE_SETTLEMENT",
      ].map((boundary) => [boundary, fixtureDigest(`proof-${boundary.toLowerCase()}`)]),
    ),
  ),
});

export const REFERENCE_PRECONDITION = Object.freeze({
  listingState: "ACTIVE",
  invocationId: REFERENCE_FIXTURE.invocationId,
  serviceSkuId: REFERENCE_FIXTURE.serviceSkuId,
  skuVersionDigest: REFERENCE_FIXTURE.skuVersionDigest,
  authorizationAuthority: REFERENCE_FIXTURE.fundingAuthority,
  authorizationProfile: "MANDATE_PROTECTED",
  paymentIntentFingerprintDigest: REFERENCE_FIXTURE.paymentIntentFingerprintDigest,
});
