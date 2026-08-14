# Hosted Phase 0 conformance vectors

`hosted-phase0.mjs` exports the public `VECTORS` array pinned to Commerce
Protocol `0.1.0-draft.4` and canonical digest
`0069b449f4b0f2f2ae88103219a182703498231b3e7cbe6d76cdd7e3f195ff27`.

All 53 vectors have a unique stable ID, explicit precondition, action steps,
an independently constructed normalized final state and lineage, expected
error code, observations, effects, and transition journal. The matrix covers
every Hosted commit boundary (`VERIFY`, `EXECUTE`,
`STAGE`, `SETTLE`, `DELIVER`, `ACK`) for:

- failure before commit and safe retry;
- response loss after commit and idempotent replay;
- an ordinary duplicate call;
- out-of-order execution;
- a proof binding mismatch.

Additional vectors cover Seller 5xx/timeout/schema failures, emergency Listing
revocation before and after final settlement, same-key/different-fingerprint
conflicts, signed/deadlined settlement reconciliation, proof lineage changes,
and illegal registry macros including reservation bypass. Revoked-Listing
rejection is itself an idempotent committed result.

The fixtures contain metadata and digests only. They never contain request or
response bodies, artifact bytes, credentials, or real-money capabilities.

## OpenAnt trust snapshot v1

`openant-trust-snapshot-v1.json` publishes snapshot version 2 as canonical,
byte-identical public metadata. It pins the signed Listing/Challenge/catalog corpus
at commit `f1cd81d977717986eaad741d22fc84ad1b380f70` and artifact SHA-256
`cc45f2e5d3566c3756c522d20f9eb978d086256980af59957d780eda7699996e`.
Its own immutable artifact SHA-256 is
`93215bccc6dcd11e9bb00e6f9334cfbde542faae05bfebd020b69c91b6c654f4`.

The corpus contains a verify-only root JWK, an independently signed snapshot,
previous/current Challenge-key overlap, the seller Listing verification key, a
signed ListingMandate, and immutable Definition/Offer/Endpoint/SKU roots. It has no
tenant credential and grants no Mandate/AppProof/Commerce authority. Node exercises
the HTTP cache and fault matrix; Rust independently reproduces JCS, the framed
digest, Ed25519 signature, ETag, and privacy assertions.
`openant-trust-snapshot-v1-report.json` is the downloadable deterministic
positive/negative/cache/privacy matrix for that exact coordinate.

## Signed OpenAnt x402 Challenge

`openant-x402-challenge-v1.json` is the additive draft.4 challenge/catalog resolution
corpus. It carries a complete strict immutable `ServiceDefinitionVersion` →
`OfferVersion` → `EndpointDescriptorVersion` → `ServiceSKUVersion` root plus a
`ListingMandate` and `OpenAntX402Extension`. Both signed objects have real Ed25519
detached JWS signatures. The artifact exposes verify-only JWKs with fixed `ISSUER`
roles and lifecycle windows; it contains no signing secrets.

The immutable signed literal was produced outside the repository under controlled
release custody. Repository tests independently reproduce every structured digest,
verify both signatures from public JWKs, and pin the exact artifact bytes:

```console
shasum -a 256 vectors/openant-x402-challenge-v1.json
```

The expected artifact SHA-256 is
`cc45f2e5d3566c3756c522d20f9eb978d086256980af59957d780eda7699996e`.
The conformance tests reject signed-field tampering, recompute all four catalog
digests, enforce Listing/Challenge/catalog bindings, and reject URL, media type,
operation, mode, amount, or payout mutation even while the original JWS remains valid.
The selected `ValidFrom` lifecycle field does not check the upper bound: adapters must
apply their trusted clock to `validUntil` and challenge `expiresAt` separately.
Standard x402 without `extensions.openant` cannot become `MANDATE_PROTECTED`; this
corpus also does not constitute a MandateAuthorizationProof or AppProof chain.
