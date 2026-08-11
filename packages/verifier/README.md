# openant-commerce-verifier

Fail-closed Rust verification core for OpenAnt Commerce Protocol 0.1 proofs.

## Public seam

- `HistoricalKeyRegistry::verify_detached_jws` verifies strict detached ES256/Ed25519 JWS
  against verifier-local issuer, role, activation, expiry, and revocation metadata.
- `HistoricalKeyRegistry::from_jwks` imports public RFC 7517 keys without allowing JWKS data
  to self-assert trust roles or lifecycle windows.
- `verify_eip712_wallet` accepts only the fixed Base USDC x402 v2 exact EIP-3009
  `TransferWithAuthorization`. It derives the message from complete WalletAuthorizationProof
  claims, recomputes `PAYMENT_AUTHORIZATION`, requires both the claim and EIP-712 envelope
  digest to equal it, recovers the payer, recomputes `RECEIPT_CLAIMS`, and verifies the
  receipt's claimed `claimsDigest`.

Both public verification APIs are live-only: each invocation reads the verifier-owned
system clock internally. No public context field can inject or backdate an observation.

The wallet signature proves the standard transfer authorization, not the surrounding
commercial receipt. Commercial context is nevertheless bound through the
PaymentIntent-fingerprint-derived EIP-3009 nonce and the resolver's PaymentIntent bindings.

## Time and key lifecycle

Activation is inclusive; expiry and revocation are exclusive upper bounds. Verification
evaluates lifecycle policy at trusted observation time, never at signer-claimed `issuedAt`.
The former raw caller-supplied historical-time-anchor bypass has been removed: until a
cryptographically verifiable TSA or transparency-log proof is standardized, historical
evaluation is unsupported and fails closed. Protocol timestamps and live observations are
UTC whole seconds. Wallet authorization is valid on `[issuedAt, expiresAt)` because EIP-3009
uses an exclusive `validBefore` boundary.

Signature encodings are deliberately narrow: detached JWS uses an empty payload segment;
ES256 is raw 64-byte low-S `r || s`; EdDSA is Ed25519; EIP-712 is lowercase 65-byte
`0x`-prefixed `r,s,v` with low-S and parity 27/28.
