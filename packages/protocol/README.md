# @openant/commerce-protocol

Deterministic cryptographic construction helpers for OpenAnt Commerce Protocol 0.1.
This package contains no network client, key registry, policy engine, or custody logic.

## Public seam

- `canonicalizeJcs` implements RFC 8785 over strict I-JSON.
- `digestStructured` applies the public NUL-delimited profile frame and SHA-256.
- `signDigestJws` creates strict detached ES256 or Ed25519 JWS. Protocol identifiers use
  the exact public schema lexical set; ES256 is raw 64-byte low-S JOSE form.
- `buildPaymentAuthorizationTypedData` accepts WalletAuthorizationProof claim input and
  emits only the Phase 0 x402 v2 `exact` EIP-3009 `TransferWithAuthorization` object.
- `createEip712ProofEnvelope` derives `paymentAuthorizationDigest`, the complete Wallet
  receipt claims, and `claimsDigest`; a caller cannot supply either envelope digest.
- `digestWalletAuthorizationProofClaims` hashes the complete receipt preimage under the
  registered `RECEIPT_CLAIMS` profile.

## Fixed Phase 0 mapping

The EIP-712 domain is exactly `USD Coin`, version `2`, chain ID `8453`, verifying contract
`0x833589fcd6edb6e08f4c7c32d4f71b54bda02913`. The primary type is
`TransferWithAuthorization`, with only `from`, `to`, `value`, `validAfter`, `validBefore`,
and `nonce`. `validAfter` is `0`; `validBefore` is the whole-second PaymentIntent expiry;
`nonce` is the raw 32 bytes of `paymentIntentFingerprintDigest`.
At verification time, the EIP-3009 authorization interval is right-open: an observation
equal to `validBefore` is already expired.

This creates an acyclic, public chain:

```text
PaymentIntent fingerprint
  -> EIP-3009 nonce
  -> PAYMENT_AUTHORIZATION digest + wallet signature
  -> complete WalletAuthorizationProof claims
  -> RECEIPT_CLAIMS digest
```

The wallet signature proves the standard settlement authorization. It does not directly
sign the commercial receipt claims. Accordingly, the EIP-712 envelope's
`signedObjectDigest` equals `paymentAuthorizationDigest`; `claimsDigest` is independently
derived and normally differs.

Standards: RFC 8785, RFC 7515, RFC 8037, EIP-712, EIP-3009, and x402 v2 exact.
