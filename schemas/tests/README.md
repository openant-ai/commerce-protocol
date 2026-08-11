# Schema verification

The tests require Node.js 20+ and Ajv 8 with JSON Schema 2020 support. Until
the independent public repository package manifest is created by the M0 release
work, run against an existing Ajv 8 installation by setting `NODE_PATH`:

```bash
cd repos/commerce-protocol
NODE_PATH=../services/x402-gateway/node_modules/.pnpm/ajv@8.17.1/node_modules \
  node --test schemas/tests/*.test.cjs
```

The suite verifies:

- every public object reference compiles;
- positive domain/payment/proof examples;
- unknown fields, amount overflow, missing signed UNKNOWN observation/deadline,
  missing buyer ACK identity, impossible calendar dates, zero payout, and
  artifact limit rejection;
- closed per-type receipts, including rejection of settlement receipts carrying
  delivery, response, buyer, or content-custody claims;
- failure-state proof exclusion, signed Listing seller binding, and removal of
  the unsigned duplicate PaymentRequired Invocation identity;
- mandatory authorization, settlement, delivery, custody, and identity proofs
  for every claimed assurance dimension;
- expired challenge, idempotency fingerprint conflict, illegal transition,
  x402/extension terms mismatch, and incomplete multi-issuer proof semantics;
- authorization known-failure/expiry and confirmed-reorg convergence, plus the
  explicit Invocation recovery-window terminal;
- complete MandateAuthorizationProof bindings and exact digest-profile coverage;
- claimed receipt issuer/key/digest equality with the verified signer, Buyer
  acknowledgement signer binding, and role-separated funding authorities;
- resolved ProofBundle reference/object issuer, digest, Invocation, and SKU
  correlation, including cross-ledger and value-swap attacks;
- inclusive proof-time ordering and concrete nine-receipt signature digest
  selector completeness;
- signed x402 challenge to PaymentIntent term equality, including lockstep
  PaymentIntent/Mandate-proof mutation attacks;
- complete WalletAuthorizationProof bindings and buyer actor anchoring for
  wallet, acknowledgement, and Direct acceptance evidence;
- Invocation/PaymentIntent evidence digest resolution to an allowed concrete
  receipt type with Invocation, SKU, and PaymentIntent correlation;
- role-separated execution, staging/custody, delivery, and commerce signer
  membership in resolved endpoint keys, verifier-local Hosted custody trust,
  and SellerIdentityCredential subject equality with the ListingMandate;
- strict local preimage schemas for TaskAgreementVersion, RuntimeCapability,
  and SellerIdentityCredential;
- canonical SKU root/child resolution plus Listing seller and Definition
  operation correlation, including the Phase 0 Endpoint mode/Offer assurance
  compatibility matrix;
- immutable Definition/Offer/Endpoint projections into signed challenge and
  Invocation, including lockstep gateway/PaymentIntent/proof attacks;
- Invocation request correlation for staging, execution, and commerce
  receipts, Hosted staging/delivery content lineage, and independently
  authorized CommerceReceipt settlement evidence;
- intrinsic signed-object time intervals and Offer-derived Hosted recovery
  availability at Invocation, ProofBundle, Delivery, and ACK anchors;
- mode-aware authorization/output/staging/settlement/delivery chronology and
  rejection of DELIVERED/ACKED projections backed by DELIVERABLE receipts;
- single PaymentIntent ID/fingerprint/authorization lineage across every
  funding proof and CommerceReceipt settlement chain, including A/B mix-and-
  match attacks;
- reachable mode-specific Invocation paths using the existing state enum:
  Hosted staging/delivery/ACK versus Direct execution/settlement/exact-content
  acceptance directly to ACKED, with no Direct DELIVERED projection;
- PaymentIntent fingerprint coverage for ledger namespace, authority keys,
  exact Runtime Capability, and payer;
- path-unique digest profiles, explicit RESPONSE/ARTIFACT acknowledgement kind,
  and rejection of dual-domain content evidence;
- state-closed evidence fields for Invocation and PaymentIntent snapshots;
- error registry and state registry consistency;
- byte-for-byte reproducible draft source digest.

`uint256-decimal` is registered as an assertion format so an overflow cannot
pass through a JSON Schema implementation that treats custom formats as mere
annotations.
