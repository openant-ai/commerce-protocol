# OpenAnt Commerce Protocol 0.1 — Interface Contract

Status: draft implementation contract for OpenAnt **OnChain** only.

## Interface and seam

The public Interface is `spec/commerce.json` plus
`schemas/commerce-0.1.schema.json`. HTTP, OpenAPI, MCP, CLI, Skill, OpenAnt,
and 0xkey implementations are adapters at that seam. They may not add a
second interpretation of amount, state, expiry, issuer, or error semantics.

The Interface is deliberately transport-neutral. It defines immutable
commercial references, funding references, state observations, and proof
manifests. It does not define an OpenAnt database, a 0xkey Budget Ledger, a
Gateway implementation, seller business logic, or deployment configuration.

## Operation-kind applicability

`operationKindApplicability` is the machine-readable authority that prevents
OpenAPI, MCP, CLI, Skill, and SDK adapters from inventing different defaults.
For `INVOCATION`, the adapter must resolve the immutable SKU children,
seller-signed ListingMandate, and Invocation. Fixed per-success pricing comes
from `OfferVersion`, chargeable success comes from
`ServiceDefinitionVersion`, and the two authority-owned projections are the
OpenAnt `invocation` state machine and 0xkey `paymentIntent` state machine.
Settlement is buyer-to-seller A2MCP x402. RuntimeCapability is conditional on
`authorization=MANDATE_PROTECTED`; a low-risk external wallet may instead use
`WALLET_SIGNED` and `ANONYMOUS_WALLET` evidence from `assuranceRequirements`.
Its buyer actor is the self-certifying identifier
`wallet_eip155_8453_<lowercase payer address without 0x>`; it cannot borrow an
OpenAnt account or delegated Agent identity without that identity profile.
Standard x402 without a signed OpenAnt extension remains outside the complete
CommerceOperation catalog.

`TASK` is only the shared A2A envelope in this revision. Its authority and
commercial terms come from signed `TaskAgreementVersion`; funds may enter only
the external A2A escrow contract. A2MCP pricing and chargeable-success are not
applicable, while A2A value and limits remain in the agreement plus its future
published adapter. The registry therefore names an external state machine,
error registry, limit source, and escrow funding model instead of exposing a
`null` that consumers could reinterpret. A consumer must not invent an
Invocation or PaymentIntent default for TASK.

## Ownership and non-duplication

- OpenAnt is authoritative for SKU, Listing, Invocation, output staging,
  delivery, acknowledgement, reputation, and disputes.
- 0xkey is authoritative for Treasury, PaymentMandate, RuntimeCapability,
  Budget Reservation, authorization, settlement, and funding proof.
- An adapter records the other authority's immutable identifier, digest, and
  issuer evidence. It never promotes an observation into a locally authored
  fact.
- A `PaymentIntent` is metadata-only. Raw prompt, tool arguments, request body,
  response body, artifact bytes, credentials, cookies, and private keys are
  forbidden.

## SKU version root

`ServiceSKUVersion` is the immutable combination root of exactly three
independently versioned objects:

1. `ServiceDefinitionVersion`: schema, media type, chargeable success, and
   execution/content limits.
2. `OfferVersion`: fixed atomic amount, Base native USDC, payout, refund, and
   recovery terms.
3. `EndpointDescriptorVersion`: Hosted/Direct mode, endpoint, challenge key,
   and role-separated execution, staging/custody, delivery, and commerce issuer
   key sets.

Changing any child produces a new child digest, SKU root digest, and
seller-signed `ListingMandate`. OpenAnt cannot mutate price, payout, endpoint,
key, schema, or success semantics in place.

Verification resolves the SKU root and recomputes all four canonical digests:
the ServiceSKUVersion root plus its ServiceDefinitionVersion, OfferVersion,
and EndpointDescriptorVersion children. The Listing seller must equal the SKU
seller, and the SKU operation must equal the Definition operation. Digest
labels or repeated identity fields are never accepted without those checks.

The resolved Endpoint mode and Offer minimum assurance must also describe a
Phase 0 path that actually exists. `DIRECT` requires
`delivery=DIRECT_BUYER_ACCEPTED` and `contentCustody=DIRECT`. `HOSTED` requires
`delivery=HOSTED_RECOVERABLE` and either `HOSTED_EPHEMERAL` or
`HOSTED_ENCRYPTED_BUFFER` custody, together with the Endpoint's Hosted staging
and delivery roles. `NONE` and `SELLER_ASSERTED` remain assurance vocabulary
for later profiles, but are not legal Phase 0 SKU minimums. This compatibility
check occurs after canonical child resolution and before challenge issuance.

## Phase 0 invocation semantics

Phase 0 is one fixed-price, successful, bounded unary call on Base native USDC.
The Hosted commit order is:

```text
verify → execute → validate and durably buffer exact bytes → settle → deliver
```

An artifact manifest or remote URL does not prove byte possession. Hosted
settlement requires an `OutputStagingReceipt` whose artifact digest and byte
count match the manifest after the bytes enter encrypted content escrow.

`DELIVERABLE` means final settlement evidence exists and exact bytes remain
retrievable. `DELIVERED` means those bytes were sent. `ACKED` requires a signed
or authenticated `DeliveryAcknowledgement` binding buyer actor, Invocation,
delivery digest, exact response/artifact digest, and receipt time. ACK proves
technical receipt, not subjective quality.

Evidence chronology is mode-dependent and inclusive. Hosted requires
authorization proof issuance ≤ staging issuance ≤ settlement issuance ≤
delivery issuance ≤ acknowledgement receipt. Direct requires authorization
proof issuance ≤ execution receipt issuance ≤ settlement issuance ≤ buyer
acceptance issuance. `DIRECT_BUYER_ACCEPTED` therefore composes both
ExecutionReceipt and AcceptanceReceipt. A valid settlement signature cannot
make output evidence timestamped after settlement chargeable.

The acknowledgement `buyerActorRef` MUST equal both the independently verified
attestation issuer and the resolved Invocation `buyerActorRef`; an arbitrary
self-signed actor cannot acknowledge delivery on the Buyer's behalf.

A Direct `AcceptanceReceipt` applies the same rule: its `buyerActorRef` MUST
equal the independently verified receipt signature issuer and the resolved
Invocation buyer actor. Every PaymentIntent `buyerActorRef` is scoped to that
Invocation buyer. For `MANDATE_PROTECTED`, `agentId` is also equal to that
buyer actor; `WALLET_SIGNED` has no Agent field and instead derives the buyer
actor from the payer address. Acceptance additionally inherits the exact
Invocation, SKU, single content kind, response or artifact-manifest digest,
and byte count from the resolved ExecutionReceipt; an acceptance for different
bytes cannot complete the Direct Invocation.

Direct does not manufacture Hosted custody evidence. Its Invocation records a
resolved `executionReceiptDigest` before settlement and an
`acceptanceReceiptDigest` at ACKED; `outputStagingReceiptDigest`,
`deliveryReceiptDigest`, `acknowledgementDigest`, `OUTPUT_STAGED`,
`DELIVERABLE`, `DELIVERED`, and `RECOVERY_WINDOW_EXPIRED` are Hosted-only.
Direct converges from `SETTLEMENT_PENDING` (or reconciled `PAYMENT_UNKNOWN`)
straight to `ACKED` only when final settlement plus exact buyer acceptance are
verified. Both modes retain the same state enum for wire compatibility, with
separate transition registries and schema evidence guards.

Acknowledgement content is resolved, not self-asserted. For `RESPONSE`, the
received digest MUST equal the resolved DeliveryReceipt `responseDigest`. For
`ARTIFACT`, the acknowledgement MUST reference an ArtifactManifest whose
canonical digest equals the resolved DeliveryReceipt manifest reference, and
the received digest MUST equal that resolved manifest's `contentDigest`.

`PAYMENT_UNKNOWN` is valid only with a 0xkey-issued
`FundingUnknownObservation` digest and an explicit `reconciliationDeadline`.
The deadline schedules escalation; it does not prove failure. A
`FAILED_BEFORE_SETTLEMENT` Invocation is schema-forbidden from carrying a
settlement, delivery, or acknowledgement digest. If the promised unacknowledged
recovery period ends without ACK, the commercial state converges to the
explicit terminal `RECOVERY_WINDOW_EXPIRED` while preserving the final payment
evidence.

## x402 compatibility

A standard x402 v2 `PaymentRequired` remains usable by any compatible wallet.
Only a challenge with a valid, signed `extensions.openant` object enters the
complete ListingMandate, PaymentMandate, atomic budget, and ProofBundle path.
The extension binds the standard payment terms digest, immutable SKU root,
ListingMandate, Invocation, request hash, issuer, nonce, expiry, and assurance.

Phase 0 full-assurance challenges contain one `exact` acceptance for Base
native USDC. Supporting a standard challenge does not imply that the wallet or
facilitator provides 0xkey Mandate protection.

The signed OpenAnt extension is the only Invocation identity inside
`PaymentRequiredOutcome`; the outcome deliberately has no unsigned duplicate
`invocationId`. Amount, asset, and payout in the selected x402 acceptance must
equal the signed extension values. A ListingMandate is valid only when
`sellerIdentityRef` equals `signature.issuer`. These cross-object constraints
are machine-readable in `spec/commerce.json.crossObjectBindings`.

The resolved Invocation MUST equal the signed extension on `invocationId`,
`operationId`, `serviceSkuId`, `skuVersionDigest`, `requestDigest`, and `mode`.
Matching only Invocation ID and SKU does not authorize a different operation,
request payload, or execution mode.

The signed challenge is a projection of the resolved immutable roots. Its SKU
identity/root and operation come from ServiceSKUVersion/ServiceDefinitionVersion;
amount, asset, payout, and full assurance vector come from OfferVersion; mode,
resource URL, and challenge issuer/key come from EndpointDescriptorVersion.
Resource media type comes from the Definition. A gateway
authorized by the Listing cannot choose different terms, even if it re-signs
the challenge and changes the PaymentIntent and authorization proof in lockstep.

The Invocation independently resolves the same SKU root. Its Service SKU,
operation, and mode must equal the SKU, Definition, and Endpoint roots before
execution.

The extension signer `(issuer, keyId)` MUST be an exact member of the resolved
ListingMandate's `authorizedChallengeIssuers`. The resolved mandate digest,
SKU identity/root, and Seller identity MUST also equal the signed extension;
a valid signature from any other issuer is not challenge authority. Challenge
issuance MUST be no earlier than the resolved ListingMandate `validFrom`, and
challenge expiry MUST be no later than `validUntil`; equality at either instant
is valid. A ListingMandate is intrinsically valid only when
`validFrom <= validUntil`.

A PaymentIntent is derived from the independently verified signed extension,
not from caller-supplied duplicate terms. Its challenge digest, Invocation,
SKU, Seller, payout, asset, amount, mode, all assurance dimensions, and expiry
MUST equal that extension. This comparison is required even when an
authorization proof was changed in lockstep with the PaymentIntent.

## Integer and time rules

- Monetary values are base-unit unsigned decimal strings; JSON numbers,
  signs, decimals, exponent notation, and leading zeroes are invalid.
- `uint256-decimal` is an assertion format: values must be in
  `[0, 2^256 - 1]`. Implementations MUST enforce it even where a generic JSON
  Schema library treats `format` as annotation.
- Protocol timestamps are real UTC Gregorian RFC 3339 values with whole
  seconds, not merely strings matching a date-shaped regular expression. A challenge
  with `expiresAt <= now` fails with `CHALLENGE_EXPIRED` before signing.
- An UNKNOWN funding state always includes `reconciliationDeadline`. Deadline
  expiry triggers escalation/reconciliation; it never proves failure and never
  releases reserved budget by itself.

## Idempotency and fingerprint

The idempotency fingerprint always binds funding-ledger namespace and all
role-specific authority keys, Invocation, buyer actor, challenge, SKU root,
seller, payer, payout, network, asset, amount, Hosted/Direct mode, all five
requested assurance dimensions, facilitator, and expiry. For
`MANDATE_PROTECTED` it additionally binds tenant, Member SubOrg, Treasury
profile/ref, agent, runtime and exact Runtime Capability digest, and Mandate
ID/version. Those delegated fields are absent—not null—for `WALLET_SIGNED`.
Reusing an idempotency key with a different profile-selected fingerprint fails
with `IDEMPOTENCY_FINGERPRINT_CONFLICT`. A replay with the same fingerprint
returns or resolves the existing intent and cannot create a second
authorization.

`PaymentIntent` has two authorization profiles selected by
`requestedAssurance.authorization`. `MANDATE_PROTECTED` requires tenant,
member SubOrg, Treasury, Agent, runtime, RuntimeCapability, Mandate, and atomic
reservation context. `WALLET_SIGNED` forbids those fields and the `RESERVED`
state; it uses a self-certifying wallet buyer actor and proceeds from `CREATED`
to `AUTHORIZING`. Both profiles share the same immutable challenge, SKU,
amount, payer/payee, EIP-3009 authorization, settlement, and UNKNOWN lineage.
`NONE` is not a valid paid PaymentIntent authorization profile.

`PaymentIntent` declares three role-separated verification authorities:
`fundingAuthority` for the selected Mandate or wallet authorization,
`settlementAuthority` for final settlement evidence, and
`observationAuthority` for signed UNKNOWN observations.
Their issuer/key pairs and the ledger namespace are part of the fingerprint;
an equally shaped proof from another ledger or role is not interchangeable.
The fingerprint always includes common commerce and settlement context, then
adds tenant/Treasury/Mandate/Agent/runtime fields only for
`MANDATE_PROTECTED`; absent profile fields are never serialized as null or
silently omitted from a supposedly mandate-protected fingerprint.

## Proof composition and assurance

`ProofBundle` is a manifest of issuer-specific, privately held objects. It is
not a new super-signature. Each entry identifies object type, issuer, key,
digest, issuance time, and disclosure state. The holder can disclose objects
for public verification without requiring the transaction to be publicly
indexed.

Each proof reference also carries the Bundle's Invocation and SKU context.
Verification MUST resolve every referenced object and compare its object type,
verified signer issuer/key, canonical digest, issuance time, Invocation, and
SKU with both the reference and Bundle. A manifest cannot relabel a proof or
replay evidence from another Invocation or SKU.

Funding evidence has one additional lineage invariant. Every resolved Mandate
or Wallet authorization proof, SettlementReceipt, FundingUnknownObservation,
and the SettlementReceipt behind a CommerceReceipt must share the
`paymentIntentId`, PaymentIntent fingerprint, and authorization digest when
present, and that PaymentIntent must be the resolved Invocation
`paymentIntentRef`. Sharing only Invocation and SKU cannot compose
authorization A with settlement B.

The Bundle creation time is greater than or equal to every reference and
resolved proof issuance time; equality is valid. Every proof-like digest on an
Invocation or PaymentIntent resolves to an allowed concrete receipt type and
matches its claims digest, Invocation, SKU, and PaymentIntent where applicable.
Digest equality without these scope checks is insufficient.

Assurance is a vector with independent `authorization`, `settlement`,
`delivery`, `contentCustody`, and `identity` dimensions. Implementations must
not collapse it into a total score. A settlement receipt proves payment only;
Hosted delivery evidence or Direct buyer acceptance is required for fulfillment
reputation.

Every asserted assurance dimension has its own mandatory proof set. In
particular, `HOSTED_ENCRYPTED_BUFFER` requires an `OutputStagingReceipt`, and
`VERIFIED_SELLER` requires both the seller `ListingMandate` and a
`SellerIdentityCredential`. A ProofBundle that lacks any proof for a claimed
dimension is schema-invalid and resolves as `PROOF_INCOMPLETE`.

Receipt schemas are closed per issuer fact. A SettlementReceipt cannot carry
response, delivery, buyer-acceptance, or content-custody claims. A
`MandateAuthorizationProof` must bind the exact Mandate ID/version, runtime
capability digest, reservation, challenge, SKU, payment authorization, decision
code, amount, parties, and expiry. It additionally carries the PaymentIntent
fingerprint and every funding-context field needed to compare the proof with
the resolved PaymentIntent. Only the literal decision `APPROVED` is positive
Mandate evidence; a denial or unknown result cannot satisfy
`MANDATE_PROTECTED` assurance.

`WALLET_SIGNED` is equally closed, but makes a narrower cryptographic claim:
the wallet signs the standard x402 v2 `exact` EIP-3009
`TransferWithAuthorization`, not the surrounding commercial receipt. Phase 0
fixes its EIP-712 domain to Base mainnet USDC (`USD Coin`, version `2`, chain
8453, contract `0x833589fcd6edb6e08f4c7c32d4f71b54bda02913`) and closes the
type to `from`, `to`, `value`, `validAfter`, `validBefore`, and `nonce` only.
`from`, `to`, and `value` come from the resolved PaymentIntent;
`validAfter` is `0`; `validBefore` is its whole-second expiry; and `nonce` is
the raw 32 bytes of `PaymentIntent.fingerprintDigest`. Because that fingerprint
already covers challenge, SKU, mandate, mode, assurance, tenant, Agent, and
Runtime context, the authorization is indirectly bound to those immutable
terms without renaming a proprietary commercial signature as EIP-3009.

The WalletAuthorizationProof independently hashes its complete claims,
including `paymentAuthorizationDigest`, under `RECEIPT_CLAIMS`. Its
`claimsDigest` therefore does not equal the EIP-712
`signature.signedObjectDigest`; the latter equals the recomputed
`PAYMENT_AUTHORIZATION` digest. Neither digest is caller-authoritative. The
buyer actor and envelope issuer MUST equal the PaymentIntent/Invocation buyer,
and the recovered EIP-712 signer address MUST equal the PaymentIntent payer.

OutputStagingReceipt, ExecutionReceipt, DeliveryReceipt, and CommerceReceipt
consume `stagingIssuerKeys`, `executionIssuerKeys`, `deliveryIssuerKeys`, and
`commerceIssuerKeys` respectively. Execution and commerce keys are disjoint
from Hosted custody/delivery roles; staging and delivery may share one Hosted
gateway key. A receipt whose issuer fields and signature are mutually
consistent but whose key is not authorized for that exact role is invalid.
Staging and delivery keys must additionally be members of verifier-local
trusted Hosted custody keys, so a Seller cannot grant itself Hosted guarantees
by placing its execution key in an EndpointDescriptor. A SellerIdentityCredential likewise
must resolve to the same seller subject as the ListingMandate in its Bundle,
and its issuer/key must be in verifier-local trusted identity keys. That trust
policy cannot be supplied by the Seller or ProofBundle. The credential is
intrinsically valid only when `issuedAt <= expiresAt`, and `VERIFIED_SELLER` is
evaluated at `ProofBundle.createdAt`, which must be inside that closed interval.

OutputStagingReceipt, ExecutionReceipt, and CommerceReceipt request digests
must equal the resolved Invocation request digest. Hosted staging and delivery
receipts must preserve one content lineage: Invocation, SKU, response or
artifact-manifest digest, byte count, and `availableUntil` all match.
CommerceReceipt resolves its SettlementReceipt by concrete type/digest and
Invocation/SKU scope, and its signer must be an EndpointDescriptorVersion
`commerceIssuerKeys` member.

Signed time intervals are closed and intrinsic except for the EIP-3009 wallet
authorization: extension `issuedAt <= expiresAt`, PaymentIntent `createdAt <=
expiresAt`, WalletAuthorizationProof `issuedAt < expiresAt`, TaskAgreementVersion
`validFrom <= validUntil`, and staging/delivery `issuedAt <= availableUntil`.
A delivery acknowledgement is
accepted only from delivery issuance through availability, inclusive.
PaymentIntent creation must also fall inside the resolved signed challenge
interval. Mandate proof issuance may equal the resolved PaymentIntent expiry;
WalletAuthorizationProof issuance must fall in the half-open PaymentIntent
interval.

Live WalletAuthorizationProof verification uses the verifier-owned current
time and accepts only `[issuedAt, expiresAt)`, matching EIP-3009's exclusive
`validBefore` contract check. Public verification APIs do not accept a caller
time override. Historical verification is unsupported until a verifiable TSA
or transparency-log evidence profile is registered.

For Hosted recovery, `availableUntil` is derived exactly from staging
`issuedAt + OfferVersion.deliveryTerms.unacknowledgedRecoverySeconds`;
DeliveryReceipt inherits it. Invocation creation precedes staging, and the
ProofBundle anchor must be between delivery issuance and that availability
instant. An arbitrary later recovery timestamp is not gateway authority.

TaskAgreementVersion, RuntimeCapability, and SellerIdentityCredential are
strict local schema objects in this interface. Their digest profiles name
those exact schemas, so an adapter cannot choose a different opaque claim set
for the same digest label. A PaymentIntent's resolved RuntimeCapability also
matches its funding authority, runtime, agent/buyer, Mandate, SKU, and validity
interval; digest equality alone is not capability authority.

Mandate authorization issuance is valid only when `issuedAt <= expiresAt`.
A ProofBundle may be created only at or after every correlated proof issuance
instant. Both comparisons are inclusive: equality at the boundary is valid.

For every ReceiptEnvelope, the claimed issuer and key MUST equal the verified
signature issuer and key. Detached-JWS and AppProof receipts additionally
require `claimsDigest == signature.signedObjectDigest`. The schema-fixed
EIP-712 WalletAuthorizationProof instead requires
`paymentAuthorizationDigest == signature.signedObjectDigest` and independently
recomputes `claimsDigest` under `RECEIPT_CLAIMS`. Settlement and UNKNOWN
receipts additionally bind the resolved PaymentIntent fingerprint, ledger
namespace, Invocation, SKU, role-specific authority, and their state-specific
funding fields. A `FundingUnknownObservation` carries the authorization profile
it observed: `MANDATE_PROTECTED` requires the reservation lineage, while
`WALLET_SIGNED` forbids a reservation. Both profiles bind the exact observed
state, derived boundary, and reconciliation deadline.

## Digest preimages

`spec/commerce.json.digestProfiles` is the sole digest registry. Every
`*Digest` field maps to a named profile with an exact input, exclusion or
include-only projection, domain-separated framing, and output field. Structured
profiles use RFC 8785 JCS; byte profiles hash a domain frame, uint64 big-endian
length, and the exact staged/delivered octets. Implementations must not hash a
whole object and then silently add or remove fields. Cryptographic
implementation and cross-language vectors remain the separate M0 signing work,
but they must implement these frozen preimages.

`PAYMENT_AUTHORIZATION` is not an extensible OpenAnt typed-data message. Its
only Phase 0 preimage is the complete, closed Base USDC EIP-3009 TypedData
described above. Commercial context remains in the public PaymentIntent
fingerprint and receipt profiles; no private digest profile participates in
this chain.

## Error and observation contract

Every rejection returns a stable `code`, fixed `retryable` value, failure
`boundary`, safe `reason`, and correlation context. `invocationId`,
`paymentIntentId`, `requestId`, and `traceId` belong in structured logs/traces,
not metric labels. Protocol messages and business events contain hashes and
metadata only; runtime telemetry must never copy raw business content.

The authoritative state/error registries live in `spec/commerce.json`.
Adapters reject transitions absent from that registry with
`ILLEGAL_STATE_TRANSITION`. They also reject unknown fields and unknown
mandatory protocol versions rather than guessing.

## Digest

The draft source digest covers the exact ordered JSON files listed in
`spec/commerce.json`. `schemas/tests/digest.test.cjs` canonicalizes each JSON
document, applies the documented filename framing, and compares the SHA-256
digest with `schemas/tests/expected-digest.txt`. This draft digest proves source
reproducibility, not the RFC 8785/signature profile, which is a separate M0
cryptography work item.

`digestProfiles.pathBindings` assigns every schema `*Digest` path exactly one
profile or one explicit selector. A DeliveryAcknowledgement carries
`contentKind`; `RESPONSE` selects `RESPONSE_BYTES` and `ARTIFACT` selects
`ARTIFACT_BYTES`, so identical bytes cannot be interpreted under two domain
frames.
