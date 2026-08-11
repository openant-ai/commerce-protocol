# State ownership and transitions

The machine-readable transition registry is `commerce.json.stateMachines`.
This document records the guards that cannot be inferred from state names.

## Listing

- `SUSPENDED_NEW` stops new challenges but permits an already verified,
  durably staged invocation to converge safely.
- `EMERGENCY_REVOKED` stops every invocation not yet settled. It is terminal;
  re-enabling the service requires a new endpoint/SKU/ListingMandate version.

## Invocation

`Invocation` is the OpenAnt commercial projection. It refers to 0xkey funding
facts but never authors `AUTHORIZED`, `CONFIRMED`, or `FINALIZED` funding facts.
Its `PAYMENT_AUTHORIZED`, `SETTLEMENT_PENDING`, `PAYMENT_UNKNOWN`, and
`DELIVERABLE` transitions require issuer evidence from the funding authority.
The machine-readable registry has mode-specific transition sets while retaining
one backward-compatible state enum.

- Hosted happy path: `EXECUTING → OUTPUT_STAGED → SETTLEMENT_PENDING →
  DELIVERABLE → DELIVERED → ACKED`.
- Direct happy path: `EXECUTING → SETTLEMENT_PENDING → ACKED`. Direct requires
  a resolved ExecutionReceipt before settlement, then final SettlementReceipt
  and an exact-content buyer AcceptanceReceipt at ACKED; it forbids Hosted
  staging, `DELIVERED`, delivery acknowledgement, and recovery-window evidence.

- `OUTPUT_STAGED` requires complete bytes, schema/media validation, size/hash
  verification, durable encrypted storage, and an `OutputStagingReceipt`.
- The staging receipt request digest equals the Invocation request. Its
  response/artifact digest, byte count, and availability window are inherited
  unchanged by DeliveryReceipt. `availableUntil` is exactly staging issuance
  plus the immutable Offer recovery duration, and remains valid at the
  ProofBundle anchor.
- `PAYMENT_UNKNOWN` is non-terminal and requires a signed
  `FundingUnknownObservation` plus `reconciliationDeadline`. The staged output
  remains inaccessible to the buyer until reconciliation proves final
  settlement.
- A known rejection before final settlement enters
  `FAILED_BEFORE_SETTLEMENT`; it does not create a rollback transaction.
- `DELIVERABLE` requires a final `SettlementReceipt` and recoverable exact
  bytes. Delivery may be retried without payment.
- `DELIVERED` and `ACKED` must resolve `deliveryReceiptDigest` to a
  DeliveryReceipt whose `deliveryState` is exactly `DELIVERED`; a
  `DELIVERABLE` receipt cannot advance either state. The same check applies to
  `RECOVERY_WINDOW_EXPIRED` whenever it retains a delivery receipt. These
  projections are Hosted-only; Direct uses an exact-content AcceptanceReceipt
  to move directly to ACKED and never carries a DeliveryReceipt.
- `ACKED` requires buyer identity and exact delivery/content digests. It starts
  the fixed deletion grace interval, not immediate deletion.
- `RECOVERY_WINDOW_EXPIRED` is the explicit terminal for a settled but
  unacknowledged Invocation after its promised retrieval window. It does not
  erase settlement evidence or masquerade as ACK.
- `FAILED_BEFORE_SETTLEMENT` cannot carry settlement, delivery, or ACK digests.
- A retained `paymentProofDigest`, including on `FAILED_BEFORE_SETTLEMENT`, is
  legal only together with the funding-ledger `paymentIntentRef` that scopes
  the proof. Failures before a PaymentIntent or authorization carry neither.
- Evidence fields are state-closed: a CREATED or PAYMENT_REQUIRED snapshot
  cannot carry authorization, staging, settlement, delivery, or ACK evidence;
  each later digest first becomes legal at the state whose transition produced
  it. `RECOVERY_WINDOW_EXPIRED` may retain delivery evidence only when it
  converged from DELIVERED.

## PaymentIntent

`PaymentIntent` is the 0xkey funding projection. OpenAnt may observe its signed
references but cannot transition it.

- `transitions` is the union registry, not an authorization bypass. Each entry
  in `authorizationProfileTransitions` is a complete executable transition
  table for that profile. A validator must select exactly one table using
  `requestedAssurance.authorization`; a missing selector, unknown profile, or
  edge absent from the selected profile fails closed. `MANDATE_PROTECTED`
  enters `RESERVED` before `AUTHORIZING`. `WALLET_SIGNED` enters
  `AUTHORIZING` directly and is forbidden from carrying `reservationId`.
- Reserved budget exists only for `MANDATE_PROTECTED` and is consumed only by
  `FINALIZED` settlement. `WALLET_SIGNED` binds the same idempotency,
  authorization, settlement, and reconciliation lineage without pretending an
  external wallet has a 0xkey Treasury reservation.
- `AUTHORIZATION_UNKNOWN` and `SETTLEMENT_UNKNOWN` retain the reservation when
  one exists, and always require an explicit reconciliation deadline and
  signed unknown-observation proof.
- The resolved observation MUST match the PaymentIntent's exact state,
  reconciliation deadline, and derived boundary (`authorization` for
  `AUTHORIZATION_UNKNOWN`, `settlement` for `SETTLEMENT_UNKNOWN`), in addition
  to ledger authority, fingerprint, Invocation, SKU, reservation, and any
  authorization digest.
- Wall-clock expiry alone cannot transition UNKNOWN to a failure or release
  budget. Reconciliation must prove that no authorization or settlement can
  still succeed.
- `FINALIZED` is irreversible. Refunds are separate seller-authorized payment
  operations.
- For `MANDATE_PROTECTED`, a known failure while `AUTHORIZING` converges to
  `DENIED` only after the reservation is released. `WALLET_SIGNED` has no
  reservation to release. An issued authorization can converge to
  `AUTHORIZATION_EXPIRED` only after expiry and proof that its nonce remains
  unused.
- `CONFIRMED` is not final: a pre-finality reorganization returns it to
  `SETTLEMENT_UNKNOWN`. Reconciliation may find confirmation, prove rejection,
  or safely rebroadcast the same authorization; it may not create a second
  authorization.
- A CREATED PaymentIntent carries no reservation, authorization, UNKNOWN, or
  settlement evidence. `SETTLEMENT_REJECTED` retains its authorization lineage
  and any profile-applicable reservation, while only `FINALIZED` may carry a
  final settlement receipt digest.

## A2A

The `CommerceOperation` envelope can carry a TASK reference, but Commerce 0.1
does not merge A2A with the A2MCP Invocation state machine. A2A continues to use
its independent escrow state machine and shares only immutable mandate, budget,
amount, correlation, and proof-envelope semantics.
