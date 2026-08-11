# Hosted Phase 0 in-memory reference flow

This directory is an executable protocol oracle, not a production architecture
and not a payment implementation. Every state snapshot carries
`capabilities.realMoney = false` and `REFERENCE_ONLY_NO_REAL_FUNDS`.

The reference flow models four in-memory protocol roles:

- Catalog: immutable SKU digest, Listing state, and OpenAnt issuer reference;
- HostedInvocation and content escrow: commercial state plus response digest,
  byte count, and buffered/not-buffered metadata (never output bytes);
- Payment Adapter: 0xkey-owned PaymentIntent state, authority issuer/key
  references, and immutable payment/observation/settlement digests;
- Seller Adapter: deterministic success, 5xx, timeout, and schema-failure
  outcomes behind an idempotent execution boundary.

The two state projections do not copy one another's ledger. Invocation retains
only the PaymentIntent reference and funding evidence digests. PaymentIntent
retains only the Invocation reference, SKU digest, fingerprint, role-separated
authority references, and funding evidence.

The commit sequence is:

```text
VERIFY -> EXECUTE -> STAGE -> SETTLE -> DELIVER -> ACK
```

Each step is fail-closed, state-guarded, proof-bound, and idempotent. Fault
injection distinguishes timeout before commit from response loss after commit.
`SETTLEMENT_UNKNOWN` requires both a reconciliation deadline and the digest of
a signed 0xkey observation; deadline expiry alone never changes the state.

`VERIFY` binds its mock funding proof digest to the scenario Invocation, SKU
root, PaymentIntent fingerprint, and funding authority issuer/key. Its atomic
macro is validated against the authoritative draft.4 transition registry:
Invocation follows `CREATED -> PAYMENT_REQUIRED -> PAYMENT_AUTHORIZED`, while
PaymentIntent follows `CREATED -> RESERVED -> AUTHORIZING -> AUTHORIZED`.
The PaymentIntent path selects the explicit `MANDATE_PROTECTED` authorization
profile; a missing or unknown profile fails closed. `EXECUTE`, `STAGE`,
`SETTLE`, `DELIVER`, and `ACK` each use a canonical boundary proof binding the
boundary name, Invocation, immutable SKU version, PaymentIntent fingerprint,
and authorization profile.
Every action emits only a transition count and trace digest. The final state
contains a journal count/digest, so the four-field conformance report's
`stateDigest` also commits to the complete, metadata-only transition history.

Public seams:

- `runScenario` in `index.mjs` for in-process protocol tests;
- `adapter-cli.mjs` for one-shot process isolation. It reads one
  `{command:"runVector", scenario}` object on stdin and emits one normalized,
  metadata-only result.

Run the scoped tests without changing workspace package metadata:

```sh
node --test reference/*.test.mjs vectors/*.test.mjs tools/conformance/*.test.mjs
node tools/conformance/cli.mjs
```
