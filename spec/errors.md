# Stable error semantics

The error registry in `spec/commerce.json` fixes each code's retryability and
failure seam. Human-readable messages may change; callers branch only on code.

- A retryable error means that retrying after its documented precondition can
  succeed. It never authorizes blind replay with a new idempotency key.
- `CHALLENGE_EXPIRED` requires obtaining a newly signed challenge.
- `RESERVATION_CONFLICT` requires resolving the existing PaymentIntent before
  retrying.
- `AUTHORIZATION_UNKNOWN` and `SETTLEMENT_UNKNOWN` require `resolve`; they do
  not permit a new authorization and do not release budget.
- `PAYMENT_PATH_UNAVAILABLE` is fail-closed. An adapter may use a lower assurance
  rail only when the buyer Mandate and signed SKU challenge both permit that
  degradation, and then it creates a new, explicitly identified PaymentIntent.
- `OUTPUT_NOT_STAGED` forbids settlement. A Seller-supplied hash, URL, or HEAD
  response is not staging evidence.
- `PROOF_INCOMPLETE` prevents the requested assurance label; it must not be
  silently converted to success. Authorization, settlement, delivery, content
  custody, and identity dimensions are checked independently.
- `PROOF_BINDING_MISMATCH` is non-retryable for the presented evidence. It
  rejects a proof whose claimed issuer, key, digest, or correlated object does
  not match the independently verified signer and resolved object.

The `context` object is metadata-only and has an allowlist. It cannot contain
request/response bodies, prompts, tool arguments, tokens, cookies, credentials,
or artifact bytes.
