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
