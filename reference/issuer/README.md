# Reference trust snapshot publisher

`trust-snapshot.mjs` is the public, metadata-only protocol seam for the immutable
OpenAnt trust snapshot corpus. It is a reference oracle, not a production server:
`/v1/trust-snapshots/current` is a fixed reference path, not a deployed production
URL, and this directory does not claim durable monotonic-version storage.

The handler accepts only `GET`, `HEAD`, and `If-None-Match`. It has no request body,
query, tenant credential, issuer selector, rail selector, proof input, or write
operation. The canonical response bytes, strong ETag, cache policy, media type, and
content length are fixed by `vectors/openant-trust-snapshot-v1.json`.

`validateTrustSnapshot` is a fail-closed consumer oracle. It verifies canonical
bytes, the independently signed snapshot digest, a caller-pinned public trust root,
bounded freshness, expiry, monotonic version linkage, verify-only key lifecycle,
Listing signer/Challenge signer availability, and immutable catalog roots. An HTTP
200 is never sufficient authority. The result is trust metadata only; it cannot mint
a Mandate proof, AppProof, Commerce authorization, Payment Rail, or assurance label.

The only observation is a metadata event containing snapshot digest/version,
issuer/kid, cache age, stable decision/retryability, and a validated W3C trace ID.
It never records URL query, request headers, caller identity, tenant data, proof JSON,
or commerce content.

Production publisher storage, deployment routing, availability SLOs, and monotonic
publication fencing remain an integration gate outside this reference package.
