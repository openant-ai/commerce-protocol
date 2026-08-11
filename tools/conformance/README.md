# Commerce Protocol conformance CLI

This CLI is the public black-box seam for OpenAnt and 0xkey implementations.
An Adapter receives one canonical JSON request on stdin and returns one JSON
object on stdout. It receives vector inputs but never their expectations.

Run the complete suite against the in-memory, explicitly non-money reference
Adapter:

```sh
node tools/conformance/cli.mjs
```

Run one vector against another executable:

```sh
node tools/conformance/cli.mjs \
  --adapter /absolute/path/to/node \
  --adapter-arg /absolute/path/to/implementation-adapter.mjs \
  --vector HOSTED.HAPPY.001
```

`--adapter-arg` may be repeated. Unknown options, unknown vector IDs, Adapter
responses with `skip`/`skipped`, and every malformed or partial response fail
closed. There is no skip option.

Each stdout line contains exactly `vectorId`, `result`, `stateDigest`, and
`errorCode`. It never contains request/response content. Vector order, state
serialization, and digests are deterministic, so two runs over the same
implementation state must be byte-identical.

Passing requires an exact match to each vector's independent normalized final
state, immutable lineage, effects, observations, and transition journal. A
matching digest alone is not sufficient.
