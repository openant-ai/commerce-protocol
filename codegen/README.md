# OpenAnt Commerce Codegen

This package is the deterministic adapter generator for the accepted OpenAnt
Commerce Protocol draft. Its external seam is one CLI:

```sh
npm --prefix codegen test
node codegen/src/cli.mjs generate
node codegen/src/cli.mjs check
node codegen/src/cli.mjs validate --input fixtures/valid/quoted-markers.yaml
```

`generate` reads only `spec/commerce.json` and the schema files named by its
canonical digest frame. It writes five adapters under `codegen/generated`:

- OpenAPI 3.1 components
- TypeScript structural types and runtime schema constants
- MCP tool declarations
- an executable CLI command skeleton
- Skill metadata

Every adapter embeds the same contract IR, protocol version, source digest,
and generator version. Required fields, errors (including retryability and
boundary), limits, permission evidence, pricing, chargeable-success schema,
and state machines are therefore rendered once rather than reinterpreted by
each adapter.

The pipeline is deliberately one-way:

```text
strict parser -> source validator -> immutable contract IR -> five renderers
```

JSON duplicate keys and YAML duplicate keys, anchors, aliases, merge keys,
non-finite numbers, and prototype-sensitive mapping keys are rejected before
digest or IR construction. Parsed mappings use null-prototype data objects;
canonical hashing independently admits only finite, plain data properties.
YAML markers inside quoted scalars remain ordinary text. The implementation
has no network or third-party runtime dependencies.

## Narrative overlay

`--descriptions <file>` accepts only `summary` and `description` strings under
known `operations` or `objects`. Narrative is stored beside the structured
contract. It cannot replace schemas, required fields, price, permissions,
limits, success conditions, errors, or state machines.

## Drift gate

`check` is read-only. It reports missing, extra, and byte-changed outputs and
exits non-zero on any drift. `codegen-report.json` contains only source,
generator, and output hashes plus the post-generation drift state; it never
contains an invocation, request, response, credential, or other business data.

## Draft.4 applicability registry

Draft.4 defines `operationKindApplicability` for every CommerceOperation kind.
The validator requires its kind set, envelope required fields, errors, limits,
permission evidence, source fields, and state-machine authorities to agree
with the canonical schemas and registries. The IR derives every adapter from
that registry and contains no operation-kind defaults.

Draft.4 does not declare HTTP methods or paths, so the OpenAPI artifact is
a valid 3.1 component catalog with an empty `paths` object; transport owners
must not infer endpoints from it.
