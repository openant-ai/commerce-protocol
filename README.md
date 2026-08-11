# OpenAnt Commerce Protocol

Public, implementation-neutral contracts for OpenAnt commerce and compatible
payment infrastructure. OpenAnt governs the protocol; 0xkey is the first full
mandate, policy, payment-proof, and settlement adapter rather than a required
private backend.

The current pre-1.0 line is `0.1.0-draft.4`. It defines immutable Service SKU
roots, signed Listings and x402 extensions, Invocation and PaymentIntent state,
typed receipts, ProofBundle composition, and the Phase 0 Base USDC x402 v2
`exact` / EIP-3009 authorization profile.

## Layout

- `spec/` — normative human- and machine-readable registries.
- `schemas/` — JSON Schema, examples, semantic bindings, and digest gates.
- `packages/protocol/` — TypeScript constructors and canonical signing helpers.
- `packages/verifier/` — independent Rust verifier and cross-language vectors.
- `reference/`, `vectors/`, `tools/conformance/` — non-money reference flow,
  public adversarial vectors, and the black-box conformance CLI.
- `codegen/`, `fixtures/` — deterministic OpenAPI/TS/MCP/CLI/Skill generation,
  ambiguity fixtures, and the read-only drift gate.

## Verification

```bash
npm ci && npm run test:schema
cd packages/protocol && npm ci && npm test && npm run build
cd ../verifier && cargo test && cargo clippy --all-targets -- -D warnings
cd ../.. && node --test reference/*.test.mjs vectors/*.test.mjs tools/conformance/*.test.mjs
npm --prefix codegen test
```

No package accepts raw business content. Proofs are privately held and publicly
verifiable; disclosure of a concrete transaction remains an authorized action.
