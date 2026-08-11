# OpenAnt / 0xkey cross-conformance

This additive runner verifies the OnChain Hosted Phase-0 money-kernel
projection without changing the hash-pinned PR003 conformance runner. It never
executes OffChain code and never treats a non-0xkey-owned vector as a skip or a
0xkey pass.

## Replay command

Build the standalone Rust adapter and its deterministic source bundle first,
then run:

```sh
node tools/conformance/cross-cli.mjs \
  --protocol-archive /absolute/path/openant-commerce-protocol-workspace-0.1.0-draft.4.tgz \
  --money-projection-baseline /absolute/path/ox002-reference-report.ndjson \
  --crypto-proof-report /absolute/path/conformance-report.jsonl \
  --adapter-source-bundle /absolute/path/0xkey-commerce-conformance-adapter-source.tar \
  --adapter /absolute/path/commerce-conformance-adapter \
  --timeout-ms 5000
```

The current local integration gate runs the same checks plus the adversarial
process matrix explicitly (it is intentionally not part of the self-contained
`npm test` glob):

```sh
OPENANT_COMMERCE_TEST_WORKSPACE=/absolute/path/to/codes \
  node --test tools/conformance/cross-conformance.integration.mjs
```

`OPENANT_COMMERCE_TEST_WORKSPACE` must contain the `openant-ai` and `0xkey`
workspaces used by the local integration lane. The dedicated
`cross-conformance.yml` acceptance lane downloads the immutable
`v0.1.0-draft.4` GitHub Release assets, verifies the release manifest, and runs
the production CLI twice without skips in a pinned ARM64 Bookworm-slim image.
Ordinary protocol CI remains independent of sibling repositories.

All file arguments must be absolute regular files, not symlinks. The production
CLI invokes the Adapter binary with an empty argument list, a fixed environment,
a fresh empty working directory, and one child process per vector. The source
bundle must be a sorted, regular-file-only USTAR archive with fixed `0644`
mode, zero uid/gid/mtime, empty owner/group names, valid checksums, zero padding,
and at least two terminal zero blocks.

The runner independently verifies these immutable inputs and records only their
digests, never their local paths:

- protocol archive SHA-256
  `7a4feabe1cdc55804f4333c13f4550a39ce4570c1ce754e1b30c2d9c5e23b797`
  and npm SHA-512 integrity;
- all five pinned PR003 artifacts inside that archive;
- the reproduced 53-line reference report SHA-256
  `c11ed834692bae1f99c3ea65b28dd18d7dea04b9a8275bcba0161bfe17c779cb`;
- the 17-line money projection baseline SHA-256
  `124c62b05fa7114122d8c5ac51b4ce0ad1c2db243704cd4b8347e7435fb31689`;
- the OX003 cryptographic verifier report SHA-256
  `f17ff6db79340a323dc640aacceb0c251b9c03947cd605c4796e708239ef0b40`;
- the source USTAR bytes and built Adapter binary bytes.

## Ownership and proof lanes

The accepted 53 vectors form one exact, ordered, non-overlapping partition:

- 17 `MONEY_KERNEL_PROJECTION` vectors execute through 0xkey's public fixed
  `authorize` / `settle` / `resolve` conformance seam;
- 9 `REFERENCE_HARNESS_ONLY` vectors remain reference evidence and produce no
  Adapter invocation, skip, or pass row;
- 27 `OPENANT_COMMERCIAL_LEDGER` vectors remain OpenAnt-owned and produce no
  Adapter invocation, skip, or pass row.

The four VERIFY proof-input mutations are proved semantically by their exact
PR003 reference rows (`PASS` with `PROOF_BINDING_MISMATCH`). OX003 independently
provides the cryptographic verification corpus. The report labels these as
`referenceSemanticProofDigest` and `ox003CryptoProofDigest`; it does not claim
that OX003 directly executes those four state-machine scenarios.

For each of the 17 shared projections the runner directly compares public
PaymentIntent state, the unmodified draft.4 public error code, all eight effect
counts and their digest, and the lineage digest. It also checks the comparable
OpenAnt PR003 error code against the money projection baseline before starting
the Adapter. Invocation/commercial state is not copied into 0xkey.

## Process protocol

stdin is exactly one canonical JSON line plus LF and EOF with these five keys:

```json
{"command":"runVector","protocolDigest":"sha256:0069b449f4b0f2f2ae88103219a182703498231b3e7cbe6d76cdd7e3f195ff27","protocolVersion":"0.1.0-draft.4","schemaVersion":"openant-commerce-cross-conformance/1","vectorId":"HOSTED.HAPPY.001"}
```

stdout must be fatal-valid UTF-8 and exactly one canonical JSON line plus LF.
It has exactly 12 keys: `schemaVersion`, `implementation`,
`implementationVersion`, `protocolVersion`, `protocolDigest`, `vectorId`,
`result`, `paymentIntentState`, `errorCode`, `effects`, `effectsDigest`, and
`lineageDigest`. `effects` has exactly the eight public count fields. Unknown,
missing, duplicate, non-canonical, private skip/error, extra-line, invalid
UTF-8, or mismatched-version responses fail closed. stderr must be empty.

Adapter stdout plus stderr is capped at 1 MiB. Timeout, output overflow, signal,
and process failure terminate the isolated process group and become a
metadata-only harness failure; they are never remapped to a Commerce Protocol
business error.

Exit status is `0` only when all 17 rows pass, `1` for a completed report with
one or more projection or Adapter failures, and `2` when invocation or pinned
input verification fails. Reports are ordered canonical NDJSON and contain no
request, response, proof, artifact, secret, local path, or business payload.

The exact draft.4 RC is published as the immutable GitHub pre-release
`https://github.com/openant-ai/commerce-protocol/releases/tag/v0.1.0-draft.4`.
Its canonical release manifest pins every input, the clean runtime image, and
the expected byte-identical report digest. npm and crates.io registry
publication remain intentionally separate from this GitHub RC coordinate.
