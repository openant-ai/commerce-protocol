import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  SNAPSHOT_PATH,
  handleTrustSnapshotRequest,
  validateTrustSnapshot,
} from "./trust-snapshot.mjs";
import { canonicalJson } from "../canonical.mjs";

const corpusUrl = new URL("../../vectors/openant-trust-snapshot-v1.json", import.meta.url);
const corpus = JSON.parse(readFileSync(corpusUrl, "utf8"));
const report = JSON.parse(readFileSync(
  new URL("../../vectors/openant-trust-snapshot-v1-report.json", import.meta.url),
  "utf8",
));

function get(headers = {}, traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01") {
  return handleTrustSnapshotRequest({ method: "GET", path: SNAPSHOT_PATH, headers, traceparent });
}

function signedCandidate(mutate = () => {}) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const trustAnchor = {
    issuer: "openant_trust",
    kid: "test_trust_root",
    role: "ISSUER",
    algorithm: "EdDSA",
    notBeforeUnixMs: Date.parse("2026-08-01T00:00:00Z"),
    notAfterUnixMs: Date.parse("2026-09-01T00:00:00Z"),
    revokedAtUnixMs: null,
    jwk: { ...publicKey.export({ format: "jwk" }), use: "sig", key_ops: ["verify"] },
  };
  const snapshot = structuredClone(corpus.snapshot);
  snapshot.signature.issuer = trustAnchor.issuer;
  snapshot.signature.keyId = trustAnchor.kid;
  mutate(snapshot, trustAnchor);
  const preimage = structuredClone(snapshot);
  delete preimage.signature;
  const frame = Buffer.concat([
    Buffer.from("openant-commerce\0"),
    Buffer.from("0.1\0"),
    Buffer.from("OPENANT_TRUST_SNAPSHOT\0"),
    Buffer.from(canonicalJson(preimage)),
  ]);
  snapshot.signature.signedObjectDigest = `sha256:${createHash("sha256").update(frame).digest("hex")}`;
  const header = {
    alg: "EdDSA",
    aud: "openant:trust_snapshot",
    iss: snapshot.signature.issuer,
    kid: snapshot.signature.keyId,
    typ: "openant-commerce+jws",
  };
  const protectedHeader = Buffer.from(canonicalJson(header)).toString("base64url");
  const payload = Buffer.from(snapshot.signature.signedObjectDigest).toString("base64url");
  snapshot.signature.signature = `${protectedHeader}..${cryptoSign(
    null,
    Buffer.from(`${protectedHeader}.${payload}`),
    privateKey,
  ).toString("base64url")}`;
  return { body: canonicalJson(snapshot), trustAnchor };
}

function rejectSigned(mutate, code) {
  const candidate = signedCandidate(mutate);
  assert.throws(() => validateTrustSnapshot({
    ...candidate,
    observedAt: "2026-08-14T00:00:00Z",
  }), (error) => error.code === code, code);
}

test("GET publishes byte-identical signed metadata with deterministic cache headers", () => {
  const first = get();
  const second = get();

  assert.equal(first.status, 200);
  assert.deepEqual(first, second);
  assert.equal(first.body, corpus.canonicalSnapshot);
  assert.equal(first.headers["content-type"], "application/json; charset=utf-8");
  assert.equal(first.headers["content-length"], String(Buffer.byteLength(first.body)));
  assert.equal(first.headers.etag, corpus.etag);
  assert.equal(corpus.snapshot.signature.signedObjectDigest, "sha256:0074ec6d799ec83846f644c4eefd337ee6639c4b7f021ec91b235792d7b231fd");
  assert.equal(corpus.etag, '"sha256:c2bc504de781106fcbb9edc1f3e13a9d74bce532eb20adb698fbcbd1b754fe04"');
  assert.equal(createHash("sha256").update(readFileSync(corpusUrl)).digest("hex"), "93215bccc6dcd11e9bb00e6f9334cfbde542faae05bfebd020b69c91b6c654f4");
  assert.equal(first.headers["cache-control"], "public, max-age=300, must-revalidate");
  assert.deepEqual(first.observation, {
    event: "trust_snapshot.request_completed",
    traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
    snapshotDigest: corpus.snapshot.signature.signedObjectDigest,
    snapshotVersion: 2,
    issuer: "openant_trust",
    kid: "trust_snapshot_root_2026_08",
    cacheAgeSeconds: 0,
    decision: "SERVED",
    retryable: false,
  });
});

test("HEAD and If-None-Match preserve the immutable coordinate without a body", () => {
  const head = handleTrustSnapshotRequest({ method: "HEAD", path: SNAPSHOT_PATH, headers: {} });
  const notModified = get({ "if-none-match": corpus.etag });

  assert.equal(head.status, 200);
  assert.equal(head.body, "");
  assert.equal(head.headers["content-length"], String(Buffer.byteLength(corpus.canonicalSnapshot)));
  assert.equal(notModified.status, 304);
  assert.equal(notModified.body, "");
  assert.equal(notModified.headers.etag, corpus.etag);
  assert.deepEqual(Object.keys(notModified.headers).sort(), ["cache-control", "etag"]);
  assert.equal(get({ "iF-NoNe-MaTcH": corpus.etag }).status, 304);
});

test("the endpoint has no caller-selected trust, tenant, query, proof, or write seam", () => {
  for (const request of [
    { method: "POST", path: SNAPSHOT_PATH, headers: {}, body: { tenantCredential: "secret" } },
    { method: "GET", path: `${SNAPSHOT_PATH}?issuer=attacker`, headers: {} },
    { method: "GET", path: "/v1/trust-snapshots/attacker", headers: {} },
  ]) {
    const response = handleTrustSnapshotRequest(request);
    assert.equal(response.status, request.method === "POST" ? 405 : 404);
    assert.equal(response.body, "");
    assert.equal(JSON.stringify(response).includes("secret"), false);
    assert.equal(Object.hasOwn(response.headers, "etag"), false);
    assert.equal(Object.hasOwn(response.headers, "content-type"), false);
    if (response.status === 405) assert.equal(response.headers.allow, "GET, HEAD");
  }
});

test("rejects malformed trust anchors before cryptographic use", () => {
  for (const [name, mutate] of [
    ["extra field", (anchor) => { anchor.tenantCredential = "secret"; }],
    ["wrong type", (anchor) => { anchor.notBeforeUnixMs = "1785542400000"; }],
    ["inverted lifecycle", (anchor) => { anchor.notAfterUnixMs = anchor.notBeforeUnixMs; }],
    ["revocation before activation", (anchor) => { anchor.revokedAtUnixMs = anchor.notBeforeUnixMs - 1; }],
    ["private JWK", (anchor) => { anchor.jwk.d = "AA"; }],
    ["extra JWK field", (anchor) => { anchor.jwk.alg = "EdDSA"; }],
    ["non-canonical x", (anchor) => { anchor.jwk.x += "="; }],
    ["wrong x length", (anchor) => { anchor.jwk.x = "AA"; }],
  ]) {
    const anchor = structuredClone(corpus.trustAnchor);
    mutate(anchor);
    assert.throws(() => validateTrustSnapshot({
      body: corpus.canonicalSnapshot,
      trustAnchor: anchor,
      observedAt: "2026-08-14T00:00:00Z",
    }), (error) => error.code === "TRUST_ANCHOR_INVALID", name);
  }
});

test("signed nested metadata uses closed schemas and canonical verify-only JWKs", () => {
  rejectSigned((snapshot) => { snapshot.capabilities.tenantCredential = "secret"; }, "SCHEMA_INVALID");
  rejectSigned((snapshot) => { snapshot.listingMandates[0].privateKey = "secret"; }, "LISTING_INVALID");
  rejectSigned((snapshot) => { snapshot.listingMandates[0].signature.privateKey = "secret"; }, "LISTING_INVALID");
  rejectSigned((snapshot) => { snapshot.listingMandates[0].authorizedChallengeIssuers[0].tenant = "secret"; }, "LISTING_INVALID");
  rejectSigned((snapshot) => { snapshot.verificationKeys[0].jwk.alg = "EdDSA"; }, "KEY_INVALID");
  rejectSigned((snapshot) => { snapshot.verificationKeys[0].jwk.d = "AA"; }, "KEY_INVALID");
  rejectSigned((snapshot) => { snapshot.verificationKeys[0].jwk.x += "="; }, "KEY_INVALID");
  rejectSigned((snapshot) => { snapshot.verificationKeys[0].jwk.x = "AA"; }, "KEY_INVALID");
});

test("every signer referenced by a Listing is active at observedAt", () => {
  rejectSigned((snapshot) => {
    snapshot.verificationKeys.find((key) => key.kid === "listing_key_2026_08").revokedAtUnixMs =
      Date.parse("2026-08-13T23:59:59Z");
  }, "LISTING_KEY_INACTIVE");
  rejectSigned((snapshot) => {
    snapshot.verificationKeys.find((key) => key.kid === "challenge_key_2026_08").notAfterUnixMs =
      Date.parse("2026-08-14T00:00:00Z");
  }, "CHALLENGE_KEY_INACTIVE");
  const accepted = signedCandidate((snapshot) => {
    snapshot.verificationKeys.find((key) => key.kid === "challenge_key_2026_07").notAfterUnixMs =
      Date.parse("2026-08-14T00:00:00Z");
  });
  assert.equal(validateTrustSnapshot({
    ...accepted,
    observedAt: "2026-08-14T00:00:00Z",
  }).decision, "ACCEPTED", "an unreferenced previous overlap key may be retired");
});

test("version continuity permits only exact replay or the exact next link", () => {
  const digest = corpus.snapshot.signature.signedObjectDigest;
  assert.equal(validateTrustSnapshot({
    body: corpus.canonicalSnapshot,
    trustAnchor: corpus.trustAnchor,
    observedAt: "2026-08-14T00:00:00Z",
    previous: { version: 2, digest },
  }).decision, "ACCEPTED");
  const gap = signedCandidate((snapshot) => {
    snapshot.snapshotVersion = 4;
  });
  assert.throws(() => validateTrustSnapshot({
    ...gap,
    observedAt: "2026-08-14T00:00:00Z",
    previous: { version: 1, digest: corpus.previousSnapshotDigest },
  }), (error) => error.code === "VERSION_GAP");
  assert.throws(() => validateTrustSnapshot({
    body: corpus.canonicalSnapshot,
    trustAnchor: corpus.trustAnchor,
    observedAt: "2026-08-14T00:00:00Z",
    previous: { version: 1, digest: "sha256:" + "cc".repeat(32) },
  }), (error) => error.code === "CHAIN_MISMATCH");
});

test("consumer validates current and overlap keys but fails closed on trust faults", () => {
  const accepted = validateTrustSnapshot({
    body: corpus.canonicalSnapshot,
    trustAnchor: corpus.trustAnchor,
    observedAt: "2026-08-14T00:00:00Z",
    previous: { version: 1, digest: corpus.previousSnapshotDigest },
  });
  assert.equal(accepted.decision, "ACCEPTED");
  assert.deepEqual(accepted.activeKeyIds, ["challenge_key_2026_07", "challenge_key_2026_08", "listing_key_2026_08"]);

  const cases = [
    ["EXPIRED", { observedAt: "2026-09-13T00:00:01Z" }],
    ["STALE", { observedAt: "2026-08-14T00:10:01Z", maxCacheAgeSeconds: 300 }],
    ["ROLLBACK", { previous: { version: 3, digest: "sha256:" + "aa".repeat(32) } }],
    ["UNKNOWN_KID", { trustAnchor: { ...corpus.trustAnchor, kid: "unknown_root" } }],
    ["ROOT_KEY_INACTIVE", { trustAnchor: { ...corpus.trustAnchor, revokedAtUnixMs: Date.parse("2026-08-13T23:59:30Z") } }],
  ];
  for (const [code, overrides] of cases) {
    assert.throws(() => validateTrustSnapshot({
      body: corpus.canonicalSnapshot,
      trustAnchor: corpus.trustAnchor,
      observedAt: "2026-08-14T00:00:00Z",
      previous: { version: 1, digest: corpus.previousSnapshotDigest },
      ...overrides,
    }), (error) => error.code === code && error.retryable === false, code);
  }

  const tampered = corpus.canonicalSnapshot.replace("sku_weather", "sku_attacker");
  assert.throws(() => validateTrustSnapshot({
    body: tampered,
    trustAnchor: corpus.trustAnchor,
    observedAt: "2026-08-14T00:00:00Z",
  }), (error) => error.code === "SIGNATURE_INVALID");
  assert.throws(() => validateTrustSnapshot({
    body: "",
    trustAnchor: corpus.trustAnchor,
    observedAt: "2026-08-14T00:00:00Z",
  }), (error) => error.code === "EMPTY_SNAPSHOT");
  assert.throws(() => validateTrustSnapshot({
    body: JSON.stringify(corpus.snapshot, null, 2),
    trustAnchor: corpus.trustAnchor,
    observedAt: "2026-08-14T00:00:00Z",
  }), (error) => error.code === "NON_CANONICAL");
  assert.throws(() => validateTrustSnapshot({
    body: corpus.canonicalSnapshot,
    trustAnchor: corpus.trustAnchor,
    observedAt: "2026-08-14T00:00:00Z",
    previous: { version: 2, digest: "sha256:" + "bb".repeat(32) },
  }), (error) => error.code === "VERSION_FORK");
  assert.throws(() => validateTrustSnapshot({
    body: corpus.canonicalSnapshot,
    trustAnchor: corpus.trustAnchor,
    observedAt: "2026-08-14T00:04:01Z",
  }), (error) => error.code === "STALE", "signed cache.maxAgeSeconds is the default freshness bound");
});

test("snapshot is verify-only metadata and cannot upgrade standard x402", () => {
  const serialized = JSON.stringify(corpus);
  for (const forbidden of ["tenantCredential", "membership", "Bearer ", "requestBody", "responseBody", '"d"']) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
  assert.equal(serialized.includes("MANDATE_PROTECTED"), false);
  assert.equal(corpus.snapshot.capabilities.mintsCommerceAuthority, false);
  assert.equal(corpus.snapshot.capabilities.containsTenantCredentials, false);
  assert.deepEqual(report, {
    id: "OPENANT.TRUST.SNAPSHOT.REPORT.001",
    result: "PASS",
    protocolVersion: "0.1",
    sourceCommit: "f1cd81d977717986eaad741d22fc84ad1b380f70",
    sourceArtifactSha256: "cc45f2e5d3566c3756c522d20f9eb978d086256980af59957d780eda7699996e",
    snapshotArtifactSha256: "93215bccc6dcd11e9bb00e6f9334cfbde542faae05bfebd020b69c91b6c654f4",
    snapshotDigest: "sha256:0074ec6d799ec83846f644c4eefd337ee6639c4b7f021ec91b235792d7b231fd",
    snapshotVersion: 2,
    issuer: "openant_trust",
    kid: "trust_snapshot_root_2026_08",
    etag: '"sha256:c2bc504de781106fcbb9edc1f3e13a9d74bce532eb20adb698fbcbd1b754fe04"',
    accepted: ["CURRENT_KEY", "OVERLAP_ROTATION"],
    rejected: ["EMPTY_SNAPSHOT", "EXPIRED", "INACTIVE_REFERENCED_CHALLENGE_KEY", "INACTIVE_REFERENCED_LISTING_KEY", "MALFORMED_TRUST_ANCHOR", "NESTED_EXTRA_FIELD", "NON_CANONICAL", "PRIVATE_OR_NON_CANONICAL_JWK", "REVOKED_ROOT", "ROLLBACK", "SIGNATURE_TAMPER", "STALE", "UNKNOWN_KID", "VERSION_GAP", "VERSION_FORK"],
    http: ["GET_200", "HEAD_200", "IF_NONE_MATCH_304", "IF_NONE_MATCH_CASE_INSENSITIVE", "METHOD_405", "QUERY_404"],
    privacy: ["NO_BEARER", "NO_BUSINESS_BODY", "NO_PRIVATE_JWK", "NO_TENANT_CREDENTIAL", "NO_MANDATE_ASSURANCE"],
    authority: "PUBLIC_TRUST_METADATA_ONLY",
  });
});
