import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  SNAPSHOT_PATH,
  handleTrustSnapshotRequest,
  validateTrustSnapshot,
} from "./trust-snapshot.mjs";

const corpusUrl = new URL("../../vectors/openant-trust-snapshot-v1.json", import.meta.url);
const corpus = JSON.parse(readFileSync(corpusUrl, "utf8"));

function get(headers = {}, traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01") {
  return handleTrustSnapshotRequest({ method: "GET", path: SNAPSHOT_PATH, headers, traceparent });
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
    assert.equal(JSON.stringify(response)).includes("secret", false);
  }
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
    ["STALE", { observedAt: "2026-08-14T00:10:01Z", maxCacheAgeSeconds: 600 }],
    ["ROLLBACK", { previous: { version: 3, digest: "sha256:" + "aa".repeat(32) } }],
    ["UNKNOWN_KID", { trustAnchor: { ...corpus.trustAnchor, kid: "unknown_root" } }],
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
});

test("snapshot is verify-only metadata and cannot upgrade standard x402", () => {
  const serialized = JSON.stringify(corpus);
  for (const forbidden of ["tenantCredential", "membership", "Bearer ", "requestBody", "responseBody", '"d"']) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
  assert.equal(serialized.includes("MANDATE_PROTECTED"), false);
  assert.equal(corpus.snapshot.capabilities.mintsCommerceAuthority, false);
  assert.equal(corpus.snapshot.capabilities.containsTenantCredentials, false);
});
