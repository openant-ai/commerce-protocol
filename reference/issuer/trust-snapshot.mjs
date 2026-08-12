import {
  createHash,
  createPublicKey,
  verify as cryptoVerify,
} from "node:crypto";
import { readFileSync } from "node:fs";

import { canonicalJson } from "../canonical.mjs";

export const SNAPSHOT_PATH = "/v1/trust-snapshots/current";
const PROFILE = "OPENANT_TRUST_SNAPSHOT";
const WIRE_VERSION = "0.1";
const corpus = JSON.parse(readFileSync(
  new URL("../../vectors/openant-trust-snapshot-v1.json", import.meta.url),
  "utf8",
));

export class TrustSnapshotError extends Error {
  constructor(code, message, retryable = false) {
    super(message);
    this.name = "TrustSnapshotError";
    this.code = code;
    this.retryable = retryable;
  }
}

function digestStructured(profile, value) {
  const frame = Buffer.concat([
    Buffer.from("openant-commerce\0", "utf8"),
    Buffer.from(`${WIRE_VERSION}\0`, "utf8"),
    Buffer.from(`${profile}\0`, "utf8"),
    Buffer.from(canonicalJson(value), "utf8"),
  ]);
  return `sha256:${createHash("sha256").update(frame).digest("hex")}`;
}

function fail(code, message) {
  throw new TrustSnapshotError(code, message, false);
}

function parseInstant(value, code) {
  if (typeof value !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(value)) {
    fail(code, "snapshot instant must be canonical UTC seconds");
  }
  const instant = Date.parse(value);
  if (!Number.isFinite(instant)) fail(code, "snapshot instant is invalid");
  return instant;
}

function requireExactKeys(value, names, code) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(code, "snapshot field must be an object");
  }
  const actual = Object.keys(value).sort();
  const expected = [...names].sort();
  if (actual.length !== expected.length || actual.some((name, index) => name !== expected[index])) {
    fail(code, "snapshot object has an unknown or missing field");
  }
}

function verifyRootSignature(snapshot, trustAnchor, observedAtMs) {
  const envelope = snapshot.signature;
  requireExactKeys(envelope, ["scheme", "issuer", "keyId", "signedObjectDigest", "signature"], "SIGNATURE_INVALID");
  if (
    envelope.scheme !== "DETACHED_JWS_EDDSA"
    || trustAnchor?.issuer !== envelope.issuer
    || trustAnchor?.kid !== envelope.keyId
    || trustAnchor?.role !== "ISSUER"
    || trustAnchor?.algorithm !== "EdDSA"
  ) fail("UNKNOWN_KID", "snapshot signer is not the pinned trust anchor");
  if (
    observedAtMs < trustAnchor.notBeforeUnixMs
    || (trustAnchor.notAfterUnixMs !== null && observedAtMs >= trustAnchor.notAfterUnixMs)
    || (trustAnchor.revokedAtUnixMs !== null && observedAtMs >= trustAnchor.revokedAtUnixMs)
  ) fail("ROOT_KEY_INACTIVE", "snapshot root key is inactive or revoked");

  const [encodedHeader, detachedPayload, encodedSignature, extra] = envelope.signature.split(".");
  if (!encodedHeader || detachedPayload !== "" || !encodedSignature || extra !== undefined) {
    fail("SIGNATURE_INVALID", "snapshot detached JWS is malformed");
  }
  let header;
  try {
    header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString("utf8"));
  } catch {
    fail("SIGNATURE_INVALID", "snapshot protected header is invalid");
  }
  requireExactKeys(header, ["alg", "aud", "iss", "kid", "typ"], "SIGNATURE_INVALID");
  if (
    header.alg !== "EdDSA"
    || header.aud !== "openant:trust_snapshot"
    || header.iss !== envelope.issuer
    || header.kid !== envelope.keyId
    || header.typ !== "openant-commerce+jws"
    || Buffer.from(canonicalJson(header)).toString("base64url") !== encodedHeader
  ) fail("SIGNATURE_INVALID", "snapshot protected header does not match the profile");

  const preimage = { ...snapshot };
  delete preimage.signature;
  const reproduced = digestStructured(PROFILE, preimage);
  if (reproduced !== envelope.signedObjectDigest) {
    fail("SIGNATURE_INVALID", "snapshot digest does not match its canonical preimage");
  }
  const payload = Buffer.from(reproduced, "utf8").toString("base64url");
  let valid = false;
  try {
    valid = cryptoVerify(
      null,
      Buffer.from(`${encodedHeader}.${payload}`, "ascii"),
      createPublicKey({ key: trustAnchor.jwk, format: "jwk" }),
      Buffer.from(encodedSignature, "base64url"),
    );
  } catch {
    valid = false;
  }
  if (!valid) fail("SIGNATURE_INVALID", "snapshot signature verification failed");
  return reproduced;
}

function validateVerificationKeys(keys, observedAtMs) {
  if (!Array.isArray(keys) || keys.length === 0) fail("EMPTY_KEYS", "snapshot has no verification keys");
  const identities = new Set();
  const active = [];
  for (const key of keys) {
    requireExactKeys(key, [
      "issuer", "kid", "role", "algorithm", "notBeforeUnixMs", "notAfterUnixMs",
      "revokedAtUnixMs", "jwk",
    ], "KEY_INVALID");
    const identity = `${key.issuer}\0${key.kid}\0${key.role}`;
    if (identities.has(identity)) fail("KEY_INVALID", "duplicate verification key identity");
    identities.add(identity);
    if (
      key.role !== "ISSUER" || key.algorithm !== "EdDSA"
      || key.jwk?.kty !== "OKP" || key.jwk?.crv !== "Ed25519"
      || key.jwk?.use !== "sig" || canonicalJson(key.jwk?.key_ops) !== '["verify"]'
      || typeof key.jwk?.x !== "string" || Object.hasOwn(key.jwk, "d")
    ) fail("KEY_INVALID", "verification key is not verify-only Ed25519 material");
    if (!Number.isSafeInteger(key.notBeforeUnixMs)) fail("KEY_INVALID", "key activation is invalid");
    if (key.notAfterUnixMs !== null && (!Number.isSafeInteger(key.notAfterUnixMs) || key.notAfterUnixMs <= key.notBeforeUnixMs)) {
      fail("KEY_INVALID", "key expiry is invalid");
    }
    if (key.revokedAtUnixMs !== null && !Number.isSafeInteger(key.revokedAtUnixMs)) fail("KEY_INVALID", "key revocation is invalid");
    if (
      observedAtMs >= key.notBeforeUnixMs
      && (key.notAfterUnixMs === null || observedAtMs < key.notAfterUnixMs)
      && (key.revokedAtUnixMs === null || observedAtMs < key.revokedAtUnixMs)
    ) active.push(key.kid);
  }
  if (active.length === 0) fail("EMPTY_KEYS", "snapshot has no active verification key");
  return active.sort();
}

export function validateTrustSnapshot({ body, trustAnchor, observedAt, previous, maxCacheAgeSeconds }) {
  if (typeof body !== "string" || body.length === 0) fail("EMPTY_SNAPSHOT", "snapshot body is empty");
  let snapshot;
  try {
    snapshot = JSON.parse(body);
  } catch {
    fail("INVALID_JSON", "snapshot body is not JSON");
  }
  if (canonicalJson(snapshot) !== body) fail("NON_CANONICAL", "snapshot bytes are not canonical JSON");
  requireExactKeys(snapshot, [
    "objectType", "protocolVersion", "snapshotVersion", "previousSnapshotDigest", "issuer",
    "generatedAt", "expiresAt", "cache", "capabilities", "sourceArtifact",
    "verificationKeys", "listingMandates", "catalogRoots", "signature",
  ], "SCHEMA_INVALID");
  if (
    snapshot.objectType !== "OpenAntTrustSnapshot" || snapshot.protocolVersion !== WIRE_VERSION
    || snapshot.issuer !== "openant_trust" || !Number.isSafeInteger(snapshot.snapshotVersion)
    || snapshot.snapshotVersion < 1
  ) fail("SCHEMA_INVALID", "snapshot identity or version is invalid");
  if (
    snapshot.capabilities?.containsTenantCredentials !== false
    || snapshot.capabilities?.mintsCommerceAuthority !== false
  ) fail("AUTHORITY_FORBIDDEN", "trust metadata cannot contain tenant authority");
  requireExactKeys(snapshot.cache, ["maxAgeSeconds", "mustRevalidate"], "SCHEMA_INVALID");
  if (
    !Number.isSafeInteger(snapshot.cache.maxAgeSeconds)
    || snapshot.cache.maxAgeSeconds < 0
    || snapshot.cache.maxAgeSeconds > 300
    || snapshot.cache.mustRevalidate !== true
  ) fail("SCHEMA_INVALID", "snapshot cache policy is invalid or unbounded");
  requireExactKeys(snapshot.sourceArtifact, ["commit", "artifactSha256"], "SCHEMA_INVALID");
  if (
    snapshot.sourceArtifact.commit !== "f1cd81d977717986eaad741d22fc84ad1b380f70"
    || snapshot.sourceArtifact.artifactSha256 !== "cc45f2e5d3566c3756c522d20f9eb978d086256980af59957d780eda7699996e"
  ) fail("SOURCE_MISMATCH", "snapshot does not identify the pinned public Challenge corpus");
  requireExactKeys(snapshot.catalogRoots, [
    "serviceDefinitionVersionDigest", "offerVersionDigest",
    "endpointDescriptorVersionDigest", "serviceSkuVersionDigest",
  ], "SCHEMA_INVALID");
  for (const root of Object.values(snapshot.catalogRoots)) {
    if (typeof root !== "string" || !/^sha256:[0-9a-f]{64}$/.test(root)) {
      fail("CATALOG_ROOT_INVALID", "catalog root is not a canonical SHA-256 digest");
    }
  }
  if (!Array.isArray(snapshot.listingMandates) || snapshot.listingMandates.length === 0) {
    fail("LISTING_EMPTY", "snapshot has no ListingMandate");
  }
  for (const listing of snapshot.listingMandates) {
    if (
      listing?.objectType !== "ListingMandate"
      || listing.skuVersionDigest !== snapshot.catalogRoots.serviceSkuVersionDigest
      || typeof listing.signature?.signedObjectDigest !== "string"
    ) fail("LISTING_INVALID", "ListingMandate does not bind the published SKU root");
  }

  const observedAtMs = parseInstant(observedAt, "CLOCK_INVALID");
  const generatedAtMs = parseInstant(snapshot.generatedAt, "SCHEMA_INVALID");
  const expiresAtMs = parseInstant(snapshot.expiresAt, "SCHEMA_INVALID");
  if (generatedAtMs > observedAtMs) fail("FUTURE_SNAPSHOT", "snapshot is future-dated");
  if (expiresAtMs <= generatedAtMs || observedAtMs >= expiresAtMs) fail("EXPIRED", "snapshot is expired");
  const freshnessBound = maxCacheAgeSeconds ?? snapshot.cache.maxAgeSeconds;
  if (!Number.isSafeInteger(freshnessBound) || freshnessBound < 0 || freshnessBound > snapshot.cache.maxAgeSeconds) {
    fail("SCHEMA_INVALID", "caller cache bound must not widen the signed freshness policy");
  }
  if (observedAtMs - generatedAtMs > freshnessBound * 1000) fail("STALE", "snapshot exceeds bounded freshness policy");

  const digest = verifyRootSignature(snapshot, trustAnchor, observedAtMs);
  if (previous !== undefined) {
    if (!Number.isSafeInteger(previous.version) || typeof previous.digest !== "string") fail("SCHEMA_INVALID", "previous coordinate is invalid");
    if (snapshot.snapshotVersion < previous.version) fail("ROLLBACK", "snapshot version rolled back");
    if (snapshot.snapshotVersion === previous.version && digest !== previous.digest) fail("VERSION_FORK", "same snapshot version has different digest");
    if (snapshot.snapshotVersion === previous.version + 1 && snapshot.previousSnapshotDigest !== previous.digest) {
      fail("CHAIN_MISMATCH", "snapshot does not extend the accepted coordinate");
    }
  }
  const activeKeyIds = validateVerificationKeys(snapshot.verificationKeys, observedAtMs);
  const knownKeys = new Set(snapshot.verificationKeys.map((key) => `${key.issuer}\0${key.kid}`));
  for (const listing of snapshot.listingMandates) {
    if (!knownKeys.has(`${listing.signature.issuer}\0${listing.signature.keyId}`)) {
      fail("LISTING_KEY_UNKNOWN", "Listing signer is absent from verification keys");
    }
    for (const authorized of listing.authorizedChallengeIssuers ?? []) {
      if (!knownKeys.has(`${authorized.issuer}\0${authorized.keyId}`)) {
        fail("CHALLENGE_KEY_UNKNOWN", "authorized Challenge signer is absent from verification keys");
      }
    }
  }
  return Object.freeze({
    decision: "ACCEPTED",
    retryable: false,
    digest,
    version: snapshot.snapshotVersion,
    issuer: snapshot.issuer,
    kid: snapshot.signature.keyId,
    activeKeyIds,
  });
}

const publishedCoordinate = validateTrustSnapshot({
  body: corpus.canonicalSnapshot,
  trustAnchor: corpus.trustAnchor,
  observedAt: "2026-08-14T00:00:00Z",
  previous: { version: 1, digest: corpus.previousSnapshotDigest },
});
const publishedEtag = `"sha256:${createHash("sha256").update(corpus.canonicalSnapshot).digest("hex")}"`;
if (
  publishedCoordinate.digest !== corpus.snapshot.signature.signedObjectDigest
  || corpus.etag !== publishedEtag
) fail("PUBLISHED_CORPUS_INVALID", "immutable published snapshot coordinate is inconsistent");

function traceId(traceparent) {
  const match = typeof traceparent === "string"
    ? /^00-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$/.exec(traceparent)
    : null;
  return match?.[1] ?? null;
}

function headers() {
  return {
    "cache-control": "public, max-age=300, must-revalidate",
    "content-type": "application/json; charset=utf-8",
    "content-length": String(Buffer.byteLength(corpus.canonicalSnapshot)),
    etag: corpus.etag,
  };
}

function response(status, body, decision, request) {
  return {
    status,
    headers: headers(),
    body,
    observation: {
      event: "trust_snapshot.request_completed",
      traceId: traceId(request.traceparent),
      snapshotDigest: corpus.snapshot.signature.signedObjectDigest,
      snapshotVersion: corpus.snapshot.snapshotVersion,
      issuer: corpus.snapshot.issuer,
      kid: corpus.snapshot.signature.keyId,
      cacheAgeSeconds: 0,
      decision,
      retryable: false,
    },
  };
}

export function handleTrustSnapshotRequest(request) {
  if (request?.path !== SNAPSHOT_PATH) return response(404, "", "NOT_FOUND", request ?? {});
  if (request.method !== "GET" && request.method !== "HEAD") return response(405, "", "METHOD_NOT_ALLOWED", request);
  const requestHeaders = request.headers ?? {};
  const match = requestHeaders["if-none-match"] ?? requestHeaders["If-None-Match"];
  if (match === corpus.etag) return response(304, "", "NOT_MODIFIED", request);
  return response(200, request.method === "HEAD" ? "" : corpus.canonicalSnapshot, "SERVED", request);
}
