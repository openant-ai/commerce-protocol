import {
  createHash,
  createPublicKey,
  verify as cryptoVerify,
} from "node:crypto";
import { readFileSync } from "node:fs";
import Ajv2020 from "ajv/dist/2020.js";

import { canonicalJson } from "../canonical.mjs";

export const SNAPSHOT_PATH = "/v1/trust-snapshots/current";
const PROFILE = "OPENANT_TRUST_SNAPSHOT";
const WIRE_VERSION = "0.1";
const IDENTIFIER = /^[a-z][a-z0-9]*(?:[_:-][a-zA-Z0-9]+)+$/;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/;
const corpus = JSON.parse(readFileSync(
  new URL("../../vectors/openant-trust-snapshot-v1.json", import.meta.url),
  "utf8",
));
const commerceSchema = JSON.parse(readFileSync(
  new URL("../../schemas/commerce-0.1.schema.json", import.meta.url),
  "utf8",
));
const ajv = new Ajv2020({
  allErrors: true,
  strictSchema: true,
  strictTypes: false,
  validateFormats: true,
});
ajv.addFormat("uint256-decimal", {
  type: "string",
  validate(value) {
    if (!/^(0|[1-9][0-9]*)$/.test(value)) return false;
    try {
      return BigInt(value) <= (1n << 256n) - 1n;
    } catch {
      return false;
    }
  },
});
ajv.addFormat("rfc3339-utc-whole-seconds", {
  type: "string",
  validate(value) {
    if (!/^\d{4}-(0[1-9]|1[0-2])-([0-2]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\dZ$/.test(value)) {
      return false;
    }
    const epochMillis = Date.parse(value);
    return Number.isFinite(epochMillis)
      && new Date(epochMillis).toISOString().replace(".000Z", "Z") === value;
  },
});
ajv.addSchema(commerceSchema);
const validateListingMandate = ajv.compile({
  $ref: `${commerceSchema.$id}#/$defs/listingMandate`,
});

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
  if (
    !Number.isFinite(instant)
    || new Date(instant).toISOString().replace(".000Z", "Z") !== value
  ) fail(code, "snapshot instant is invalid");
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

function validateVerifyOnlyEd25519Jwk(jwk, code) {
  requireExactKeys(jwk, ["kty", "crv", "use", "key_ops", "x"], code);
  if (
    jwk.kty !== "OKP"
    || jwk.crv !== "Ed25519"
    || jwk.use !== "sig"
    || canonicalJson(jwk.key_ops) !== '["verify"]'
    || typeof jwk.x !== "string"
    || !/^[A-Za-z0-9_-]{43}$/.test(jwk.x)
  ) fail(code, "JWK is not canonical verify-only Ed25519 material");
  let decoded;
  try {
    decoded = Buffer.from(jwk.x, "base64url");
  } catch {
    fail(code, "JWK x is not canonical base64url");
  }
  if (decoded.length !== 32 || decoded.toString("base64url") !== jwk.x) {
    fail(code, "JWK x must be canonical base64url for exactly 32 bytes");
  }
}

function validateKeyLifecycle(key, code) {
  if (
    typeof key.issuer !== "string" || !IDENTIFIER.test(key.issuer)
    || typeof key.kid !== "string" || !IDENTIFIER.test(key.kid)
    || key.role !== "ISSUER" || key.algorithm !== "EdDSA"
    || !Number.isSafeInteger(key.notBeforeUnixMs) || key.notBeforeUnixMs < 0
    || (key.notAfterUnixMs !== null && (
      !Number.isSafeInteger(key.notAfterUnixMs) || key.notAfterUnixMs <= key.notBeforeUnixMs
    ))
    || (key.revokedAtUnixMs !== null && (
      !Number.isSafeInteger(key.revokedAtUnixMs)
      || key.revokedAtUnixMs < key.notBeforeUnixMs
      || (key.notAfterUnixMs !== null && key.revokedAtUnixMs > key.notAfterUnixMs)
    ))
  ) fail(code, "key identity, type, or lifecycle ordering is invalid");
  validateVerifyOnlyEd25519Jwk(key.jwk, code);
}

function validateTrustAnchor(trustAnchor) {
  requireExactKeys(trustAnchor, [
    "issuer", "kid", "role", "algorithm", "notBeforeUnixMs", "notAfterUnixMs",
    "revokedAtUnixMs", "jwk",
  ], "TRUST_ANCHOR_INVALID");
  validateKeyLifecycle(trustAnchor, "TRUST_ANCHOR_INVALID");
}

function verifyRootSignature(snapshot, trustAnchor, observedAtMs) {
  validateTrustAnchor(trustAnchor);
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
  let signatureBytes;
  try {
    signatureBytes = Buffer.from(encodedSignature, "base64url");
  } catch {
    fail("SIGNATURE_INVALID", "snapshot signature is not canonical base64url");
  }
  if (signatureBytes.length !== 64 || signatureBytes.toString("base64url") !== encodedSignature) {
    fail("SIGNATURE_INVALID", "snapshot signature must be canonical base64url for exactly 64 bytes");
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
      signatureBytes,
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
    validateKeyLifecycle(key, "KEY_INVALID");
    const identity = `${key.issuer}\0${key.kid}\0${key.role}`;
    if (identities.has(identity)) fail("KEY_INVALID", "duplicate verification key identity");
    identities.add(identity);
    if (
      observedAtMs >= key.notBeforeUnixMs
      && (key.notAfterUnixMs === null || observedAtMs < key.notAfterUnixMs)
      && (key.revokedAtUnixMs === null || observedAtMs < key.revokedAtUnixMs)
    ) active.push({ identity: `${key.issuer}\0${key.kid}`, kid: key.kid });
  }
  if (active.length === 0) fail("EMPTY_KEYS", "snapshot has no active verification key");
  return active;
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
  requireExactKeys(snapshot.capabilities, ["containsTenantCredentials", "mintsCommerceAuthority"], "SCHEMA_INVALID");
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
    if (!validateListingMandate(listing)) {
      fail("LISTING_INVALID", "ListingMandate does not satisfy the strict Commerce schema");
    }
    if (listing.skuVersionDigest !== snapshot.catalogRoots.serviceSkuVersionDigest) {
      fail("LISTING_INVALID", "ListingMandate does not bind the published SKU root");
    }
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
    requireExactKeys(previous, ["version", "digest"], "SCHEMA_INVALID");
    if (!Number.isSafeInteger(previous.version) || previous.version < 1 || typeof previous.digest !== "string" || !SHA256_DIGEST.test(previous.digest)) {
      fail("SCHEMA_INVALID", "previous coordinate is invalid");
    }
    if (snapshot.snapshotVersion < previous.version) fail("ROLLBACK", "snapshot version rolled back");
    if (snapshot.snapshotVersion === previous.version && digest !== previous.digest) fail("VERSION_FORK", "same snapshot version has different digest");
    if (snapshot.snapshotVersion > previous.version) {
      if (snapshot.snapshotVersion !== previous.version + 1) fail("VERSION_GAP", "snapshot skipped a version");
      if (snapshot.previousSnapshotDigest !== previous.digest) {
        fail("CHAIN_MISMATCH", "snapshot does not extend the accepted coordinate");
      }
    }
  }
  const activeKeys = validateVerificationKeys(snapshot.verificationKeys, observedAtMs);
  const activeIdentities = new Set(activeKeys.map((key) => key.identity));
  const knownKeys = new Set(snapshot.verificationKeys.map((key) => `${key.issuer}\0${key.kid}`));
  for (const listing of snapshot.listingMandates) {
    const listingSigner = `${listing.signature.issuer}\0${listing.signature.keyId}`;
    if (!knownKeys.has(listingSigner)) {
      fail("LISTING_KEY_UNKNOWN", "Listing signer is absent from verification keys");
    }
    if (!activeIdentities.has(listingSigner)) fail("LISTING_KEY_INACTIVE", "Listing signer is inactive");
    for (const authorized of listing.authorizedChallengeIssuers ?? []) {
      const challengeSigner = `${authorized.issuer}\0${authorized.keyId}`;
      if (!knownKeys.has(challengeSigner)) {
        fail("CHALLENGE_KEY_UNKNOWN", "authorized Challenge signer is absent from verification keys");
      }
      if (!activeIdentities.has(challengeSigner)) {
        fail("CHALLENGE_KEY_INACTIVE", "authorized Challenge signer is inactive");
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
    activeKeyIds: activeKeys.map((key) => key.kid).sort(),
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

function entityHeaders() {
  return {
    "cache-control": "public, max-age=300, must-revalidate",
    "content-type": "application/json; charset=utf-8",
    "content-length": String(Buffer.byteLength(corpus.canonicalSnapshot)),
    etag: corpus.etag,
  };
}

function cacheHeaders() {
  return {
    "cache-control": "public, max-age=300, must-revalidate",
    etag: corpus.etag,
  };
}

function response(status, headers, body, decision, request) {
  return {
    status,
    headers,
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
  if (request?.path !== SNAPSHOT_PATH) return response(404, {}, "", "NOT_FOUND", request ?? {});
  if (request.method !== "GET" && request.method !== "HEAD") {
    return response(405, { allow: "GET, HEAD" }, "", "METHOD_NOT_ALLOWED", request);
  }
  const requestHeaders = Object.fromEntries(
    Object.entries(request.headers ?? {}).map(([name, value]) => [name.toLowerCase(), value]),
  );
  if (requestHeaders["if-none-match"] === corpus.etag) {
    return response(304, cacheHeaders(), "", "NOT_MODIFIED", request);
  }
  return response(
    200,
    entityHeaders(),
    request.method === "HEAD" ? "" : corpus.canonicalSnapshot,
    "SERVED",
    request,
  );
}
