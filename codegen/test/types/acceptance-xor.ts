import type {
  AcceptanceReceipt,
  Sha256Digest,
} from "../../generated/commerce-types.js";

declare const receipt: AcceptanceReceipt;
declare const digest: Sha256Digest;

// JSON Schema oneOf requires exactly one content digest.
// @ts-expect-error both responseDigest and artifactManifestDigest are forbidden
const invalidReceipt: AcceptanceReceipt = {
  ...receipt,
  responseDigest: digest,
  artifactManifestDigest: digest,
};

void invalidReceipt;
