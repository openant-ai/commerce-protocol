"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");

const Ajv2020 = require("ajv/dist/2020").default;

const repoDir = path.resolve(__dirname, "../..");
const schema = JSON.parse(
  fs.readFileSync(path.join(repoDir, "schemas/commerce-0.1.schema.json"), "utf8"),
);
const vector = JSON.parse(
  fs.readFileSync(path.join(repoDir, "vectors/openant-x402-challenge-v1.json"), "utf8"),
);
const UINT256_MAX = (1n << 256n) - 1n;
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
      return BigInt(value) <= UINT256_MAX;
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
    return Number.isFinite(epochMillis) &&
      new Date(epochMillis).toISOString().replace(".000Z", "Z") === value;
  },
});
ajv.addSchema(schema);

function validator(definition) {
  return ajv.compile({ $ref: `${schema.$id}#/$defs/${definition}` });
}

test("public signed Listing and OpenAnt x402 extension satisfy strict draft.4 schemas", () => {
  const listing = validator("listingMandate");
  const outcome = validator("paymentRequiredOutcome");
  assert.equal(listing(vector.listingMandate), true, JSON.stringify(listing.errors));
  assert.equal(
    outcome(vector.paymentRequiredOutcome),
    true,
    JSON.stringify(outcome.errors),
  );
});

test("the complete resolved catalog root satisfies all four strict schemas", () => {
  for (const definition of [
    "serviceDefinitionVersion",
    "offerVersion",
    "endpointDescriptorVersion",
    "serviceSkuVersion",
  ]) {
    const validate = validator(definition);
    assert.equal(
      validate(vector.resolvedCatalog[definition]),
      true,
      `${definition}: ${JSON.stringify(validate.errors)}`,
    );
  }
});

test("standard x402 without extensions.openant cannot satisfy the OpenAnt payment contract", () => {
  const paymentRequired = validator("x402PaymentRequired");
  assert.equal(paymentRequired(vector.standardX402WithoutExtension), false);
  assert.ok(
    paymentRequired.errors.some(
      ({ keyword, params }) => keyword === "required" && params.missingProperty === "extensions",
    ),
  );
});

test("the signed objects reject unsigned extra fields", () => {
  const listing = validator("listingMandate");
  const extension = validator("openAntX402Extension");
  assert.equal(listing({ ...vector.listingMandate, attackerControlled: true }), false);
  const signedExtension = vector.paymentRequiredOutcome.paymentRequired.extensions.openant;
  assert.equal(extension({ ...signedExtension, attackerControlled: true }), false);
});
