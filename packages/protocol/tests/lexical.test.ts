import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { expect, it } from "vitest";

import {
  isNonZeroEvmAddress,
  isPositiveUint256Decimal,
  isProtocolIdentifier,
  isRfc3339UtcWholeSeconds,
} from "../src/index.js";

const vector = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../../verifier/test-vectors/lexical-v1.json", import.meta.url)),
    "utf8",
  ),
) as {
  validIdentifiers: string[];
  invalidIdentifiers: string[];
  validRfc3339UtcWholeSeconds: string[];
  invalidRfc3339UtcWholeSeconds: string[];
  validNonZeroEvmAddresses: string[];
  invalidNonZeroEvmAddresses: string[];
  validPositiveUint256Decimals: string[];
  invalidPositiveUint256Decimals: string[];
};

it("matches the shared protocol identifier lexical set", () => {
  for (const value of vector.validIdentifiers) expect(isProtocolIdentifier(value)).toBe(true);
  for (const value of vector.invalidIdentifiers) expect(isProtocolIdentifier(value)).toBe(false);
});

it("matches the shared non-zero EVM address lexical set", () => {
  for (const value of vector.validNonZeroEvmAddresses) {
    expect(isNonZeroEvmAddress(value)).toBe(true);
  }
  for (const value of vector.invalidNonZeroEvmAddresses) {
    expect(isNonZeroEvmAddress(value)).toBe(false);
  }
});

it("matches the shared positive uint256 decimal lexical set", () => {
  for (const value of vector.validPositiveUint256Decimals) {
    expect(isPositiveUint256Decimal(value)).toBe(true);
  }
  for (const value of vector.invalidPositiveUint256Decimals) {
    expect(isPositiveUint256Decimal(value)).toBe(false);
  }
});

it("matches the shared RFC 3339 UTC whole-second lexical set", () => {
  for (const value of vector.validRfc3339UtcWholeSeconds) {
    expect(isRfc3339UtcWholeSeconds(value)).toBe(true);
  }
  for (const value of vector.invalidRfc3339UtcWholeSeconds) {
    expect(isRfc3339UtcWholeSeconds(value)).toBe(false);
  }
});
