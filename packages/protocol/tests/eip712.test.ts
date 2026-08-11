import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { recoverTypedDataAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";

import {
  BASE_USDC_CONTRACT,
  buildPaymentAuthorizationTypedData,
  createEip712ProofEnvelope,
  digestWalletAuthorizationProofClaims,
  type Eip712EnvelopeRequest,
  type WalletAuthorizationProofClaimsInput,
} from "../src/index.js";

const account = privateKeyToAccount(
  "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
);
const walletProofClaimsInput = {
  objectType: "WalletAuthorizationProof",
  protocolVersion: "0.1",
  receiptId: "receipt:wallet:1",
  invocationId: "invocation:1",
  issuedAt: "2020-01-01T00:00:00Z",
  issuer: {
    issuer: "buyer:alice",
    keyId: `wallet:${account.address.toLowerCase()}`,
  },
  paymentIntentId: "payment:intent:1",
  paymentIntentFingerprintDigest: `sha256:${"aa".repeat(32)}`,
  buyerActorRef: "buyer:alice",
  serviceSkuVersionDigest: `sha256:${"dd".repeat(32)}`,
  challengeDigest: `sha256:${"bb".repeat(32)}`,
  expiresAt: "2099-01-01T00:00:00Z",
  amountAtomic: "1250000",
  asset: {
    network: "eip155:8453",
    namespace: "erc20",
    reference: BASE_USDC_CONTRACT,
    symbol: "USDC",
    decimals: 6,
  },
  payerAddress: account.address,
  payeeAddress: "0x2222222222222222222222222222222222222222",
  mode: "HOSTED",
  requestedAssurance: {
    authorization: "WALLET_SIGNED",
    settlement: "FINALITY_VERIFIED",
    delivery: "HOSTED_RECOVERABLE",
    contentCustody: "HOSTED_ENCRYPTED_BUFFER",
    identity: "PLATFORM_BOUND",
  },
  facilitatorId: "facilitator:0xkey:base",
} satisfies WalletAuthorizationProofClaimsInput;

const crossLanguageVector = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../../verifier/test-vectors/eip712-v1.json", import.meta.url)),
    "utf8",
  ),
) as {
  envelope: { signature: `0x${string}`; signedObjectDigest: `sha256:${string}` };
  paymentAuthorizationDigest: `sha256:${string}`;
  claimsDigest: `sha256:${string}`;
  eip712SigningHash: `0x${string}`;
};

describe("Phase 0 x402 v2 exact EIP-3009 authorization", () => {
  it("constructs only the fixed Base USDC TransferWithAuthorization object", () => {
    const prepared = buildPaymentAuthorizationTypedData(walletProofClaimsInput);
    expect(prepared.typedData).toEqual({
      domain: {
        name: "USD Coin",
        version: "2",
        chainId: 8453,
        verifyingContract: BASE_USDC_CONTRACT,
      },
      types: {
        TransferWithAuthorization: [
          { name: "from", type: "address" },
          { name: "to", type: "address" },
          { name: "value", type: "uint256" },
          { name: "validAfter", type: "uint256" },
          { name: "validBefore", type: "uint256" },
          { name: "nonce", type: "bytes32" },
        ],
      },
      primaryType: "TransferWithAuthorization",
      message: {
        from: account.address.toLowerCase(),
        to: walletProofClaimsInput.payeeAddress,
        value: walletProofClaimsInput.amountAtomic,
        validAfter: "0",
        validBefore: "4070908800",
        nonce: `0x${"aa".repeat(32)}`,
      },
    });
  });

  it("derives both digests and never accepts a caller-reported envelope digest", async () => {
    const prepared = buildPaymentAuthorizationTypedData(walletProofClaimsInput);
    const signature = await account.signTypedData(prepared.typedData);
    const result = createEip712ProofEnvelope({
      issuer: walletProofClaimsInput.buyerActorRef,
      keyId: walletProofClaimsInput.issuer.keyId,
      walletProofClaims: walletProofClaimsInput,
      signature,
    });

    expect("signedObjectDigest" in {
      issuer: walletProofClaimsInput.buyerActorRef,
      keyId: walletProofClaimsInput.issuer.keyId,
      walletProofClaims: walletProofClaimsInput,
      signature,
    }).toBe(false);
    expect(result.walletProofClaims.paymentAuthorizationDigest).toBe(
      result.paymentAuthorizationDigest,
    );
    expect(result.envelope.signedObjectDigest).toBe(result.paymentAuthorizationDigest);
    expect(result.claimsDigest).toBe(
      digestWalletAuthorizationProofClaims(result.walletProofClaims),
    );
    expect(result.claimsDigest).not.toBe(result.envelope.signedObjectDigest);
    expect(await recoverTypedDataAddress({ ...prepared.typedData, signature })).toBe(
      account.address,
    );
    expect(result).toMatchObject({
      paymentAuthorizationDigest: crossLanguageVector.paymentAuthorizationDigest,
      claimsDigest: crossLanguageVector.claimsDigest,
      eip712SigningHash: crossLanguageVector.eip712SigningHash,
      envelope: {
        signedObjectDigest: crossLanguageVector.envelope.signedObjectDigest,
        signature: crossLanguageVector.envelope.signature,
      },
    });

    expect(() =>
      createEip712ProofEnvelope({
        issuer: walletProofClaimsInput.buyerActorRef,
        keyId: walletProofClaimsInput.issuer.keyId,
        walletProofClaims: walletProofClaimsInput,
        signature,
        signedObjectDigest: `sha256:${"ff".repeat(32)}`,
      } as unknown as Eip712EnvelopeRequest),
    ).toThrow();
  });

  it("changes the claims digest, but not the standard settlement authorization, for receipt-only metadata", () => {
    const original = buildPaymentAuthorizationTypedData(walletProofClaimsInput);
    const changed = buildPaymentAuthorizationTypedData({
      ...walletProofClaimsInput,
      receiptId: "receipt:wallet:2",
      issuedAt: "2020-01-01T00:00:01Z",
    });
    expect(changed.paymentAuthorizationDigest).toBe(original.paymentAuthorizationDigest);

    const originalClaims = {
      ...walletProofClaimsInput,
      paymentAuthorizationDigest: original.paymentAuthorizationDigest,
    } as const;
    const changedClaims = {
      ...walletProofClaimsInput,
      receiptId: "receipt:wallet:2",
      issuedAt: "2020-01-01T00:00:01Z",
      paymentAuthorizationDigest: changed.paymentAuthorizationDigest,
    } as const;
    expect(digestWalletAuthorizationProofClaims(changedClaims)).not.toBe(
      digestWalletAuthorizationProofClaims(originalClaims),
    );
  });

  it("binds challenge and all commercial context through the fingerprint-derived nonce", () => {
    const changed = buildPaymentAuthorizationTypedData({
      ...walletProofClaimsInput,
      paymentIntentFingerprintDigest: `sha256:${"ee".repeat(32)}`,
    });
    expect(changed.typedData.message.nonce).toBe(`0x${"ee".repeat(32)}`);
    expect(changed.paymentAuthorizationDigest).not.toBe(
      buildPaymentAuthorizationTypedData(walletProofClaimsInput).paymentAuthorizationDigest,
    );
  });

  it.each([
    ["fractional expiry", { expiresAt: "2026-08-11T04:00:00.000Z" }],
    ["offset expiry", { expiresAt: "2026-08-11T12:00:00+08:00" }],
    ["invalid calendar expiry", { expiresAt: "2026-02-30T04:00:00Z" }],
    ["invalid buyer identifier", { buyerActorRef: "did:web:buyer.example" }],
    ["NUL facilitator", { facilitatorId: "facilitator:0xkey\0base" }],
    ["zero amount", { amountAtomic: "0" }],
    ["uint256 overflow", { amountAtomic: (1n << 256n).toString() }],
    ["zero-length wallet proof interval", { issuedAt: walletProofClaimsInput.expiresAt }],
  ] as const)("rejects %s", (_name, override) => {
    expect(() =>
      buildPaymentAuthorizationTypedData({
        ...walletProofClaimsInput,
        ...override,
      } as WalletAuthorizationProofClaimsInput),
    ).toThrow();
  });

  it("rejects a signature/envelope identity not equal to the proof buyer and wallet key", async () => {
    const prepared = buildPaymentAuthorizationTypedData(walletProofClaimsInput);
    const signature = await account.signTypedData(prepared.typedData);
    for (const override of [
      { issuer: "buyer:attacker" },
      { keyId: "wallet:attacker" },
    ]) {
      expect(() =>
        createEip712ProofEnvelope({
          issuer: walletProofClaimsInput.buyerActorRef,
          keyId: walletProofClaimsInput.issuer.keyId,
          walletProofClaims: walletProofClaimsInput,
          signature,
          ...override,
        }),
      ).toThrow();
    }
  });

  it.each([
    ["zero/parity-0 signature", `0x${"00".repeat(64)}00`],
    ["uppercase signature", `0x${"AA".repeat(64)}1b`],
  ] as const)("rejects %s", (_name, signature) => {
    expect(() =>
      createEip712ProofEnvelope({
        issuer: walletProofClaimsInput.buyerActorRef,
        keyId: walletProofClaimsInput.issuer.keyId,
        walletProofClaims: walletProofClaimsInput,
        signature,
      }),
    ).toThrow();
  });
});
