"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");
const { isDeepStrictEqual } = require("node:util");

const Ajv2020 = require("ajv/dist/2020").default;

const SCHEMAS_DIR = path.resolve(__dirname, "..");
const REPO_DIR = path.resolve(SCHEMAS_DIR, "..");
const schema = JSON.parse(
  fs.readFileSync(path.join(SCHEMAS_DIR, "commerce-0.1.schema.json"), "utf8"),
);
const contract = JSON.parse(
  fs.readFileSync(path.join(REPO_DIR, "spec", "commerce.json"), "utf8"),
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
    if (!/^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/.test(value)) {
      return false;
    }
    const epochMillis = Date.parse(value);
    if (!Number.isFinite(epochMillis)) return false;
    return new Date(epochMillis).toISOString().replace(".000Z", "Z") === value;
  },
});
ajv.addSchema(schema);

const validators = new Map();

function validatorFor(definition) {
  if (!validators.has(definition)) {
    assert.ok(schema.$defs[definition], `unknown schema definition ${definition}`);
    validators.set(
      definition,
      ajv.compile({ $ref: `${schema.$id}#/$defs/${definition}` }),
    );
  }
  return validators.get(definition);
}

function load(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(SCHEMAS_DIR, relativePath), "utf8"));
}

function asCases(document) {
  return document.cases ?? [document];
}

function contractError(code) {
  const entry = contract.errors.find((candidate) => candidate.code === code);
  assert.ok(entry, `error ${code} must exist in contract registry`);
  return entry;
}

function hasBinding(id) {
  return contract.crossObjectBindings.some((binding) => binding.id === id);
}

function receiptBindingResult(receipt) {
  const signedDigest = receipt.objectType === "WalletAuthorizationProof" &&
    receipt.signature.scheme === "EIP712"
    ? receipt.paymentAuthorizationDigest
    : receipt.claimsDigest;
  return receipt.issuer.issuer === receipt.signature.issuer &&
    receipt.issuer.keyId === receipt.signature.keyId &&
    signedDigest === receipt.signature.signedObjectDigest
    ? null
    : "PROOF_BINDING_MISMATCH";
}

function challengeListingBindingResult(listingMandate, extension) {
  const authorizedSigner = listingMandate.authorizedChallengeIssuers.some(
    ({ issuer, keyId }) => issuer === extension.signature.issuer &&
      keyId === extension.signature.keyId,
  );
  return authorizedSigner &&
    listingMandate.signature.signedObjectDigest === extension.listingMandateDigest &&
    listingMandate.serviceSkuId === extension.serviceSkuId &&
    listingMandate.skuVersionDigest === extension.skuVersionDigest &&
    listingMandate.sellerIdentityRef === extension.sellerIdentityRef
    ? null
    : "CHALLENGE_INVALID";
}

function challengeInvocationBindingResult(invocation, extension) {
  return invocation.invocationId === extension.invocationId &&
    invocation.operationId === extension.operationId &&
    invocation.serviceSkuId === extension.serviceSkuId &&
    invocation.skuVersionDigest === extension.skuVersionDigest &&
    invocation.requestDigest === extension.requestDigest &&
    invocation.mode === extension.mode
    ? null
    : "CHALLENGE_INVALID";
}

function proofReferenceBindingResult(bundle, reference, resolvedObject) {
  const resolvedDigest = resolvedObject.claimsDigest ??
    resolvedObject.signature?.signedObjectDigest;
  const resolvedIssuedAt = resolvedObject.issuedAt ?? resolvedObject.validFrom;
  const resolvedSkuDigest = resolvedObject.serviceSkuVersionDigest ??
    resolvedObject.skuVersionDigest;
  const resolvedSigner = resolvedObject.signature;
  return reference.objectType === resolvedObject.objectType &&
    reference.issuer === resolvedSigner.issuer &&
    reference.keyId === resolvedSigner.keyId &&
    reference.objectDigest === resolvedDigest &&
    reference.issuedAt === resolvedIssuedAt &&
    reference.invocationId === bundle.invocationId &&
    reference.serviceSkuVersionDigest === bundle.serviceSkuVersionDigest &&
    resolvedObject.invocationId === bundle.invocationId &&
    resolvedSkuDigest === bundle.serviceSkuVersionDigest
    ? null
    : "PROOF_BINDING_MISMATCH";
}

function mandateProofBindingResult(paymentIntent, proof) {
  const equal = (left, right) => isDeepStrictEqual(left, right);
  return proof.decisionCode === "APPROVED" &&
    proof.issuer.issuer === paymentIntent.fundingAuthority.issuer &&
    proof.issuer.keyId === paymentIntent.fundingAuthority.keyId &&
    proof.paymentIntentId === paymentIntent.paymentIntentId &&
    proof.paymentIntentFingerprintDigest === paymentIntent.fingerprintDigest &&
    proof.fundingLedgerNamespace === paymentIntent.fundingLedgerNamespace &&
    proof.invocationId === paymentIntent.invocationId &&
    proof.tenantId === paymentIntent.tenantId &&
    proof.memberSuborgId === paymentIntent.memberSuborgId &&
    proof.treasuryProfile === paymentIntent.treasuryProfile &&
    proof.treasuryRef === paymentIntent.treasuryRef &&
    proof.agentId === paymentIntent.agentId &&
    proof.runtimeId === paymentIntent.runtimeId &&
    proof.runtimeCapabilityDigest === paymentIntent.runtimeCapabilityDigest &&
    proof.mandateId === paymentIntent.mandateId &&
    proof.mandateVersion === paymentIntent.mandateVersion &&
    proof.reservationId === paymentIntent.reservationId &&
    proof.challengeDigest === paymentIntent.challengeDigest &&
    proof.serviceSkuVersionDigest === paymentIntent.skuVersionDigest &&
    proof.sellerIdentityRef === paymentIntent.sellerIdentityRef &&
    proof.payeeAddress.toLowerCase() === paymentIntent.payoutAddress.toLowerCase() &&
    proof.payerAddress.toLowerCase() === paymentIntent.payerAddress.toLowerCase() &&
    equal(proof.asset, paymentIntent.asset) &&
    proof.amountAtomic === paymentIntent.amountAtomic &&
    proof.mode === paymentIntent.mode &&
    equal(proof.requestedAssurance, paymentIntent.requestedAssurance) &&
    proof.facilitatorId === paymentIntent.facilitatorId &&
    proof.paymentAuthorizationDigest === paymentIntent.authorizationDigest &&
    proof.expiresAt === paymentIntent.expiresAt
    ? null
    : "PROOF_BINDING_MISMATCH";
}

function paymentIntentChallengeBindingResult(paymentIntent, extension) {
  return paymentIntent.challengeDigest === extension.signature.signedObjectDigest &&
    paymentIntent.invocationId === extension.invocationId &&
    paymentIntent.skuVersionDigest === extension.skuVersionDigest &&
    paymentIntent.sellerIdentityRef === extension.sellerIdentityRef &&
    paymentIntent.payoutAddress.toLowerCase() === extension.payoutAddress.toLowerCase() &&
    isDeepStrictEqual(paymentIntent.asset, extension.asset) &&
    paymentIntent.amountAtomic === extension.amountAtomic &&
    paymentIntent.mode === extension.mode &&
    isDeepStrictEqual(paymentIntent.requestedAssurance, extension.assurance) &&
    paymentIntent.expiresAt === extension.expiresAt
    ? null
    : "PROOF_BINDING_MISMATCH";
}

function walletProofBindingResult(
  paymentIntent,
  proof,
  recoveredSignerAddress = paymentIntent.payerAddress,
) {
  const derivedWalletActor = `wallet_eip155_8453_${paymentIntent.payerAddress.slice(2).toLowerCase()}`;
  return proof.issuer.issuer === paymentIntent.fundingAuthority.issuer &&
    proof.issuer.keyId === paymentIntent.fundingAuthority.keyId &&
    paymentIntent.buyerActorRef === derivedWalletActor &&
    proof.issuer.issuer === paymentIntent.buyerActorRef &&
    proof.buyerActorRef === paymentIntent.buyerActorRef &&
    proof.paymentIntentId === paymentIntent.paymentIntentId &&
    proof.paymentIntentFingerprintDigest === paymentIntent.fingerprintDigest &&
    proof.invocationId === paymentIntent.invocationId &&
    proof.serviceSkuVersionDigest === paymentIntent.skuVersionDigest &&
    proof.challengeDigest === paymentIntent.challengeDigest &&
    proof.paymentAuthorizationDigest === paymentIntent.authorizationDigest &&
    proof.signature.signedObjectDigest === proof.paymentAuthorizationDigest &&
    proof.expiresAt === paymentIntent.expiresAt &&
    proof.amountAtomic === paymentIntent.amountAtomic &&
    isDeepStrictEqual(proof.asset, paymentIntent.asset) &&
    proof.payerAddress.toLowerCase() === paymentIntent.payerAddress.toLowerCase() &&
    recoveredSignerAddress.toLowerCase() === paymentIntent.payerAddress.toLowerCase() &&
    proof.payeeAddress.toLowerCase() === paymentIntent.payoutAddress.toLowerCase() &&
    proof.mode === paymentIntent.mode &&
    isDeepStrictEqual(proof.requestedAssurance, paymentIntent.requestedAssurance) &&
    proof.facilitatorId === paymentIntent.facilitatorId
    ? null
    : "PROOF_BINDING_MISMATCH";
}

function fundingReceiptBindingResult(paymentIntent, receipt) {
  const isSettlement = receipt.objectType === "SettlementReceipt";
  const expectedAuthority = isSettlement
    ? paymentIntent.settlementAuthority
    : paymentIntent.observationAuthority;
  const common = receipt.issuer.issuer === expectedAuthority.issuer &&
    receipt.issuer.keyId === expectedAuthority.keyId &&
    receipt.paymentIntentId === paymentIntent.paymentIntentId &&
    receipt.paymentIntentFingerprintDigest === paymentIntent.fingerprintDigest &&
    receipt.fundingLedgerNamespace === paymentIntent.fundingLedgerNamespace &&
    receipt.invocationId === paymentIntent.invocationId &&
    receipt.serviceSkuVersionDigest === paymentIntent.skuVersionDigest;
  if (!common) return "PROOF_BINDING_MISMATCH";
  if (!isSettlement) {
    const authorizationProfile = paymentIntent.requestedAssurance.authorization;
    const reservationMatches = authorizationProfile === "MANDATE_PROTECTED"
      ? receipt.reservationId === paymentIntent.reservationId
      : receipt.reservationId === undefined && paymentIntent.reservationId === undefined;
    return receipt.authorizationProfile === authorizationProfile &&
      reservationMatches &&
      receipt.observedState === paymentIntent.state &&
      receipt.unknownBoundary === (paymentIntent.state === "AUTHORIZATION_UNKNOWN"
        ? "authorization"
        : "settlement") &&
      receipt.reconciliationDeadline === paymentIntent.reconciliationDeadline &&
      (!receipt.authorizationDigest ||
        receipt.authorizationDigest === paymentIntent.authorizationDigest)
      ? null
      : "PROOF_BINDING_MISMATCH";
  }
  return receipt.facilitatorId === paymentIntent.facilitatorId &&
    receipt.paymentAuthorizationDigest === paymentIntent.authorizationDigest &&
    receipt.amountAtomic === paymentIntent.amountAtomic &&
    isDeepStrictEqual(receipt.asset, paymentIntent.asset) &&
    receipt.payerAddress.toLowerCase() === paymentIntent.payerAddress.toLowerCase() &&
    receipt.payeeAddress.toLowerCase() === paymentIntent.payoutAddress.toLowerCase()
    ? null
    : "PROOF_BINDING_MISMATCH";
}

function evidenceReferenceBindingResult(owner, digestField, resolved, expectedType) {
  const ownerPaymentIntentId = owner.paymentIntentId ?? owner.paymentIntentRef;
  return resolved.objectType === expectedType &&
    owner[digestField] === resolved.claimsDigest &&
    owner.invocationId === resolved.invocationId &&
    owner.skuVersionDigest === resolved.serviceSkuVersionDigest &&
    (!resolved.paymentIntentId || ownerPaymentIntentId === resolved.paymentIntentId)
    ? null
    : "PROOF_BINDING_MISMATCH";
}

function endpointIssuerBindingResult(receipt, sku, endpoint) {
  const issuerSetByType = {
    OutputStagingReceipt: endpoint.stagingIssuerKeys,
    ExecutionReceipt: endpoint.executionIssuerKeys,
    DeliveryReceipt: endpoint.deliveryIssuerKeys,
    CommerceReceipt: endpoint.commerceIssuerKeys,
  };
  const issuerSet = issuerSetByType[receipt.objectType] ?? [];
  const trustedHostedCustodyKeys = new Set([
    "openant_gateway#key_delivery_1",
  ]);
  const isHostedCustodyReceipt = receipt.objectType === "OutputStagingReceipt" ||
    receipt.objectType === "DeliveryReceipt";
  const signerPair = `${receipt.signature.issuer}#${receipt.signature.keyId}`;
  return receipt.serviceSkuVersionDigest === sku.skuVersionDigest &&
    sku.endpointDescriptorVersionDigest === endpoint.versionDigest &&
    issuerSet.some(({ issuer, keyId }) =>
      receipt.signature.issuer === issuer && receipt.signature.keyId === keyId) &&
    (!isHostedCustodyReceipt || trustedHostedCustodyKeys.has(signerPair))
    ? null
    : "PROOF_BINDING_MISMATCH";
}

function runtimeCapabilityBindingResult(paymentIntent, capability) {
  return paymentIntent.runtimeCapabilityDigest === capability.runtimeCapabilityDigest &&
    paymentIntent.fundingAuthority.issuer === capability.signature.issuer &&
    paymentIntent.fundingAuthority.keyId === capability.signature.keyId &&
    paymentIntent.runtimeId === capability.runtimeId &&
    paymentIntent.agentId === capability.agentId &&
    paymentIntent.buyerActorRef === capability.buyerActorRef &&
    paymentIntent.mandateId === capability.mandateId &&
    paymentIntent.mandateVersion === capability.mandateVersion &&
    paymentIntent.skuVersionDigest === capability.serviceSkuVersionDigest &&
    Date.parse(paymentIntent.createdAt) >= Date.parse(capability.issuedAt) &&
    Date.parse(paymentIntent.expiresAt) <= Date.parse(capability.expiresAt)
    ? null
    : "PROOF_BINDING_MISMATCH";
}

function skuRootBindingResult(definition, offer, endpoint, sku, listing) {
  return sku.serviceDefinitionVersionDigest === definition.versionDigest &&
    sku.offerVersionDigest === offer.versionDigest &&
    sku.endpointDescriptorVersionDigest === endpoint.versionDigest &&
    listing.skuVersionDigest === sku.skuVersionDigest &&
    listing.serviceSkuId === sku.serviceSkuId &&
    listing.sellerIdentityRef === sku.sellerIdentityRef &&
    sku.operationId === definition.operationId
    ? null
    : "CHALLENGE_INVALID";
}

function skuModeAssuranceBindingResult(endpoint, offer) {
  const { delivery, contentCustody } = offer.minimumAssurance;
  if (endpoint.mode === "DIRECT") {
    return delivery === "DIRECT_BUYER_ACCEPTED" && contentCustody === "DIRECT"
      ? null
      : "CHALLENGE_INVALID";
  }
  return delivery === "HOSTED_RECOVERABLE" &&
    ["HOSTED_EPHEMERAL", "HOSTED_ENCRYPTED_BUFFER"].includes(contentCustody)
    ? null
    : "CHALLENGE_INVALID";
}

function challengeRootBindingResult(outcome, definition, offer, endpoint, sku) {
  const extension = outcome.paymentRequired.extensions.openant;
  const resource = outcome.paymentRequired.resource;
  return extension.serviceSkuId === sku.serviceSkuId &&
    extension.skuVersionDigest === sku.skuVersionDigest &&
    extension.operationId === definition.operationId &&
    extension.amountAtomic === offer.amountAtomic &&
    isDeepStrictEqual(extension.asset, offer.asset) &&
    extension.payoutAddress.toLowerCase() === offer.payoutAddress.toLowerCase() &&
    isDeepStrictEqual(extension.assurance, offer.minimumAssurance) &&
    extension.mode === endpoint.mode &&
    extension.signature.issuer === endpoint.challengeIssuer.issuer &&
    extension.signature.keyId === endpoint.challengeIssuer.keyId &&
    resource.url === endpoint.invokeUri &&
    resource.mimeType === definition.outputMediaType
    ? null
    : "CHALLENGE_INVALID";
}

function invocationRootBindingResult(invocation, definition, endpoint, sku) {
  return invocation.serviceSkuId === sku.serviceSkuId &&
    invocation.skuVersionDigest === sku.skuVersionDigest &&
    invocation.operationId === sku.operationId &&
    invocation.operationId === definition.operationId &&
    invocation.mode === endpoint.mode
    ? null
    : "CHALLENGE_INVALID";
}

function requestReceiptBindingResult(invocation, receipt) {
  return receipt.invocationId === invocation.invocationId &&
    receipt.serviceSkuVersionDigest === invocation.skuVersionDigest &&
    receipt.requestDigest === invocation.requestDigest
    ? null
    : "PROOF_BINDING_MISMATCH";
}

function hostedRecoveryBindingResult(staging, delivery) {
  return staging.invocationId === delivery.invocationId &&
    staging.serviceSkuVersionDigest === delivery.serviceSkuVersionDigest &&
    staging.responseDigest === delivery.responseDigest &&
    staging.artifactManifestDigest === delivery.artifactManifestDigest &&
    staging.contentBytes === delivery.contentBytes &&
    staging.availableUntil === delivery.availableUntil
    ? null
    : "PROOF_BINDING_MISMATCH";
}

function commerceReceiptBindingResult(receipt, settlement, endpoint) {
  return receipt.settlementReceiptDigest === settlement.claimsDigest &&
    receipt.invocationId === settlement.invocationId &&
    receipt.serviceSkuVersionDigest === settlement.serviceSkuVersionDigest &&
    endpoint.commerceIssuerKeys.some(({ issuer, keyId }) =>
      receipt.signature.issuer === issuer && receipt.signature.keyId === keyId)
    ? null
    : "PROOF_BINDING_MISMATCH";
}

function hostedRecoveryTimeBindingResult(
  invocation,
  offer,
  staging,
  delivery,
  acknowledgement,
  bundle,
) {
  const expectedAvailableUntil = Date.parse(staging.issuedAt) +
    offer.deliveryTerms.unacknowledgedRecoverySeconds * 1000;
  return Date.parse(staging.issuedAt) <= Date.parse(staging.availableUntil) &&
    Date.parse(delivery.issuedAt) <= Date.parse(delivery.availableUntil) &&
    Date.parse(delivery.issuedAt) <= Date.parse(acknowledgement.receivedAt) &&
    Date.parse(acknowledgement.receivedAt) <= Date.parse(delivery.availableUntil) &&
    Date.parse(staging.availableUntil) === expectedAvailableUntil &&
    staging.availableUntil === delivery.availableUntil &&
    Date.parse(invocation.createdAt) <= Date.parse(staging.issuedAt) &&
    Date.parse(bundle.createdAt) >= Date.parse(delivery.issuedAt) &&
    Date.parse(bundle.createdAt) <= Date.parse(delivery.availableUntil)
    ? null
    : "PROOF_BINDING_MISMATCH";
}

function evidenceChronologyBindingResult({
  mode,
  authorizationProof,
  staging,
  execution,
  settlement,
  delivery,
  acknowledgement,
  acceptance,
}) {
  const authorizationAt = Date.parse(authorizationProof.issuedAt);
  const settlementAt = Date.parse(settlement.issuedAt);
  if (mode === "HOSTED") {
    return authorizationAt <= Date.parse(staging.issuedAt) &&
      Date.parse(staging.issuedAt) <= settlementAt &&
      settlementAt <= Date.parse(delivery.issuedAt) &&
      Date.parse(delivery.issuedAt) <= Date.parse(acknowledgement.receivedAt)
      ? null
      : "PROOF_BINDING_MISMATCH";
  }
  return authorizationAt <= Date.parse(execution.issuedAt) &&
    Date.parse(execution.issuedAt) <= settlementAt &&
    settlementAt <= Date.parse(acceptance.issuedAt)
    ? null
    : "PROOF_BINDING_MISMATCH";
}

function directAcceptanceContentBindingResult(execution, acceptance) {
  const executionKind = execution.responseDigest ? "RESPONSE" :
    execution.artifactManifestDigest ? "ARTIFACT" : null;
  const acceptanceKind = acceptance.responseDigest ? "RESPONSE" :
    acceptance.artifactManifestDigest ? "ARTIFACT" : null;
  const executionContentDigest = execution.responseDigest ??
    execution.artifactManifestDigest;
  const acceptanceContentDigest = acceptance.responseDigest ??
    acceptance.artifactManifestDigest;
  return execution.invocationId === acceptance.invocationId &&
    execution.serviceSkuVersionDigest === acceptance.serviceSkuVersionDigest &&
    executionKind !== null &&
    executionKind === acceptanceKind &&
    executionContentDigest === acceptanceContentDigest &&
    execution.contentBytes === acceptance.contentBytes
    ? null
    : "PROOF_BINDING_MISMATCH";
}

function invocationDeliveryStateBindingResult(invocation, deliveryReceipt) {
  const requiresDelivered = invocation.mode === "HOSTED" &&
    (["DELIVERED", "ACKED"].includes(invocation.state) ||
      (invocation.state === "RECOVERY_WINDOW_EXPIRED" &&
        !!invocation.deliveryReceiptDigest));
  if (!requiresDelivered) return null;
  return invocation.deliveryReceiptDigest === deliveryReceipt.claimsDigest &&
    invocation.invocationId === deliveryReceipt.invocationId &&
    invocation.skuVersionDigest === deliveryReceipt.serviceSkuVersionDigest &&
    deliveryReceipt.deliveryState === "DELIVERED"
    ? null
    : "PROOF_BINDING_MISMATCH";
}

function proofBundleFundingLineageResult(
  bundle,
  invocation,
  paymentIntent,
  resolvedProofs,
  settlementByDigest = new Map(),
) {
  if (bundle.invocationId !== invocation.invocationId ||
      invocation.paymentIntentRef !== paymentIntent.paymentIntentId) {
    return "PROOF_BINDING_MISMATCH";
  }
  const fundingProofs = [];
  for (const proof of resolvedProofs) {
    if ([
      "MandateAuthorizationProof",
      "WalletAuthorizationProof",
      "SettlementReceipt",
      "FundingUnknownObservation",
    ].includes(proof.objectType)) fundingProofs.push(proof);
    if (proof.objectType === "CommerceReceipt") {
      const settlement = settlementByDigest.get(proof.settlementReceiptDigest);
      if (!settlement) return "PROOF_BINDING_MISMATCH";
      fundingProofs.push(settlement);
    }
  }
  return fundingProofs.every((proof) => {
    const authorizationDigest = proof.paymentAuthorizationDigest ??
      proof.authorizationDigest;
    return proof.paymentIntentId === paymentIntent.paymentIntentId &&
      proof.paymentIntentFingerprintDigest === paymentIntent.fingerprintDigest &&
      (!authorizationDigest || authorizationDigest === paymentIntent.authorizationDigest);
  })
    ? null
    : "PROOF_BINDING_MISMATCH";
}

function deliveryAcknowledgementBindingResult(
  acknowledgement,
  deliveryReceipt,
  resolvedArtifactManifest,
  resolvedArtifactManifestDigest,
) {
  if (acknowledgement.deliveryReceiptDigest !== deliveryReceipt.claimsDigest ||
      acknowledgement.invocationId !== deliveryReceipt.invocationId) {
    return "PROOF_BINDING_MISMATCH";
  }
  if (acknowledgement.contentKind === "RESPONSE") {
    return !acknowledgement.artifactManifestDigest &&
      !!deliveryReceipt.responseDigest &&
      !deliveryReceipt.artifactManifestDigest &&
      acknowledgement.receivedContentDigest === deliveryReceipt.responseDigest
      ? null
      : "PROOF_BINDING_MISMATCH";
  }
  if (acknowledgement.contentKind === "ARTIFACT") {
    return !!acknowledgement.artifactManifestDigest &&
      !deliveryReceipt.responseDigest &&
      deliveryReceipt.artifactManifestDigest === acknowledgement.artifactManifestDigest &&
      acknowledgement.artifactManifestDigest === resolvedArtifactManifestDigest &&
      acknowledgement.receivedContentDigest === resolvedArtifactManifest?.contentDigest
      ? null
      : "PROOF_BINDING_MISMATCH";
  }
  return "PROOF_BINDING_MISMATCH";
}

function semanticResult(testCase) {
  switch (testCase.kind) {
    case "expiredChallenge":
      return Date.parse(testCase.extension.expiresAt) <= Date.parse(testCase.now)
        ? "CHALLENGE_EXPIRED"
        : null;
    case "fingerprintConflict":
      return testCase.existing.idempotencyKey === testCase.incoming.idempotencyKey &&
        testCase.existing.fingerprintDigest !== testCase.incoming.fingerprintDigest
        ? "IDEMPOTENCY_FINGERPRINT_CONFLICT"
        : null;
    case "illegalTransition": {
      const machine = contract.stateMachines[testCase.machine];
      assert.ok(machine, `unknown state machine ${testCase.machine}`);
      const selectedTransitions = machine.authorizationProfileTransitions
        ? machine.authorizationProfileTransitions[testCase.authorizationProfile]
        : machine.transitions;
      const allowed = Array.isArray(selectedTransitions) && selectedTransitions.some(
        ([from, to]) => from === testCase.from && to === testCase.to,
      );
      return allowed ? null : "ILLEGAL_STATE_TRANSITION";
    }
    case "x402TermsMismatch": {
      const { acceptance, extension } = testCase;
      return acceptance.amount !== extension.amountAtomic ||
        acceptance.asset.toLowerCase() !== extension.asset.reference.toLowerCase() ||
        acceptance.payTo.toLowerCase() !== extension.payoutAddress.toLowerCase()
        ? "CHALLENGE_INVALID"
        : null;
    }
    case "proofIncomplete": {
      const required = [
        ...contract.assuranceRequirements.authorization[testCase.assurance.authorization],
        ...contract.assuranceRequirements.settlement[testCase.assurance.settlement],
        ...contract.assuranceRequirements.delivery[testCase.assurance.delivery],
        ...contract.assuranceRequirements.contentCustody[testCase.assurance.contentCustody],
        ...contract.assuranceRequirements.identity[testCase.assurance.identity],
      ];
      return required.every((proofType) => testCase.proofTypes.includes(proofType))
        ? null
        : "PROOF_INCOMPLETE";
    }
    case "listingSellerIssuerMismatch":
      return testCase.listingMandate.sellerIdentityRef !==
        testCase.listingMandate.signature.issuer
        ? "CHALLENGE_INVALID"
        : null;
    default:
      assert.fail(`unknown semantic case ${testCase.kind}`);
  }
}

test("all machine-readable object references resolve", () => {
  for (const [objectType, reference] of Object.entries(contract.objects)) {
    assert.match(reference, /^#\/\$defs\/[A-Za-z][A-Za-z0-9]+$/);
    const definition = reference.split("/").at(-1);
    assert.ok(schema.$defs[definition], `${objectType} points to missing ${definition}`);
    validatorFor(definition);
  }
});

for (const fixture of [
  "examples/valid/domain-objects.json",
  "examples/valid/payment-flow.json",
  "examples/valid/receipts.json",
  "examples/valid/proof-bundle.json",
]) {
  test(`positive schema examples: ${fixture}`, () => {
    for (const testCase of asCases(load(fixture))) {
      const validate = validatorFor(testCase.definition);
      assert.equal(
        validate(testCase.value),
        true,
        `${testCase.definition}: ${ajv.errorsText(validate.errors, { separator: "\n" })}`,
      );
    }
  });
}

for (const fixture of [
  "examples/invalid/additional-property.json",
  "examples/invalid/amount-overflow.json",
  "examples/invalid/unknown-without-deadline.json",
  "examples/invalid/ack-without-buyer.json",
  "examples/invalid/artifact-too-large.json",
]) {
  test(`negative schema example: ${fixture}`, () => {
    const testCase = load(fixture);
    const validate = validatorFor(testCase.definition);
    assert.equal(validate(testCase.value), false, `${fixture} must be rejected`);
    assert.equal(testCase.expectedCode, "SCHEMA_INVALID");
    contractError(testCase.expectedCode);
  });
}

test("semantic rejections are stable and registered", () => {
  const fixture = load("examples/invalid/semantic-cases.json");
  for (const testCase of fixture.cases) {
    assert.equal(semanticResult(testCase), testCase.expectedCode, testCase.kind);
    contractError(testCase.expectedCode);
  }
});

const reviewDomainCases = load("examples/valid/domain-objects.json").cases;
const reviewPaymentCases = load("examples/valid/payment-flow.json").cases;
const reviewReceiptCases = load("examples/valid/receipts.json").cases;
const reviewProofBundle = load("examples/valid/proof-bundle.json");

test("Service SKU root resolves exact immutable components and repeated authority fields", () => {
  for (const id of [
    "BIND-SKU-DEFINITION-RESOLUTION",
    "BIND-SKU-OFFER-RESOLUTION",
    "BIND-SKU-ENDPOINT-RESOLUTION",
    "BIND-LISTING-SKU-ROOT",
    "BIND-LISTING-SKU-SELLER",
    "BIND-SKU-DEFINITION-OPERATION",
  ]) assert.equal(hasBinding(id), true, id);
  const definition = reviewDomainCases.find(
    ({ definition: name }) => name === "serviceDefinitionVersion",
  ).value;
  const offer = reviewDomainCases.find(
    ({ definition: name }) => name === "offerVersion",
  ).value;
  const endpoint = reviewDomainCases.find(
    ({ definition: name }) => name === "endpointDescriptorVersion",
  ).value;
  const sku = reviewDomainCases.find(
    ({ definition: name }) => name === "serviceSkuVersion",
  ).value;
  const listing = reviewDomainCases.find(
    ({ definition: name }) => name === "listingMandate",
  ).value;
  assert.equal(skuRootBindingResult(definition, offer, endpoint, sku, listing), null);
  for (const mutate of [
    (value) => { value.sku.serviceDefinitionVersionDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; },
    (value) => { value.sku.offerVersionDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; },
    (value) => { value.sku.endpointDescriptorVersionDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; },
    (value) => { value.listing.skuVersionDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; },
    (value) => { value.listing.sellerIdentityRef = "seller_attacker"; },
    (value) => { value.sku.operationId = "operation_attacker_1"; },
  ]) {
    const candidate = {
      definition: structuredClone(definition),
      offer: structuredClone(offer),
      endpoint: structuredClone(endpoint),
      sku: structuredClone(sku),
      listing: structuredClone(listing),
    };
    mutate(candidate);
    assert.equal(
      skuRootBindingResult(
        candidate.definition,
        candidate.offer,
        candidate.endpoint,
        candidate.sku,
        candidate.listing,
      ),
      "CHALLENGE_INVALID",
    );
  }
});

test("SKU roots reject Endpoint mode and Offer assurance combinations with no Phase 0 path", () => {
  assert.equal(hasBinding("BIND-SKU-MODE-ASSURANCE"), true);
  assert.deepEqual(contract.modeAssuranceCompatibility, {
    DIRECT: {
      delivery: ["DIRECT_BUYER_ACCEPTED"],
      contentCustody: ["DIRECT"],
    },
    HOSTED: {
      delivery: ["HOSTED_RECOVERABLE"],
      contentCustody: ["HOSTED_EPHEMERAL", "HOSTED_ENCRYPTED_BUFFER"],
    },
  });
  const offer = structuredClone(reviewDomainCases.find(
    ({ definition: name }) => name === "offerVersion",
  ).value);
  const endpoint = structuredClone(reviewDomainCases.find(
    ({ definition: name }) => name === "endpointDescriptorVersion",
  ).value);
  assert.equal(skuModeAssuranceBindingResult(endpoint, offer), null);

  const hostedEphemeral = structuredClone(offer);
  hostedEphemeral.minimumAssurance.contentCustody = "HOSTED_EPHEMERAL";
  assert.equal(skuModeAssuranceBindingResult(endpoint, hostedEphemeral), null);

  const directEndpoint = structuredClone(endpoint);
  directEndpoint.mode = "DIRECT";
  delete directEndpoint.stagingIssuerKeys;
  delete directEndpoint.deliveryIssuerKeys;
  const directOffer = structuredClone(offer);
  directOffer.minimumAssurance.delivery = "DIRECT_BUYER_ACCEPTED";
  directOffer.minimumAssurance.contentCustody = "DIRECT";
  assert.equal(skuModeAssuranceBindingResult(directEndpoint, directOffer), null);

  for (const [name, candidateEndpoint, mutate] of [
    ["Direct with Hosted assurance", directEndpoint, () => {}],
    ["Direct with Hosted custody", directEndpoint, (candidate) => {
      candidate.minimumAssurance.delivery = "DIRECT_BUYER_ACCEPTED";
    }],
    ["Direct with Hosted delivery", directEndpoint, (candidate) => {
      candidate.minimumAssurance.contentCustody = "DIRECT";
    }],
    ["Hosted with Direct assurance", endpoint, (candidate) => {
      candidate.minimumAssurance.delivery = "DIRECT_BUYER_ACCEPTED";
      candidate.minimumAssurance.contentCustody = "DIRECT";
    }],
    ["Hosted with NONE delivery", endpoint, (candidate) => {
      candidate.minimumAssurance.delivery = "NONE";
    }],
    ["Hosted with SELLER_ASSERTED delivery", endpoint, (candidate) => {
      candidate.minimumAssurance.delivery = "SELLER_ASSERTED";
    }],
  ]) {
    const candidateOffer = structuredClone(offer);
    mutate(candidateOffer);
    assert.equal(
      skuModeAssuranceBindingResult(candidateEndpoint, candidateOffer),
      "CHALLENGE_INVALID",
      name,
    );
  }
});

test("an authorized challenge issuer cannot rewrite immutable SKU-root terms", () => {
  for (const id of [
    "BIND-CHALLENGE-SKU-ROOT",
    "BIND-CHALLENGE-DEFINITION",
    "BIND-CHALLENGE-OFFER-TERMS",
    "BIND-CHALLENGE-ENDPOINT",
  ]) assert.equal(hasBinding(id), true, id);
  const definition = reviewDomainCases.find(
    ({ definition: name }) => name === "serviceDefinitionVersion",
  ).value;
  const offer = reviewDomainCases.find(
    ({ definition: name }) => name === "offerVersion",
  ).value;
  const endpoint = reviewDomainCases.find(
    ({ definition: name }) => name === "endpointDescriptorVersion",
  ).value;
  const sku = reviewDomainCases.find(
    ({ definition: name }) => name === "serviceSkuVersion",
  ).value;
  const outcome = reviewPaymentCases.find(
    ({ definition: name }) => name === "paymentRequiredOutcome",
  ).value;
  assert.equal(challengeRootBindingResult(outcome, definition, offer, endpoint, sku), null);
  const missingResource = structuredClone(outcome);
  delete missingResource.paymentRequired.resource;
  assert.equal(
    validatorFor("paymentRequiredOutcome")(missingResource),
    false,
    "a challenge without the resolved endpoint projection is structurally incomplete",
  );
  const missingMediaType = structuredClone(outcome);
  delete missingMediaType.paymentRequired.resource.mimeType;
  assert.equal(validatorFor("paymentRequiredOutcome")(missingMediaType), false);

  const intent = reviewPaymentCases.find(
    ({ definition: name }) => name === "paymentIntent",
  ).value;
  const proof = reviewReceiptCases.find(
    ({ value }) => value.objectType === "MandateAuthorizationProof",
  ).value;
  const amountAttack = structuredClone(outcome);
  const attackedExtension = amountAttack.paymentRequired.extensions.openant;
  amountAttack.paymentRequired.accepts[0].amount = attackedExtension.amountAtomic = "999999";
  attackedExtension.signature.signedObjectDigest =
    "sha256:fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe";
  const attackedIntent = structuredClone(intent);
  const attackedProof = structuredClone(proof);
  attackedIntent.amountAtomic = attackedProof.amountAtomic = "999999";
  attackedIntent.challengeDigest = attackedProof.challengeDigest =
    attackedExtension.signature.signedObjectDigest;
  assert.equal(paymentIntentChallengeBindingResult(attackedIntent, attackedExtension), null);
  assert.equal(mandateProofBindingResult(attackedIntent, attackedProof), null);
  assert.equal(
    challengeRootBindingResult(amountAttack, definition, offer, endpoint, sku),
    "CHALLENGE_INVALID",
    "root Offer remains authoritative under lockstep PI/proof mutation",
  );

  for (const [name, mutate] of [
    ["payout", (value) => {
      value.paymentRequired.extensions.openant.payoutAddress =
        value.paymentRequired.accepts[0].payTo =
          "0x3333333333333333333333333333333333333333";
    }],
    ["asset", (value) => {
      value.paymentRequired.extensions.openant.asset.reference =
        "0x3333333333333333333333333333333333333333";
    }],
    ["assurance", (value) => {
      value.paymentRequired.extensions.openant.assurance.identity = "ANONYMOUS_WALLET";
    }],
    ["mode", (value) => { value.paymentRequired.extensions.openant.mode = "DIRECT"; }],
    ["resource endpoint", (value) => {
      value.paymentRequired.resource.url = "https://attacker.example/invoke";
    }],
    ["resource media type", (value) => {
      value.paymentRequired.resource.mimeType = "application/octet-stream";
    }],
    ["challenge key", (value) => {
      value.paymentRequired.extensions.openant.signature.keyId = "key_challenge_legacy";
    }],
  ]) {
    const malicious = structuredClone(outcome);
    mutate(malicious);
    assert.equal(
      challengeRootBindingResult(malicious, definition, offer, endpoint, sku),
      "CHALLENGE_INVALID",
      name,
    );
  }
});

test("Invocation identity and mode are derived from the resolved SKU roots", () => {
  for (const id of [
    "BIND-INVOCATION-SKU-ROOT",
    "BIND-INVOCATION-DEFINITION",
    "BIND-INVOCATION-ENDPOINT",
  ]) assert.equal(hasBinding(id), true, id);
  const definition = reviewDomainCases.find(
    ({ definition: name }) => name === "serviceDefinitionVersion",
  ).value;
  const endpoint = reviewDomainCases.find(
    ({ definition: name }) => name === "endpointDescriptorVersion",
  ).value;
  const sku = reviewDomainCases.find(
    ({ definition: name }) => name === "serviceSkuVersion",
  ).value;
  const invocation = reviewPaymentCases.find(
    ({ definition: name }) => name === "invocation",
  ).value;
  assert.equal(invocationRootBindingResult(invocation, definition, endpoint, sku), null);
  for (const [name, mutate] of [
    ["service SKU", (value) => { value.serviceSkuId = "sku_attacker_1"; }],
    ["SKU root", (value) => { value.skuVersionDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; }],
    ["operation", (value) => { value.operationId = "operation_attacker_1"; }],
    ["endpoint mode", (value) => { value.mode = "DIRECT"; }],
  ]) {
    const malicious = structuredClone(invocation);
    mutate(malicious);
    assert.equal(
      invocationRootBindingResult(malicious, definition, endpoint, sku),
      "CHALLENGE_INVALID",
      name,
    );
  }
});

test("execution projections bind the Invocation request and Hosted recovery lineage", () => {
  for (const id of [
    "BIND-STAGING-INVOCATION-REQUEST",
    "BIND-EXECUTION-INVOCATION-REQUEST",
    "BIND-COMMERCE-INVOCATION-REQUEST",
    "BIND-HOSTED-RECOVERY-CONTENT",
  ]) assert.equal(hasBinding(id), true, id);
  const invocation = reviewPaymentCases.find(
    ({ definition: name }) => name === "invocation",
  ).value;
  const byType = new Map(reviewReceiptCases.map(({ value }) => [value.objectType, value]));
  for (const type of ["OutputStagingReceipt", "ExecutionReceipt", "CommerceReceipt"]) {
    const receipt = byType.get(type);
    assert.equal(requestReceiptBindingResult(invocation, receipt), null, type);
    const malicious = structuredClone(receipt);
    malicious.requestDigest =
      "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    assert.equal(requestReceiptBindingResult(invocation, malicious), "PROOF_BINDING_MISMATCH");
  }
  const staging = byType.get("OutputStagingReceipt");
  const delivery = byType.get("DeliveryReceipt");
  assert.equal(hostedRecoveryBindingResult(staging, delivery), null);
  for (const mutate of [
    (value) => { value.responseDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; },
    (value) => { value.contentBytes += 1; },
    (value) => { value.availableUntil = "2026-08-12T00:03:00Z"; },
  ]) {
    const malicious = structuredClone(delivery);
    mutate(malicious);
    assert.equal(hostedRecoveryBindingResult(staging, malicious), "PROOF_BINDING_MISMATCH");
  }
});

test("CommerceReceipt settlement reference and issuer are independently authorized", () => {
  for (const id of [
    "BIND-COMMERCE-SETTLEMENT-RECEIPT",
    "BIND-COMMERCE-RECEIPT-ENDPOINT-ISSUER",
  ]) assert.equal(hasBinding(id), true, id);
  const endpoint = reviewDomainCases.find(
    ({ definition: name }) => name === "endpointDescriptorVersion",
  ).value;
  const commerce = reviewReceiptCases.find(
    ({ value }) => value.objectType === "CommerceReceipt",
  ).value;
  const settlement = reviewReceiptCases.find(
    ({ value }) => value.objectType === "SettlementReceipt",
  ).value;
  assert.equal(commerceReceiptBindingResult(commerce, settlement, endpoint), null);
  const replay = structuredClone(settlement);
  replay.invocationId = "invocation_replayed";
  assert.equal(commerceReceiptBindingResult(commerce, replay, endpoint), "PROOF_BINDING_MISMATCH");
  const attacker = structuredClone(commerce);
  attacker.issuer.issuer = attacker.signature.issuer = "attacker_commerce";
  attacker.issuer.keyId = attacker.signature.keyId = "key_attacker_1";
  assert.equal(receiptBindingResult(attacker), null, "self-consistent attacker receipt");
  assert.equal(commerceReceiptBindingResult(attacker, settlement, endpoint), "PROOF_BINDING_MISMATCH");
});

test("signed objects and Hosted recovery windows obey their registered temporal contracts", () => {
  for (const id of [
    "BIND-X402-VALID-TIME",
    "BIND-PAYMENT-INTENT-VALID-TIME",
    "BIND-PAYMENT-INTENT-CHALLENGE-TIME",
    "BIND-WALLET-PROOF-VALID-TIME",
    "BIND-MANDATE-PROOF-INTENT-TIME",
    "BIND-WALLET-PROOF-INTENT-TIME",
    "BIND-WALLET-PROOF-LIVE-TIME",
    "BIND-TASK-AGREEMENT-VALID-TIME",
    "BIND-STAGING-VALID-TIME",
    "BIND-DELIVERY-VALID-TIME",
    "BIND-ACK-DELIVERY-TIME",
    "BIND-HOSTED-RECOVERY-WINDOW",
  ]) assert.equal(hasBinding(id), true, id);
  const outcome = reviewPaymentCases.find(
    ({ definition: name }) => name === "paymentRequiredOutcome",
  ).value;
  const extension = outcome.paymentRequired.extensions.openant;
  const intent = reviewPaymentCases.find(
    ({ definition: name }) => name === "paymentIntent",
  ).value;
  const wallet = reviewReceiptCases.find(
    ({ value }) => value.objectType === "WalletAuthorizationProof",
  ).value;
  const agreement = reviewDomainCases.find(
    ({ definition: name }) => name === "taskAgreementVersion",
  ).value;
  assert.equal(Date.parse(extension.issuedAt) <= Date.parse(extension.expiresAt), true);
  assert.equal(Date.parse(intent.createdAt) <= Date.parse(intent.expiresAt), true);
  assert.equal(Date.parse(wallet.issuedAt) < Date.parse(wallet.expiresAt), true);
  assert.equal(Date.parse(agreement.validFrom) <= Date.parse(agreement.validUntil), true);
  assert.equal(Date.parse(extension.issuedAt) <= Date.parse(intent.createdAt), true);
  assert.equal(Date.parse(intent.createdAt) <= Date.parse(wallet.issuedAt), true);

  const invocation = reviewPaymentCases.find(
    ({ definition: name }) => name === "invocation",
  ).value;
  const offer = reviewDomainCases.find(
    ({ definition: name }) => name === "offerVersion",
  ).value;
  const staging = reviewReceiptCases.find(
    ({ value }) => value.objectType === "OutputStagingReceipt",
  ).value;
  const delivery = reviewReceiptCases.find(
    ({ value }) => value.objectType === "DeliveryReceipt",
  ).value;
  const acknowledgement = reviewPaymentCases.find(
    ({ definition: name }) => name === "deliveryAcknowledgement",
  ).value;
  assert.equal(
    hostedRecoveryTimeBindingResult(
      invocation,
      offer,
      staging,
      delivery,
      acknowledgement,
      reviewProofBundle.value,
    ),
    null,
  );
  for (const [name, mutate] of [
    ["staging before invocation", (value) => { value.staging.issuedAt = "2026-08-09T23:59:59Z"; }],
    ["wrong recovery duration", (value) => { value.staging.availableUntil = value.delivery.availableUntil = "2026-08-12T00:03:00Z"; }],
    ["delivery after availability", (value) => { value.delivery.issuedAt = "2026-08-11T00:03:01Z"; }],
    ["ack before delivery", (value) => { value.acknowledgement.receivedAt = "2026-08-10T00:04:59Z"; }],
    ["bundle after recovery", (value) => { value.bundle.createdAt = "2026-08-11T00:03:01Z"; }],
  ]) {
    const value = {
      staging: structuredClone(staging),
      delivery: structuredClone(delivery),
      acknowledgement: structuredClone(acknowledgement),
      bundle: structuredClone(reviewProofBundle.value),
    };
    mutate(value);
    assert.equal(
      hostedRecoveryTimeBindingResult(
        invocation,
        offer,
        value.staging,
        value.delivery,
        value.acknowledgement,
        value.bundle,
      ),
      "PROOF_BINDING_MISMATCH",
      name,
    );
  }
});

test("output evidence must exist before settlement in Hosted and Direct modes", () => {
  assert.equal(hasBinding("BIND-EVIDENCE-CHRONOLOGY"), true);
  const byType = new Map(reviewReceiptCases.map(({ value }) => [value.objectType, value]));
  const authorizationProof = byType.get("MandateAuthorizationProof");
  const staging = byType.get("OutputStagingReceipt");
  const execution = byType.get("ExecutionReceipt");
  const settlement = byType.get("SettlementReceipt");
  const delivery = byType.get("DeliveryReceipt");
  const acceptance = byType.get("AcceptanceReceipt");
  const acknowledgement = reviewPaymentCases.find(
    ({ definition: name }) => name === "deliveryAcknowledgement",
  ).value;
  const evidence = {
    authorizationProof,
    staging,
    execution,
    settlement,
    delivery,
    acknowledgement,
    acceptance,
  };
  assert.equal(evidenceChronologyBindingResult({ ...evidence, mode: "HOSTED" }), null);
  assert.equal(evidenceChronologyBindingResult({ ...evidence, mode: "DIRECT" }), null);

  const prematureHostedSettlement = structuredClone(evidence);
  prematureHostedSettlement.settlement.issuedAt = "2026-08-10T00:02:59Z";
  assert.equal(
    evidenceChronologyBindingResult({ ...prematureHostedSettlement, mode: "HOSTED" }),
    "PROOF_BINDING_MISMATCH",
  );
  const prematureDirectSettlement = structuredClone(evidence);
  prematureDirectSettlement.settlement.issuedAt = "2026-08-10T00:02:58Z";
  assert.equal(
    evidenceChronologyBindingResult({ ...prematureDirectSettlement, mode: "DIRECT" }),
    "PROOF_BINDING_MISMATCH",
  );
  const deliveryBeforeSettlement = structuredClone(evidence);
  deliveryBeforeSettlement.delivery.issuedAt = "2026-08-10T00:03:59Z";
  assert.equal(
    evidenceChronologyBindingResult({ ...deliveryBeforeSettlement, mode: "HOSTED" }),
    "PROOF_BINDING_MISMATCH",
  );
});

test("Direct buyer acceptance must bind the exact executed content", () => {
  assert.equal(hasBinding("BIND-DIRECT-ACCEPTANCE-CONTENT"), true);
  const execution = structuredClone(reviewReceiptCases.find(
    ({ value }) => value.objectType === "ExecutionReceipt",
  ).value);
  const acceptance = structuredClone(reviewReceiptCases.find(
    ({ value }) => value.objectType === "AcceptanceReceipt",
  ).value);
  assert.equal(directAcceptanceContentBindingResult(execution, acceptance), null);

  for (const [name, mutate] of [
    ["invocation", (value) => { value.acceptance.invocationId = "invocation_attacker"; }],
    ["SKU", (value) => {
      value.acceptance.serviceSkuVersionDigest =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    }],
    ["response digest", (value) => {
      value.acceptance.responseDigest =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    }],
    ["content kind", (value) => {
      delete value.acceptance.responseDigest;
      value.acceptance.artifactManifestDigest =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    }],
    ["content bytes", (value) => { value.acceptance.contentBytes += 1; }],
  ]) {
    const value = {
      execution: structuredClone(execution),
      acceptance: structuredClone(acceptance),
    };
    mutate(value);
    assert.equal(
      directAcceptanceContentBindingResult(value.execution, value.acceptance),
      "PROOF_BINDING_MISMATCH",
      `mixed Direct evidence must reject mismatched ${name}`,
    );
  }
});

test("DELIVERED and ACKED Invocations require a delivered DeliveryReceipt", () => {
  assert.equal(hasBinding("BIND-INVOCATION-DELIVERY-STATE"), true);
  const invocation = structuredClone(reviewPaymentCases.find(
    ({ definition: name }) => name === "invocation",
  ).value);
  const delivery = structuredClone(reviewReceiptCases.find(
    ({ value }) => value.objectType === "DeliveryReceipt",
  ).value);
  Object.assign(invocation, {
    state: "DELIVERED",
    paymentIntentRef: "payment_intent_1",
    paymentProofDigest: "sha256:1010101010101010101010101010101010101010101010101010101010101010",
    outputStagingReceiptDigest: "sha256:6060606060606060606060606060606060606060606060606060606060606060",
    settlementReceiptDigest: "sha256:4040404040404040404040404040404040404040404040404040404040404040",
    deliveryReceiptDigest: delivery.claimsDigest,
  });
  assert.equal(validatorFor("invocation")(invocation), true);
  assert.equal(invocationDeliveryStateBindingResult(invocation, delivery), null);
  delivery.deliveryState = "DELIVERABLE";
  assert.equal(validatorFor("deliveryReceipt")(delivery), true);
  assert.equal(
    invocationDeliveryStateBindingResult(invocation, delivery),
    "PROOF_BINDING_MISMATCH",
  );
});

test("ProofBundle funding evidence cannot mix authorization A with settlement B", () => {
  assert.equal(hasBinding("BIND-PROOF-BUNDLE-FUNDING-LINEAGE"), true);
  const bundle = structuredClone(reviewProofBundle.value);
  const invocation = structuredClone(reviewPaymentCases.find(
    ({ definition: name }) => name === "invocation",
  ).value);
  const paymentIntent = reviewPaymentCases.find(
    ({ definition: name }) => name === "paymentIntent",
  ).value;
  invocation.paymentIntentRef = paymentIntent.paymentIntentId;
  const byType = new Map(reviewReceiptCases.map(({ value }) => [value.objectType, value]));
  const mandate = byType.get("MandateAuthorizationProof");
  const settlement = byType.get("SettlementReceipt");
  const unknown = byType.get("FundingUnknownObservation");
  const commerce = byType.get("CommerceReceipt");
  assert.equal(
    proofBundleFundingLineageResult(
      bundle,
      invocation,
      paymentIntent,
      [mandate, settlement, unknown, commerce],
      new Map([[settlement.claimsDigest, settlement]]),
    ),
    null,
  );

  const settlementB = structuredClone(settlement);
  settlementB.paymentIntentId = "payment_intent_B";
  settlementB.paymentIntentFingerprintDigest =
    "sha256:bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc";
  settlementB.paymentAuthorizationDigest =
    "sha256:bdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbd";
  settlementB.claimsDigest = settlementB.signature.signedObjectDigest =
    "sha256:bebebebebebebebebebebebebebebebebebebebebebebebebebebebebebebe";
  const settlementReferenceB = structuredClone(bundle.proofs.find(
    ({ objectType }) => objectType === "SettlementReceipt",
  ));
  settlementReferenceB.objectDigest = settlementB.claimsDigest;
  assert.equal(
    proofReferenceBindingResult(bundle, settlementReferenceB, settlementB),
    null,
    "B is individually valid and has the same Invocation/SKU scope",
  );
  assert.equal(
    proofBundleFundingLineageResult(
      bundle,
      invocation,
      paymentIntent,
      [mandate, settlementB],
    ),
    "PROOF_BINDING_MISMATCH",
  );

  const commerceB = structuredClone(commerce);
  commerceB.settlementReceiptDigest = settlementB.claimsDigest;
  assert.equal(
    proofBundleFundingLineageResult(
      bundle,
      invocation,
      paymentIntent,
      [mandate, commerceB],
      new Map([[settlementB.claimsDigest, settlementB]]),
    ),
    "PROOF_BINDING_MISMATCH",
    "CommerceReceipt cannot hide a settlement from payment B",
  );
});

test("Hosted and Direct Invocation modes each have a reachable evidence-valid happy path", () => {
  for (const id of [
    "BIND-INVOCATION-EXECUTION-PROOF",
    "BIND-INVOCATION-ACCEPTANCE-PROOF",
  ]) assert.equal(hasBinding(id), true, id);
  const machine = contract.stateMachines.invocation;
  assert.ok(machine.modeTransitions?.HOSTED);
  assert.ok(machine.modeTransitions?.DIRECT);
  const hasModeEdge = (mode, from, to) => machine.modeTransitions[mode].some(
    ([edgeFrom, edgeTo]) => edgeFrom === from && edgeTo === to,
  );
  for (const [from, to] of [
    ["EXECUTING", "OUTPUT_STAGED"],
    ["OUTPUT_STAGED", "SETTLEMENT_PENDING"],
    ["SETTLEMENT_PENDING", "DELIVERABLE"],
    ["DELIVERABLE", "DELIVERED"],
    ["DELIVERED", "ACKED"],
  ]) assert.equal(hasModeEdge("HOSTED", from, to), true, `HOSTED ${from}->${to}`);
  for (const [from, to] of [
    ["EXECUTING", "SETTLEMENT_PENDING"],
    ["SETTLEMENT_PENDING", "ACKED"],
    ["PAYMENT_UNKNOWN", "ACKED"],
  ]) assert.equal(hasModeEdge("DIRECT", from, to), true, `DIRECT ${from}->${to}`);
  assert.equal(
    machine.modeTransitions.DIRECT.some(([from, to]) =>
      from === "DELIVERED" || to === "DELIVERED"),
    false,
    "Direct must not project the Hosted DELIVERED state",
  );
  const isReachable = (mode, target) => {
    const seen = new Set([machine.initial]);
    let changed = true;
    while (changed) {
      changed = false;
      for (const [from, to] of machine.modeTransitions[mode]) {
        if (seen.has(from) && !seen.has(to)) {
          seen.add(to);
          changed = true;
        }
      }
    }
    return seen.has(target);
  };
  assert.equal(isReachable("HOSTED", "ACKED"), true);
  assert.equal(isReachable("DIRECT", "ACKED"), true);

  const base = reviewPaymentCases.find(
    ({ definition: name }) => name === "invocation",
  ).value;
  const directSettlementPending = structuredClone(base);
  Object.assign(directSettlementPending, {
    mode: "DIRECT",
    state: "SETTLEMENT_PENDING",
    paymentIntentRef: "payment_intent_1",
    paymentProofDigest: "sha256:1010101010101010101010101010101010101010101010101010101010101010",
    executionReceiptDigest: "sha256:7070707070707070707070707070707070707070707070707070707070707070",
  });
  assert.equal(
    validatorFor("invocation")(directSettlementPending),
    true,
    ajv.errorsText(validatorFor("invocation").errors),
  );
  const directDelivered = structuredClone(directSettlementPending);
  directDelivered.state = "DELIVERED";
  directDelivered.settlementReceiptDigest =
    "sha256:4040404040404040404040404040404040404040404040404040404040404040";
  assert.equal(validatorFor("invocation")(directDelivered), false);
  const directAcked = structuredClone(directSettlementPending);
  directAcked.state = "ACKED";
  directAcked.settlementReceiptDigest =
    "sha256:4040404040404040404040404040404040404040404040404040404040404040";
  directAcked.acceptanceReceiptDigest =
    "sha256:9090909090909090909090909090909090909090909090909090909090909090";
  assert.equal(validatorFor("invocation")(directAcked), true);

  const illegalDirectStaging = structuredClone(directSettlementPending);
  illegalDirectStaging.state = "OUTPUT_STAGED";
  illegalDirectStaging.outputStagingReceiptDigest =
    "sha256:6060606060606060606060606060606060606060606060606060606060606060";
  assert.equal(validatorFor("invocation")(illegalDirectStaging), false);
  const hostedWithoutStaging = structuredClone(directSettlementPending);
  hostedWithoutStaging.mode = "HOSTED";
  assert.equal(validatorFor("invocation")(hostedWithoutStaging), false);
  for (const state of ["CREATED", "PAYMENT_REQUIRED", "PAYMENT_AUTHORIZED", "EXECUTING"]) {
    const prematureDirectExecutionEvidence = structuredClone(directSettlementPending);
    prematureDirectExecutionEvidence.state = state;
    delete prematureDirectExecutionEvidence.executionReceiptDigest;
    if (["CREATED", "PAYMENT_REQUIRED"].includes(state)) {
      delete prematureDirectExecutionEvidence.paymentIntentRef;
      delete prematureDirectExecutionEvidence.paymentProofDigest;
    }
    assert.equal(
      validatorFor("invocation")(prematureDirectExecutionEvidence),
      true,
      `baseline Direct ${state} projection must be valid`,
    );
    prematureDirectExecutionEvidence.executionReceiptDigest =
      "sha256:7070707070707070707070707070707070707070707070707070707070707070";
    assert.equal(
      validatorFor("invocation")(prematureDirectExecutionEvidence),
      false,
      `Direct ${state} cannot claim completed execution evidence`,
    );
  }

  const directBundle = structuredClone(reviewProofBundle.value);
  directBundle.assurance.delivery = "DIRECT_BUYER_ACCEPTED";
  directBundle.assurance.contentCustody = "DIRECT";
  directBundle.createdAt = "2026-08-10T00:06:00Z";
  directBundle.proofs = directBundle.proofs.filter(({ objectType }) =>
    !["OutputStagingReceipt", "DeliveryReceipt"].includes(objectType));
  directBundle.proofs.push({
    objectType: "AcceptanceReceipt",
    invocationId: "invocation_weather_1",
    serviceSkuVersionDigest: "sha256:4444444444444444444444444444444444444444444444444444444444444444",
    issuer: "agent_buyer_1",
    keyId: "key_acceptance_1",
    objectDigest: "sha256:9090909090909090909090909090909090909090909090909090909090909090",
    issuedAt: "2026-08-10T00:06:00Z",
    disclosure: "PRIVATE_HELD",
  });
  assert.equal(
    validatorFor("proofBundle")(directBundle),
    false,
    "Direct acceptance without ExecutionReceipt cannot prove pre-settlement output",
  );
  directBundle.proofs.push({
    objectType: "ExecutionReceipt",
    invocationId: "invocation_weather_1",
    serviceSkuVersionDigest: "sha256:4444444444444444444444444444444444444444444444444444444444444444",
    issuer: "seller_acme",
    keyId: "key_execution_1",
    objectDigest: "sha256:7070707070707070707070707070707070707070707070707070707070707070",
    issuedAt: "2026-08-10T00:02:59Z",
    disclosure: "PRIVATE_HELD",
  });
  assert.equal(
    validatorFor("proofBundle")(directBundle),
    true,
    ajv.errorsText(validatorFor("proofBundle").errors),
  );
});

test("recovery with delivery evidence requires a delivered receipt", () => {
  const invocation = structuredClone(reviewPaymentCases.find(
    ({ definition: name }) => name === "invocation",
  ).value);
  const delivery = structuredClone(reviewReceiptCases.find(
    ({ value }) => value.objectType === "DeliveryReceipt",
  ).value);
  Object.assign(invocation, {
    state: "RECOVERY_WINDOW_EXPIRED",
    paymentIntentRef: "payment_intent_1",
    paymentProofDigest: "sha256:1010101010101010101010101010101010101010101010101010101010101010",
    outputStagingReceiptDigest: "sha256:6060606060606060606060606060606060606060606060606060606060606060",
    settlementReceiptDigest: "sha256:4040404040404040404040404040404040404040404040404040404040404040",
    deliveryReceiptDigest: delivery.claimsDigest,
  });
  delivery.deliveryState = "DELIVERABLE";
  assert.equal(
    invocationDeliveryStateBindingResult(invocation, delivery),
    "PROOF_BINDING_MISMATCH",
  );
});

test("review probe 1: PAYMENT_UNKNOWN requires signed observation and deadline", () => {
  const paymentUnknown = structuredClone(
    reviewPaymentCases.find(({ definition }) => definition === "invocation").value,
  );
  Object.assign(paymentUnknown, {
    state: "PAYMENT_UNKNOWN",
    paymentIntentRef: "payment_intent_1",
    paymentProofDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    outputStagingReceiptDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  });
  assert.equal(validatorFor("invocation")(paymentUnknown), false, "PAYMENT_UNKNOWN needs signed observation and deadline");
  paymentUnknown.reconciliationDeadline = "2026-08-10T00:20:00Z";
  assert.equal(validatorFor("invocation")(paymentUnknown), false, "deadline alone cannot prove UNKNOWN");
  paymentUnknown.paymentUnknownObservationProofDigest = "sha256:abababababababababababababababababababababababababababababababab";
  assert.equal(validatorFor("invocation")(paymentUnknown), true, "signed UNKNOWN observation and deadline converge");
});

test("review probe 2: settlement receipt cannot carry delivery claims", () => {
  const settlement = structuredClone(
    reviewReceiptCases.find(({ value }) => value.objectType === "SettlementReceipt").value,
  );
  settlement.responseDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  settlement.buyerActorRef = "buyer_actor_1";
  assert.equal(validatorFor("receiptEnvelope")(settlement), false, "SettlementReceipt cannot claim delivery");
});

test("review probe 3: pre-settlement failure cannot carry later proof digests", () => {
  const failedInvocation = structuredClone(
    reviewPaymentCases.find(({ definition }) => definition === "invocation").value,
  );
  Object.assign(failedInvocation, {
    state: "FAILED_BEFORE_SETTLEMENT",
    settlementReceiptDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    deliveryReceiptDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    acknowledgementDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
  });
  assert.equal(validatorFor("invocation")(failedInvocation), false, "pre-settlement failure cannot carry later proofs");
});

test("review probe 4: zero payout is invalid", () => {
  const offer = structuredClone(
    reviewDomainCases.find(({ definition }) => definition === "offerVersion").value,
  );
  offer.payoutAddress = "0x0000000000000000000000000000000000000000";
  assert.equal(validatorFor("offerVersion")(offer), false, "zero payout must fail");
});

test("review probe 5: assurance claims require custody and identity proofs", () => {
  const incompleteProofBundle = structuredClone(reviewProofBundle.value);
  incompleteProofBundle.proofs = incompleteProofBundle.proofs.filter(
    ({ objectType }) => objectType !== "SellerIdentityCredential",
  );
  assert.equal(validatorFor("proofBundle")(incompleteProofBundle), false, "verified seller needs identity proof");
});

test("review probe 6: unsigned duplicate PaymentRequired invocation ID is forbidden", () => {
  assert.ok(
    contract.crossObjectBindings.find(({ id }) => id === "BIND-PAYMENT-REQUIRED-INVOCATION"),
  );
  const paymentRequired = structuredClone(
    reviewPaymentCases.find(({ definition }) => definition === "paymentRequiredOutcome").value,
  );
  paymentRequired.invocationId = "invocation_other_1";
  assert.equal(validatorFor("paymentRequiredOutcome")(paymentRequired), false, "unsigned duplicate invocation ID is forbidden");
});

test("review probe 7: ListingMandate seller must equal signature issuer", () => {
  assert.ok(
    contract.crossObjectBindings.find(({ id }) => id === "BIND-LISTING-SELLER-SIGNATURE"),
  );
  const mismatch = {
    kind: "listingSellerIssuerMismatch",
    listingMandate: {
      sellerIdentityRef: "seller_acme",
      signature: { issuer: "seller_attacker" },
    },
  };
  assert.equal(semanticResult(mismatch), "CHALLENGE_INVALID");
});

test("review probe 8: impossible Gregorian dates are invalid", () => {
  const listing = structuredClone(
    reviewDomainCases.find(({ definition }) => definition === "listingMandate").value,
  );
  listing.validFrom = "2026-02-31T00:00:00Z";
  assert.equal(validatorFor("listingMandate")(listing), false, "invalid calendar date must fail");
});

test("review follow-up: mandate authorization proof binds all funding authority inputs", () => {
  const validMandateProof = reviewReceiptCases.find(
    ({ value }) => value.objectType === "MandateAuthorizationProof",
  ).value;
  for (const binding of [
    "paymentIntentFingerprintDigest",
    "fundingLedgerNamespace",
    "tenantId",
    "memberSuborgId",
    "treasuryProfile",
    "treasuryRef",
    "agentId",
    "runtimeId",
    "serviceSkuVersionDigest",
    "sellerIdentityRef",
    "mandateId",
    "mandateVersion",
    "runtimeCapabilityDigest",
    "reservationId",
    "challengeDigest",
    "paymentAuthorizationDigest",
    "decisionCode",
    "expiresAt",
    "amountAtomic",
    "asset",
    "payerAddress",
    "payeeAddress",
    "mode",
    "requestedAssurance",
    "facilitatorId",
  ]) {
    const malicious = structuredClone(validMandateProof);
    delete malicious[binding];
    assert.equal(validatorFor("receiptEnvelope")(malicious), false, binding);
  }
});

test("adversarial receipt issuer, key, and claims digest must match the verified signer", () => {
  for (const bindingId of [
    "BIND-RECEIPT-ISSUER-SIGNATURE",
    "BIND-RECEIPT-KEY-SIGNATURE",
    "BIND-JWS-RECEIPT-CLAIMS-SIGNATURE",
    "BIND-WALLET-PROOF-AUTHORIZATION-SIGNATURE",
  ]) {
    assert.equal(hasBinding(bindingId), true, bindingId);
  }
  contractError("PROOF_BINDING_MISMATCH");

  const validReceipt = reviewReceiptCases.find(
    ({ value }) => value.objectType === "MandateAuthorizationProof",
  ).value;
  assert.equal(receiptBindingResult(validReceipt), null);

  for (const mutate of [
    (receipt) => { receipt.signature.issuer = "attacker_ledger"; },
    (receipt) => { receipt.signature.keyId = "attacker_key"; },
    (receipt) => {
      receipt.claimsDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    },
  ]) {
    const malicious = structuredClone(validReceipt);
    mutate(malicious);
    assert.equal(
      validatorFor("receiptEnvelope")(malicious),
      true,
      "cross-field attacks remain structurally valid and must reach semantic validation",
    );
    assert.equal(receiptBindingResult(malicious), "PROOF_BINDING_MISMATCH");
  }
});

test("adversarial DeliveryAcknowledgement signer cannot impersonate the Buyer actor", () => {
  assert.equal(hasBinding("BIND-ACK-BUYER-SIGNATURE"), true);
  const acknowledgement = structuredClone(
    reviewPaymentCases.find(({ definition }) =>
      definition === "deliveryAcknowledgement").value,
  );
  assert.equal(
    acknowledgement.buyerActorRef === acknowledgement.attestation.issuer,
    true,
  );
  acknowledgement.attestation.issuer = "buyer_attacker";
  assert.equal(
    acknowledgement.buyerActorRef === acknowledgement.attestation.issuer,
    false,
  );
});

test("DeliveryAcknowledgement content must match the resolved receipt and artifact manifest", () => {
  for (const bindingId of [
    "BIND-ACK-DELIVERY-RECEIPT",
    "BIND-ACK-INVOCATION",
    "BIND-ACK-RESPONSE-CONTENT",
    "BIND-ACK-ARTIFACT-MANIFEST",
    "BIND-ACK-ARTIFACT-CONTENT",
  ]) assert.equal(hasBinding(bindingId), true, bindingId);

  const responseAck = structuredClone(
    reviewPaymentCases.find(({ definition }) =>
      definition === "deliveryAcknowledgement").value,
  );
  const responseReceipt = structuredClone(
    reviewReceiptCases.find(({ value }) =>
      value.objectType === "DeliveryReceipt").value,
  );
  assert.equal(
    deliveryAcknowledgementBindingResult(responseAck, responseReceipt),
    null,
  );
  responseAck.receivedContentDigest =
    "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  assert.equal(
    deliveryAcknowledgementBindingResult(responseAck, responseReceipt),
    "PROOF_BINDING_MISMATCH",
  );

  const artifactManifest = reviewPaymentCases.find(({ definition }) =>
    definition === "artifactManifest").value;
  const artifactManifestDigest =
    "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
  const artifactReceipt = structuredClone(responseReceipt);
  delete artifactReceipt.responseDigest;
  artifactReceipt.artifactManifestDigest = artifactManifestDigest;
  artifactReceipt.claimsDigest =
    "sha256:9191919191919191919191919191919191919191919191919191919191919191";
  artifactReceipt.signature.signedObjectDigest = artifactReceipt.claimsDigest;
  const artifactAck = structuredClone(
    reviewPaymentCases.find(({ definition }) =>
      definition === "deliveryAcknowledgement").value,
  );
  artifactAck.contentKind = "ARTIFACT";
  artifactAck.deliveryReceiptDigest = artifactReceipt.claimsDigest;
  artifactAck.artifactManifestDigest = artifactManifestDigest;
  artifactAck.receivedContentDigest = artifactManifest.contentDigest;
  assert.equal(
    validatorFor("deliveryAcknowledgement")(artifactAck),
    true,
    ajv.errorsText(validatorFor("deliveryAcknowledgement").errors),
  );
  assert.equal(
    deliveryAcknowledgementBindingResult(
      artifactAck,
      artifactReceipt,
      artifactManifest,
      artifactManifestDigest,
    ),
    null,
  );
  delete artifactAck.artifactManifestDigest;
  assert.equal(validatorFor("deliveryAcknowledgement")(artifactAck), false);
});

test("adversarial AcceptanceReceipt signer cannot impersonate the Buyer actor", () => {
  assert.equal(hasBinding("BIND-ACCEPTANCE-BUYER-SIGNATURE"), true);
  const receipt = structuredClone(
    reviewReceiptCases.find(({ value }) =>
      value.objectType === "AcceptanceReceipt").value,
  );
  assert.equal(receipt.buyerActorRef === receipt.signature.issuer, true);
  receipt.signature.issuer = "buyer_attacker";
  assert.equal(receipt.buyerActorRef === receipt.signature.issuer, false);
});

test("adversarial x402 signer must be authorized by the resolved ListingMandate", () => {
  for (const bindingId of [
    "BIND-X402-CHALLENGE-ISSUER",
    "BIND-X402-LISTING-DIGEST",
    "BIND-X402-LISTING-SKU-ID",
    "BIND-X402-LISTING-SKU-DIGEST",
    "BIND-X402-LISTING-SELLER",
  ]) {
    assert.equal(hasBinding(bindingId), true, bindingId);
  }

  const listingMandate = reviewDomainCases.find(
    ({ definition }) => definition === "listingMandate",
  ).value;
  const outcome = reviewPaymentCases.find(
    ({ definition }) => definition === "paymentRequiredOutcome",
  ).value;
  const extension = outcome.paymentRequired.extensions.openant;
  assert.equal(challengeListingBindingResult(listingMandate, extension), null);

  const malicious = structuredClone(extension);
  malicious.signature.issuer = "attacker_gateway";
  malicious.signature.keyId = "attacker_key";
  assert.equal(challengeListingBindingResult(listingMandate, malicious), "CHALLENGE_INVALID");
});

test("x402 challenge expiry cannot exceed the resolved ListingMandate validity", () => {
  assert.equal(hasBinding("BIND-X402-LISTING-VALID-UNTIL"), true);
  const listingMandate = reviewDomainCases.find(
    ({ definition }) => definition === "listingMandate",
  ).value;
  const extension = structuredClone(
    reviewPaymentCases.find(({ definition }) =>
      definition === "paymentRequiredOutcome").value.paymentRequired.extensions.openant,
  );
  assert.equal(
    Date.parse(extension.expiresAt) <= Date.parse(listingMandate.validUntil),
    true,
  );
  extension.expiresAt = "2030-08-10T00:00:01Z";
  assert.equal(
    Date.parse(extension.expiresAt) <= Date.parse(listingMandate.validUntil),
    false,
  );
});

test("Listing and seller credential validity intervals are intrinsic and transaction-anchored", () => {
  for (const id of [
    "BIND-LISTING-VALID-TIME",
    "BIND-X402-LISTING-VALID-FROM",
    "BIND-SELLER-CREDENTIAL-VALID-TIME",
    "BIND-SELLER-CREDENTIAL-BUNDLE-TIME",
  ]) assert.equal(hasBinding(id), true, id);
  const listing = structuredClone(reviewDomainCases.find(
    ({ definition }) => definition === "listingMandate",
  ).value);
  const extension = reviewPaymentCases.find(
    ({ definition }) => definition === "paymentRequiredOutcome",
  ).value.paymentRequired.extensions.openant;
  const credential = structuredClone(reviewDomainCases.find(
    ({ definition }) => definition === "sellerIdentityCredential",
  ).value);
  const bundleCreatedAt = reviewProofBundle.value.createdAt;
  assert.equal(Date.parse(listing.validFrom) <= Date.parse(listing.validUntil), true);
  assert.equal(Date.parse(extension.issuedAt) >= Date.parse(listing.validFrom), true);
  assert.equal(Date.parse(credential.issuedAt) <= Date.parse(credential.expiresAt), true);
  assert.equal(
    Date.parse(bundleCreatedAt) >= Date.parse(credential.issuedAt) &&
      Date.parse(bundleCreatedAt) <= Date.parse(credential.expiresAt),
    true,
  );
  listing.validFrom = "2030-08-10T00:00:01Z";
  assert.equal(Date.parse(listing.validFrom) <= Date.parse(listing.validUntil), false);
  credential.issuedAt = "2030-08-10T00:00:01Z";
  assert.equal(Date.parse(credential.issuedAt) <= Date.parse(credential.expiresAt), false);
  credential.issuedAt = "2026-08-10T00:00:00Z";
  credential.expiresAt = "2026-08-10T00:04:59Z";
  assert.equal(Date.parse(bundleCreatedAt) <= Date.parse(credential.expiresAt), false);
});

test("signed x402 challenge scope must equal the resolved Invocation", () => {
  assert.equal(hasBinding("BIND-X402-INVOCATION-SCOPE"), true);
  const invocation = reviewPaymentCases.find(
    ({ definition }) => definition === "invocation",
  ).value;
  const extension = reviewPaymentCases.find(
    ({ definition }) => definition === "paymentRequiredOutcome",
  ).value.paymentRequired.extensions.openant;
  assert.equal(challengeInvocationBindingResult(invocation, extension), null);
  for (const [name, mutate] of [
    ["invocationId", (value) => { value.invocationId = "invocation_replayed"; }],
    ["operationId", (value) => { value.operationId = "operation_attacker_1"; }],
    ["serviceSkuId", (value) => { value.serviceSkuId = "sku_attacker_1"; }],
    ["skuVersionDigest", (value) => { value.skuVersionDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; }],
    ["requestDigest", (value) => { value.requestDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; }],
    ["mode", (value) => { value.mode = "DIRECT"; }],
  ]) {
    const malicious = structuredClone(invocation);
    mutate(malicious);
    assert.equal(
      challengeInvocationBindingResult(malicious, extension),
      "CHALLENGE_INVALID",
      name,
    );
  }
});

test("adversarial ProofBundle references must correlate with every resolved proof", () => {
  for (const bindingId of [
    "BIND-PROOF-REFERENCE-TYPE",
    "BIND-PROOF-REFERENCE-ISSUER",
    "BIND-PROOF-REFERENCE-KEY",
    "BIND-PROOF-REFERENCE-DIGEST",
    "BIND-PROOF-REFERENCE-ISSUED-AT",
    "BIND-PROOF-BUNDLE-INVOCATION",
    "BIND-PROOF-BUNDLE-SKU",
  ]) {
    assert.equal(hasBinding(bindingId), true, bindingId);
  }

  const bundle = reviewProofBundle.value;
  const reference = bundle.proofs.find(
    ({ objectType }) => objectType === "MandateAuthorizationProof",
  );
  const resolvedProof = reviewReceiptCases.find(
    ({ value }) => value.objectType === "MandateAuthorizationProof",
  ).value;
  assert.equal(proofReferenceBindingResult(bundle, reference, resolvedProof), null);

  for (const mutate of [
    (candidate) => { candidate.reference.issuer = "attacker_ledger"; },
    (candidate) => { candidate.reference.keyId = "attacker_key"; },
    (candidate) => {
      candidate.reference.objectDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    },
    (candidate) => { candidate.reference.invocationId = "invocation_replayed"; },
    (candidate) => {
      candidate.reference.serviceSkuVersionDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    },
    (candidate) => { candidate.resolvedProof.invocationId = "invocation_replayed"; },
    (candidate) => {
      candidate.resolvedProof.serviceSkuVersionDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    },
  ]) {
    const candidate = {
      reference: structuredClone(reference),
      resolvedProof: structuredClone(resolvedProof),
    };
    mutate(candidate);
    assert.equal(
      proofReferenceBindingResult(bundle, candidate.reference, candidate.resolvedProof),
      "PROOF_BINDING_MISMATCH",
    );
  }
});

test("authorization and ProofBundle evidence times are ordered inclusively", () => {
  assert.equal(hasBinding("BIND-MANDATE-PROOF-VALID-TIME"), true);
  assert.equal(hasBinding("BIND-PROOF-BUNDLE-CREATED-AT"), true);

  const mandateProof = structuredClone(
    reviewReceiptCases.find(({ value }) =>
      value.objectType === "MandateAuthorizationProof").value,
  );
  mandateProof.issuedAt = mandateProof.expiresAt;
  assert.equal(
    Date.parse(mandateProof.issuedAt) <= Date.parse(mandateProof.expiresAt),
    true,
    "issuedAt == expiresAt is the inclusive boundary",
  );
  mandateProof.issuedAt = "2026-08-10T00:05:01Z";
  assert.equal(
    Date.parse(mandateProof.issuedAt) <= Date.parse(mandateProof.expiresAt),
    false,
  );

  const bundle = structuredClone(reviewProofBundle.value);
  assert.equal(
    bundle.proofs.every(({ issuedAt }) =>
      Date.parse(bundle.createdAt) >= Date.parse(issuedAt)),
    true,
    "createdAt == latest proof issuedAt is the inclusive boundary",
  );
  bundle.createdAt = "2026-08-10T00:04:59Z";
  assert.equal(
    bundle.proofs.every(({ issuedAt }) =>
      Date.parse(bundle.createdAt) >= Date.parse(issuedAt)),
    false,
  );
  const resolvedProof = structuredClone(
    reviewReceiptCases.find(({ value }) =>
      value.objectType === "MandateAuthorizationProof").value,
  );
  resolvedProof.issuedAt = "2026-08-10T00:05:01Z";
  assert.equal(
    Date.parse(reviewProofBundle.value.createdAt) >= Date.parse(resolvedProof.issuedAt),
    false,
    "a reference timestamp cannot conceal a later resolved-proof issuance",
  );
});

test("adversarial MandateAuthorizationProof value swaps cannot cross PaymentIntent or ledger boundaries", () => {
  const binding = contract.crossObjectBindings.find(
    ({ id }) => id === "BIND-MANDATE-PROOF-PAYMENT-INTENT",
  );
  assert.ok(binding);
  assert.equal(hasBinding("BIND-MANDATE-PROOF-APPROVED"), true);
  const requiredPairs = [
    ["issuer.issuer", "fundingAuthority.issuer"],
    ["issuer.keyId", "fundingAuthority.keyId"],
    ["paymentIntentId", "paymentIntentId"],
    ["paymentIntentFingerprintDigest", "fingerprintDigest"],
    ["fundingLedgerNamespace", "fundingLedgerNamespace"],
    ["invocationId", "invocationId"],
    ["tenantId", "tenantId"],
    ["memberSuborgId", "memberSuborgId"],
    ["treasuryProfile", "treasuryProfile"],
    ["treasuryRef", "treasuryRef"],
    ["agentId", "agentId"],
    ["runtimeId", "runtimeId"],
    ["runtimeCapabilityDigest", "runtimeCapabilityDigest"],
    ["mandateId", "mandateId"],
    ["mandateVersion", "mandateVersion"],
    ["reservationId", "reservationId"],
    ["challengeDigest", "challengeDigest"],
    ["serviceSkuVersionDigest", "skuVersionDigest"],
    ["sellerIdentityRef", "sellerIdentityRef"],
    ["payeeAddress", "payoutAddress"],
    ["payerAddress", "payerAddress"],
    ["asset", "asset"],
    ["amountAtomic", "amountAtomic"],
    ["mode", "mode"],
    ["requestedAssurance", "requestedAssurance"],
    ["facilitatorId", "facilitatorId"],
    ["paymentAuthorizationDigest", "authorizationDigest"],
    ["expiresAt", "expiresAt"],
  ];
  assert.deepEqual(
    binding.fieldPairs.map(({ proof, paymentIntent }) => [proof, paymentIntent]),
    requiredPairs,
  );

  const paymentIntent = reviewPaymentCases.find(
    ({ definition }) => definition === "paymentIntent",
  ).value;
  const validProof = reviewReceiptCases.find(
    ({ value }) => value.objectType === "MandateAuthorizationProof",
  ).value;
  assert.equal(mandateProofBindingResult(paymentIntent, validProof), null);

  const mutations = [
    ["funding authority", (proof) => { proof.issuer.issuer = "attacker_ledger"; }],
    ["ledger namespace", (proof) => { proof.fundingLedgerNamespace = "zero_x_key:other_ledger"; }],
    ["intent fingerprint", (proof) => { proof.paymentIntentFingerprintDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; }],
    ["tenant", (proof) => { proof.tenantId = "tenant_attacker"; }],
    ["runtime capability", (proof) => { proof.runtimeCapabilityDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; }],
    ["mandate version", (proof) => { proof.mandateVersion += 1; }],
    ["reservation", (proof) => { proof.reservationId = "reservation_replayed"; }],
    ["challenge", (proof) => { proof.challengeDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; }],
    ["SKU", (proof) => { proof.serviceSkuVersionDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; }],
    ["authorization", (proof) => { proof.paymentAuthorizationDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; }],
    ["decision", (proof) => { proof.decisionCode = "DENIED"; }],
    ["amount", (proof) => { proof.amountAtomic = "999999"; }],
    ["payer", (proof) => { proof.payerAddress = "0x3333333333333333333333333333333333333333"; }],
    ["payee", (proof) => { proof.payeeAddress = "0x3333333333333333333333333333333333333333"; }],
    ["assurance", (proof) => { proof.requestedAssurance.identity = "ANONYMOUS_WALLET"; }],
    ["expiry", (proof) => { proof.expiresAt = "2030-08-10T00:05:00Z"; }],
  ];
  for (const [name, mutate] of mutations) {
    const malicious = structuredClone(validProof);
    mutate(malicious);
    assert.equal(
      mandateProofBindingResult(paymentIntent, malicious),
      "PROOF_BINDING_MISMATCH",
      name,
    );
  }
  const deniedProof = structuredClone(validProof);
  deniedProof.decisionCode = "DENIED";
  assert.equal(
    validatorFor("receiptEnvelope")(deniedProof),
    false,
    "only APPROVED is structurally eligible as Mandate authorization evidence",
  );
});

test("adversarial settlement and UNKNOWN receipts cannot cross funding authorities", () => {
  assert.equal(hasBinding("BIND-SETTLEMENT-RECEIPT-PAYMENT-INTENT"), true);
  assert.equal(hasBinding("BIND-UNKNOWN-OBSERVATION-PAYMENT-INTENT"), true);
  const paymentIntent = reviewPaymentCases.find(
    ({ definition }) => definition === "paymentIntent",
  ).value;
  const settlement = reviewReceiptCases.find(
    ({ value }) => value.objectType === "SettlementReceipt",
  ).value;
  const unknown = reviewReceiptCases.find(
    ({ value }) => value.objectType === "FundingUnknownObservation",
  ).value;
  assert.equal(fundingReceiptBindingResult(paymentIntent, settlement), null);
  assert.equal(fundingReceiptBindingResult(paymentIntent, unknown), null);

  for (const [receipt, mutations] of [
    [settlement, [
      (value) => { value.issuer.issuer = "attacker_facilitator"; },
      (value) => { value.paymentIntentFingerprintDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; },
      (value) => { value.paymentAuthorizationDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; },
      (value) => { value.payeeAddress = "0x3333333333333333333333333333333333333333"; },
    ]],
    [unknown, [
      (value) => { value.issuer.issuer = "attacker_ledger"; },
      (value) => { value.fundingLedgerNamespace = "zero_x_key:other_ledger"; },
      (value) => { value.reservationId = "reservation_replayed"; },
      (value) => { value.observedState = "AUTHORIZATION_UNKNOWN"; },
      (value) => { value.unknownBoundary = "authorization"; },
      (value) => { value.reconciliationDeadline = "2026-08-10T00:30:00Z"; },
    ]],
  ]) {
    for (const mutate of mutations) {
      const malicious = structuredClone(receipt);
      mutate(malicious);
      assert.equal(
        fundingReceiptBindingResult(paymentIntent, malicious),
        "PROOF_BINDING_MISMATCH",
      );
    }
  }
});

test("WALLET_SIGNED authorization and settlement UNKNOWN states carry reservation-free signed observations", () => {
  const baseWalletIntent = reviewPaymentCases.find(
    ({ definition, value }) => definition === "paymentIntent" &&
      value.requestedAssurance.authorization === "WALLET_SIGNED",
  ).value;
  const baseUnknown = reviewReceiptCases.find(
    ({ value }) => value.objectType === "FundingUnknownObservation",
  ).value;
  const validateIntent = validatorFor("paymentIntent");
  const validateReceipt = validatorFor("receiptEnvelope");

  const buildWalletUnknown = (state) => {
    const intent = structuredClone(baseWalletIntent);
    intent.state = state;
    intent.unknownObservationProofDigest =
      "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    intent.reconciliationDeadline = "2026-08-10T00:20:00Z";
    if (state === "AUTHORIZATION_UNKNOWN") delete intent.authorizationDigest;

    const observation = structuredClone(baseUnknown);
    observation.receiptId = `receipt_${state.toLowerCase()}_wallet_1`;
    observation.invocationId = intent.invocationId;
    observation.paymentIntentId = intent.paymentIntentId;
    observation.paymentIntentFingerprintDigest = intent.fingerprintDigest;
    observation.fundingLedgerNamespace = intent.fundingLedgerNamespace;
    observation.serviceSkuVersionDigest = intent.skuVersionDigest;
    observation.authorizationProfile = "WALLET_SIGNED";
    observation.observedState = state;
    observation.unknownBoundary = state === "AUTHORIZATION_UNKNOWN"
      ? "authorization"
      : "settlement";
    observation.reconciliationDeadline = intent.reconciliationDeadline;
    delete observation.reservationId;
    if (state === "AUTHORIZATION_UNKNOWN") delete observation.authorizationDigest;
    else observation.authorizationDigest = intent.authorizationDigest;
    observation.claimsDigest = observation.signature.signedObjectDigest =
      intent.unknownObservationProofDigest;
    return { intent, observation };
  };

  for (const state of ["AUTHORIZATION_UNKNOWN", "SETTLEMENT_UNKNOWN"]) {
    const { intent, observation } = buildWalletUnknown(state);
    assert.equal(validateIntent(intent), true, `${state}: ${ajv.errorsText(validateIntent.errors)}`);
    assert.equal(validateReceipt(observation), true, `${state}: ${ajv.errorsText(validateReceipt.errors)}`);
    assert.equal(fundingReceiptBindingResult(intent, observation), null, state);
  }

  const mandateWithoutReservation = structuredClone(baseUnknown);
  delete mandateWithoutReservation.reservationId;
  assert.equal(
    validateReceipt(mandateWithoutReservation),
    false,
    "MANDATE_PROTECTED observations require the atomic reservation lineage",
  );

  const { intent: walletIntent, observation: walletObservation } =
    buildWalletUnknown("SETTLEMENT_UNKNOWN");
  const walletWithReservation = structuredClone(walletObservation);
  walletWithReservation.reservationId = "reservation_smuggled";
  assert.equal(
    validateReceipt(walletWithReservation),
    false,
    "WALLET_SIGNED observations cannot imply a Treasury reservation",
  );

  const wrongProfile = structuredClone(walletObservation);
  wrongProfile.authorizationProfile = "MANDATE_PROTECTED";
  wrongProfile.reservationId = "reservation_attacker";
  assert.equal(validateReceipt(wrongProfile), true);
  assert.equal(
    fundingReceiptBindingResult(walletIntent, wrongProfile),
    "PROOF_BINDING_MISMATCH",
    "a structurally valid observation cannot cross authorization profiles",
  );
});

test("WALLET_SIGNED ProofBundle funding lineage cannot mix wallet authorization, UNKNOWN, or settlement intents", () => {
  const paymentIntent = structuredClone(reviewPaymentCases.find(
    ({ definition, value }) => definition === "paymentIntent" &&
      value.requestedAssurance.authorization === "WALLET_SIGNED",
  ).value);
  paymentIntent.state = "SETTLEMENT_UNKNOWN";
  paymentIntent.unknownObservationProofDigest =
    "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
  paymentIntent.reconciliationDeadline = "2026-08-10T00:20:00Z";

  const invocation = structuredClone(reviewPaymentCases.find(
    ({ definition }) => definition === "invocation",
  ).value);
  invocation.invocationId = paymentIntent.invocationId;
  invocation.paymentIntentRef = paymentIntent.paymentIntentId;

  const bundle = structuredClone(reviewProofBundle.value);
  bundle.invocationId = invocation.invocationId;
  const byType = new Map(reviewReceiptCases.map(({ value }) => [value.objectType, value]));
  const walletProof = structuredClone(byType.get("WalletAuthorizationProof"));
  const settlement = structuredClone(byType.get("SettlementReceipt"));
  Object.assign(settlement, {
    receiptId: "receipt_settlement_wallet_1",
    invocationId: paymentIntent.invocationId,
    paymentIntentId: paymentIntent.paymentIntentId,
    paymentIntentFingerprintDigest: paymentIntent.fingerprintDigest,
    fundingLedgerNamespace: paymentIntent.fundingLedgerNamespace,
    serviceSkuVersionDigest: paymentIntent.skuVersionDigest,
    paymentAuthorizationDigest: paymentIntent.authorizationDigest,
  });
  const unknown = structuredClone(byType.get("FundingUnknownObservation"));
  Object.assign(unknown, {
    receiptId: "receipt_unknown_wallet_1",
    invocationId: paymentIntent.invocationId,
    paymentIntentId: paymentIntent.paymentIntentId,
    paymentIntentFingerprintDigest: paymentIntent.fingerprintDigest,
    fundingLedgerNamespace: paymentIntent.fundingLedgerNamespace,
    serviceSkuVersionDigest: paymentIntent.skuVersionDigest,
    authorizationProfile: "WALLET_SIGNED",
    authorizationDigest: paymentIntent.authorizationDigest,
    observedState: "SETTLEMENT_UNKNOWN",
    unknownBoundary: "settlement",
    reconciliationDeadline: paymentIntent.reconciliationDeadline,
  });
  delete unknown.reservationId;

  assert.equal(
    proofBundleFundingLineageResult(
      bundle,
      invocation,
      paymentIntent,
      [walletProof, settlement, unknown],
    ),
    null,
  );

  for (const [name, mutate] of [
    ["wallet authorization", (proofs) => {
      proofs.wallet.paymentIntentFingerprintDigest =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    }],
    ["settlement", (proofs) => { proofs.settlement.paymentIntentId = "payment_intent_B"; }],
    ["UNKNOWN observation", (proofs) => {
      proofs.unknown.authorizationDigest =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    }],
  ]) {
    const proofs = {
      wallet: structuredClone(walletProof),
      settlement: structuredClone(settlement),
      unknown: structuredClone(unknown),
    };
    mutate(proofs);
    assert.equal(
      proofBundleFundingLineageResult(
        bundle,
        invocation,
        paymentIntent,
        [proofs.wallet, proofs.settlement, proofs.unknown],
      ),
      "PROOF_BINDING_MISMATCH",
      name,
    );
  }
});

test("PaymentIntent terms cannot be swapped with Mandate proof while retaining the signed x402 challenge", () => {
  assert.equal(hasBinding("BIND-PAYMENT-INTENT-X402-CHALLENGE"), true);
  const paymentIntent = reviewPaymentCases.find(
    ({ definition }) => definition === "paymentIntent",
  ).value;
  const extension = reviewPaymentCases.find(
    ({ definition }) => definition === "paymentRequiredOutcome",
  ).value.paymentRequired.extensions.openant;
  const mandateProof = reviewReceiptCases.find(
    ({ value }) => value.objectType === "MandateAuthorizationProof",
  ).value;
  assert.equal(paymentIntentChallengeBindingResult(paymentIntent, extension), null);
  assert.equal(mandateProofBindingResult(paymentIntent, mandateProof), null);

  for (const [name, mutateBoth] of [
    ["amount", (intent, proof) => { intent.amountAtomic = proof.amountAtomic = "999999"; }],
    ["mode", (intent, proof) => { intent.mode = proof.mode = "DIRECT"; }],
    ["assurance", (intent, proof) => {
      intent.requestedAssurance.identity = proof.requestedAssurance.identity = "ANONYMOUS_WALLET";
    }],
    ["expiry", (intent, proof) => {
      intent.expiresAt = proof.expiresAt = "2026-08-10T00:04:59Z";
    }],
  ]) {
    const intent = structuredClone(paymentIntent);
    const proof = structuredClone(mandateProof);
    mutateBoth(intent, proof);
    assert.equal(mandateProofBindingResult(intent, proof), null, `${name}: proof follows intent`);
    assert.equal(
      paymentIntentChallengeBindingResult(intent, extension),
      "PROOF_BINDING_MISMATCH",
      `${name}: signed challenge remains authoritative`,
    );
  }
});

test("WalletAuthorizationProof is bound to the PaymentIntent, payer actor, and signed challenge terms", () => {
  for (const id of [
    "BIND-WALLET-PROOF-PAYMENT-INTENT",
    "BIND-WALLET-PROOF-BUYER",
    "BIND-WALLET-PROOF-PAYER-SIGNATURE",
    "BIND-WALLET-PROOF-AUTHORIZATION-SIGNATURE",
    "BIND-WALLET-PROOF-CLAIMS-DIGEST",
    "BIND-WALLET-PROOF-X402-EIP3009",
    "BIND-WALLET-PAYMENT-INTENT-BUYER-DERIVATION",
  ]) assert.equal(hasBinding(id), true, id);
  const paymentIntent = reviewPaymentCases.find(
    ({ definition, value }) => definition === "paymentIntent" &&
      value.requestedAssurance.authorization === "WALLET_SIGNED",
  ).value;
  const proof = reviewReceiptCases.find(
    ({ value }) => value.objectType === "WalletAuthorizationProof",
  ).value;
  assert.equal(walletProofBindingResult(paymentIntent, proof), null);
  assert.notEqual(proof.claimsDigest, proof.signature.signedObjectDigest);
  assert.equal(proof.paymentAuthorizationDigest, proof.signature.signedObjectDigest);
  assert.equal(
    walletProofBindingResult(
      paymentIntent,
      proof,
      "0x3333333333333333333333333333333333333333",
    ),
    "PROOF_BINDING_MISMATCH",
  );
  for (const mutate of [
    (candidate) => { candidate.issuer.issuer = "buyer_attacker"; },
    (candidate) => { candidate.issuer.keyId = "key_attacker"; },
    (candidate) => { candidate.paymentIntentFingerprintDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; },
    (candidate) => { candidate.challengeDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; },
    (candidate) => { candidate.amountAtomic = "999999"; },
    (candidate) => { candidate.mode = "DIRECT"; },
    (candidate) => { candidate.requestedAssurance.identity = "VERIFIED_SELLER"; },
  ]) {
    const malicious = structuredClone(proof);
    mutate(malicious);
    assert.equal(walletProofBindingResult(paymentIntent, malicious), "PROOF_BINDING_MISMATCH");
  }
});

test("buyer delivery evidence is anchored to the resolved Invocation buyer actor", () => {
  for (const id of [
    "BIND-ACK-INVOCATION-BUYER",
    "BIND-ACCEPTANCE-INVOCATION-BUYER",
    "BIND-PAYMENT-INTENT-INVOCATION-BUYER",
  ]) assert.equal(hasBinding(id), true, id);
  const invocation = reviewPaymentCases.find(
    ({ definition }) => definition === "invocation",
  ).value;
  const intent = reviewPaymentCases.find(
    ({ definition }) => definition === "paymentIntent",
  ).value;
  const ack = reviewPaymentCases.find(
    ({ definition }) => definition === "deliveryAcknowledgement",
  ).value;
  const acceptance = reviewReceiptCases.find(
    ({ value }) => value.objectType === "AcceptanceReceipt",
  ).value;
  assert.equal(invocation.buyerActorRef, intent.buyerActorRef);
  assert.equal(invocation.buyerActorRef, ack.buyerActorRef);
  assert.equal(invocation.buyerActorRef, acceptance.buyerActorRef);
  const attackerAck = structuredClone(ack);
  attackerAck.buyerActorRef = attackerAck.attestation.issuer = "buyer_attacker";
  assert.notEqual(attackerAck.buyerActorRef, invocation.buyerActorRef);
});

test("Invocation and PaymentIntent proof digests resolve to exact receipt types and scope", () => {
  for (const id of [
    "BIND-INVOCATION-PAYMENT-PROOF",
    "BIND-INVOCATION-STAGING-PROOF",
    "BIND-INVOCATION-SETTLEMENT-PROOF",
    "BIND-INVOCATION-DELIVERY-PROOF",
    "BIND-INVOCATION-UNKNOWN-PROOF",
    "BIND-INVOCATION-ACK-PROOF",
    "BIND-PAYMENT-INTENT-SETTLEMENT-PROOF",
    "BIND-PAYMENT-INTENT-UNKNOWN-PROOF",
  ]) assert.equal(hasBinding(id), true, id);
  const intent = structuredClone(reviewPaymentCases.find(
    ({ definition }) => definition === "paymentIntent",
  ).value);
  const invocation = structuredClone(reviewPaymentCases.find(
    ({ definition }) => definition === "invocation",
  ).value);
  invocation.paymentIntentRef = intent.paymentIntentId;
  const receiptByType = new Map(reviewReceiptCases.map(({ value }) =>
    [value.objectType, value]));
  for (const [owner, digestField, type] of [
    [invocation, "paymentProofDigest", "MandateAuthorizationProof"],
    [invocation, "executionReceiptDigest", "ExecutionReceipt"],
    [invocation, "outputStagingReceiptDigest", "OutputStagingReceipt"],
    [invocation, "settlementReceiptDigest", "SettlementReceipt"],
    [invocation, "deliveryReceiptDigest", "DeliveryReceipt"],
    [invocation, "paymentUnknownObservationProofDigest", "FundingUnknownObservation"],
    [invocation, "acceptanceReceiptDigest", "AcceptanceReceipt"],
    [intent, "settlementReceiptDigest", "SettlementReceipt"],
    [intent, "unknownObservationProofDigest", "FundingUnknownObservation"],
  ]) {
    const resolved = receiptByType.get(type);
    owner[digestField] = resolved.claimsDigest;
    assert.equal(evidenceReferenceBindingResult(owner, digestField, resolved, type), null);
    const replayed = structuredClone(resolved);
    replayed.invocationId = "invocation_replayed";
    assert.equal(
      evidenceReferenceBindingResult(owner, digestField, replayed, type),
      "PROOF_BINDING_MISMATCH",
      `${digestField} invocation replay`,
    );
  }
  const acknowledgement = reviewPaymentCases.find(
    ({ definition }) => definition === "deliveryAcknowledgement",
  ).value;
  invocation.acknowledgementDigest = acknowledgement.attestation.signedObjectDigest;
  assert.equal(invocation.invocationId, acknowledgement.invocationId);

  const settlement = receiptByType.get("SettlementReceipt");
  for (const mutate of [
    (candidate) => { candidate.objectType = "CommerceReceipt"; },
    (candidate) => { candidate.invocationId = "invocation_replayed"; },
    (candidate) => { candidate.serviceSkuVersionDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; },
    (candidate) => { candidate.paymentIntentId = "payment_intent_replayed"; },
  ]) {
    const malicious = structuredClone(settlement);
    mutate(malicious);
    assert.equal(
      evidenceReferenceBindingResult(intent, "settlementReceiptDigest", malicious, "SettlementReceipt"),
      "PROOF_BINDING_MISMATCH",
    );
  }
});

test("receipt signers consume separate endpoint roles and Hosted custody trust", () => {
  for (const id of [
    "BIND-STAGING-RECEIPT-ENDPOINT-ISSUER",
    "BIND-EXECUTION-RECEIPT-ENDPOINT-ISSUER",
    "BIND-DELIVERY-RECEIPT-ENDPOINT-ISSUER",
    "BIND-ENDPOINT-ISSUER-ROLE-SEPARATION",
    "BIND-STAGING-RECEIPT-TRUSTED-CUSTODY-ISSUER",
    "BIND-DELIVERY-RECEIPT-TRUSTED-CUSTODY-ISSUER",
  ]) assert.equal(hasBinding(id), true, id);
  const sku = reviewDomainCases.find(({ definition }) => definition === "serviceSkuVersion").value;
  const endpoint = reviewDomainCases.find(
    ({ definition }) => definition === "endpointDescriptorVersion",
  ).value;
  for (const type of ["OutputStagingReceipt", "ExecutionReceipt", "DeliveryReceipt"]) {
    const receipt = reviewReceiptCases.find(({ value }) => value.objectType === type).value;
    assert.equal(endpointIssuerBindingResult(receipt, sku, endpoint), null, type);
    const malicious = structuredClone(receipt);
    malicious.issuer.issuer = malicious.signature.issuer = "attacker_executor";
    malicious.issuer.keyId = malicious.signature.keyId = "key_attacker_1";
    assert.equal(receiptBindingResult(malicious), null, "attacker receipt remains self-consistent");
    assert.equal(endpointIssuerBindingResult(malicious, sku, endpoint), "PROOF_BINDING_MISMATCH");
  }
  const execution = reviewReceiptCases.find(
    ({ value }) => value.objectType === "ExecutionReceipt",
  ).value;
  const staging = reviewReceiptCases.find(
    ({ value }) => value.objectType === "OutputStagingReceipt",
  ).value;
  const delivery = reviewReceiptCases.find(
    ({ value }) => value.objectType === "DeliveryReceipt",
  ).value;
  const deliveryAsExecution = structuredClone(execution);
  deliveryAsExecution.issuer = structuredClone(delivery.issuer);
  deliveryAsExecution.signature.issuer = delivery.signature.issuer;
  deliveryAsExecution.signature.keyId = delivery.signature.keyId;
  assert.equal(endpointIssuerBindingResult(deliveryAsExecution, sku, endpoint), "PROOF_BINDING_MISMATCH");
  for (const hostedReceipt of [staging, delivery]) {
    const executionAsHosted = structuredClone(hostedReceipt);
    executionAsHosted.issuer = structuredClone(execution.issuer);
    executionAsHosted.signature.issuer = execution.signature.issuer;
    executionAsHosted.signature.keyId = execution.signature.keyId;
    assert.equal(endpointIssuerBindingResult(executionAsHosted, sku, endpoint), "PROOF_BINDING_MISMATCH");
    const sellerAuthorizedEndpoint = structuredClone(endpoint);
    const role = hostedReceipt.objectType === "OutputStagingReceipt"
      ? "stagingIssuerKeys"
      : "deliveryIssuerKeys";
    sellerAuthorizedEndpoint[role].push(structuredClone(execution.issuer));
    assert.equal(
      endpointIssuerBindingResult(executionAsHosted, sku, sellerAuthorizedEndpoint),
      "PROOF_BINDING_MISMATCH",
      "seller-authored endpoint membership cannot replace verifier custody trust",
    );
  }
  const pairSet = (entries) => new Set(entries.map(({ issuer, keyId }) => `${issuer}#${keyId}`));
  const executionPairs = pairSet(endpoint.executionIssuerKeys);
  const commercePairs = pairSet(endpoint.commerceIssuerKeys);
  for (const hostedPair of [
    ...pairSet(endpoint.stagingIssuerKeys),
    ...pairSet(endpoint.deliveryIssuerKeys),
  ]) {
    assert.equal(executionPairs.has(hostedPair), false);
    assert.equal(commercePairs.has(hostedPair), false);
  }
});

test("SellerIdentityCredential subject is bound to the ListingMandate seller", () => {
  assert.ok(schema.$defs.sellerIdentityCredential);
  assert.equal(hasBinding("BIND-SELLER-CREDENTIAL-LISTING-SUBJECT"), true);
  assert.equal(hasBinding("BIND-SELLER-CREDENTIAL-SIGNATURE"), true);
  assert.equal(hasBinding("BIND-SELLER-CREDENTIAL-TRUSTED-ISSUER"), true);
  const listing = reviewDomainCases.find(({ definition }) => definition === "listingMandate").value;
  const credential = reviewDomainCases.find(
    ({ definition }) => definition === "sellerIdentityCredential",
  ).value;
  assert.equal(credential.sellerIdentityRef, listing.sellerIdentityRef);
  assert.equal(credential.issuer.issuer, credential.signature.issuer);
  assert.equal(credential.issuer.keyId, credential.signature.keyId);
  assert.equal(credential.claimsDigest, credential.signature.signedObjectDigest);
  const malicious = structuredClone(credential);
  malicious.sellerIdentityRef = "seller_attacker";
  assert.notEqual(malicious.sellerIdentityRef, listing.sellerIdentityRef);
});

test("external claim digest profiles resolve to strict local schemas", () => {
  for (const [profile, definition] of [
    ["TASK_AGREEMENT_VERSION", "taskAgreementVersion"],
    ["RUNTIME_CAPABILITY", "runtimeCapability"],
    ["SELLER_IDENTITY_CREDENTIAL", "sellerIdentityCredential"],
  ]) {
    assert.equal(contract.digestProfiles.profiles[profile].inputSchema, `#/$defs/${definition}`);
    assert.equal(schema.$defs[definition].additionalProperties, false, definition);
    validatorFor(definition);
  }
});

test("RuntimeCapability digest resolves to the exact PaymentIntent authority and scope", () => {
  assert.equal(hasBinding("BIND-RUNTIME-CAPABILITY-PAYMENT-INTENT"), true);
  const intent = reviewPaymentCases.find(
    ({ definition }) => definition === "paymentIntent",
  ).value;
  const capability = reviewDomainCases.find(
    ({ definition }) => definition === "runtimeCapability",
  ).value;
  assert.equal(runtimeCapabilityBindingResult(intent, capability), null);
  for (const mutate of [
    (value) => { value.signature.keyId = "key_attacker_1"; },
    (value) => { value.agentId = "agent_attacker_1"; },
    (value) => { value.mandateVersion += 1; },
    (value) => { value.serviceSkuVersionDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; },
    (value) => { value.expiresAt = "2026-08-10T00:04:59Z"; },
  ]) {
    const malicious = structuredClone(capability);
    mutate(malicious);
    assert.equal(runtimeCapabilityBindingResult(intent, malicious), "PROOF_BINDING_MISMATCH");
  }
});

test("error retryability and boundary are fixed by the contract registry", () => {
  const codes = contract.errors.map(({ code }) => code);
  assert.equal(new Set(codes).size, codes.length, "error codes must be unique");
  assert.deepEqual(
    [...schema.$defs.errorCode.enum].sort(),
    [...codes].sort(),
    "schema and contract error registries must not drift",
  );
  for (const error of contract.errors) {
    assert.equal(typeof error.retryable, "boolean", error.code);
    assert.match(error.boundary, /^[a-z][a-z0-9_]+$/, error.code);
  }

  const validate = validatorFor("protocolError");
  for (const error of contract.errors) {
    const value = {
      objectType: "ProtocolError",
      protocolVersion: "0.1",
      code: error.code,
      message: "Safe public message",
      retryable: error.retryable,
      boundary: error.boundary,
      reason: "CONTRACT_TEST",
      requestId: "request_contract_1",
      traceId: "0123456789abcdef0123456789abcdef",
      context: {},
    };
    assert.equal(validate(value), true, `${error.code}: ${ajv.errorsText(validate.errors)}`);
    assert.equal(validate({ ...value, retryable: !error.retryable }), false, error.code);
  }
});

test("cross-object binding registry has unique IDs and resolvable field-pair paths", () => {
  const bindingIds = contract.crossObjectBindings.map(({ id }) => id);
  assert.equal(new Set(bindingIds).size, bindingIds.length);
  const paymentIntent = reviewPaymentCases.find(
    ({ definition }) => definition === "paymentIntent",
  ).value;
  const proofByType = new Map(reviewReceiptCases.map(({ value }) =>
    [value.objectType, value]));
  const getPath = (value, fieldPath) => fieldPath.split(".").reduce(
    (current, segment) => current?.[segment],
    value,
  );
  for (const binding of contract.crossObjectBindings.filter(
    ({ fieldPairs }) => fieldPairs,
  )) {
    const proof = proofByType.get(binding.leftObject);
    assert.ok(proof, binding.leftObject);
    for (const fieldPair of binding.fieldPairs) {
      assert.notEqual(
        getPath(proof, fieldPair.proof),
        undefined,
        `${binding.id}.${fieldPair.proof}`,
      );
      assert.notEqual(
        getPath(paymentIntent, fieldPair.paymentIntent),
        undefined,
        `${binding.id}.${fieldPair.paymentIntent}`,
      );
    }
  }
});

test("state registries have unique edges and declared terminal states", () => {
  for (const [name, machine] of Object.entries(contract.stateMachines)) {
    const edges = machine.transitions.map(([from, to]) => `${from}->${to}`);
    assert.equal(new Set(edges).size, edges.length, `${name} contains duplicate edges`);
    for (const terminal of machine.terminal) {
      assert.equal(
        machine.transitions.some(([from]) => from === terminal),
        false,
        `${name}.${terminal} must not have outgoing transitions`,
      );
    }
  }

  const paymentEdges = new Set(
    contract.stateMachines.paymentIntent.transitions.map(([from, to]) => `${from}->${to}`),
  );
  for (const requiredEdge of [
    "AUTHORIZING->DENIED",
    "AUTHORIZED->AUTHORIZATION_EXPIRED",
    "CONFIRMED->SETTLEMENT_UNKNOWN",
    "SETTLEMENT_UNKNOWN->SUBMITTED",
  ]) {
    assert.equal(paymentEdges.has(requiredEdge), true, requiredEdge);
  }
  const invocationEdges = new Set(
    contract.stateMachines.invocation.transitions.map(([from, to]) => `${from}->${to}`),
  );
  assert.equal(
    invocationEdges.has("DELIVERABLE->RECOVERY_WINDOW_EXPIRED") &&
      invocationEdges.has("DELIVERED->RECOVERY_WINDOW_EXPIRED"),
    true,
    "recovery window must converge to an explicit terminal state",
  );

  for (const [machineName, definition] of [
    ["invocation", "invocation"],
    ["paymentIntent", "paymentIntent"],
  ]) {
    const machine = contract.stateMachines[machineName];
    const contractStates = new Set([
      machine.initial,
      ...machine.terminal,
      ...machine.transitions.flatMap(([from, to]) => [from, to]),
    ]);
    const schemaStates = new Set(schema.$defs[definition].properties.state.enum);
    assert.deepEqual(
      [...schemaStates].sort(),
      [...contractStates].sort(),
      `${machineName} schema and transition registry must not drift`,
    );
  }
});

test("state snapshots reject evidence that cannot exist at that lifecycle boundary", () => {
  const invocationFixture = reviewPaymentCases.find(
    ({ definition }) => definition === "invocation",
  ).value;
  const impossibleInvocation = structuredClone(invocationFixture);
  Object.assign(impossibleInvocation, {
    state: "CREATED",
    settlementReceiptDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    deliveryReceiptDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    acknowledgementDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
  });
  assert.equal(validatorFor("invocation")(impossibleInvocation), false);

  const paymentFixture = reviewPaymentCases.find(
    ({ definition }) => definition === "paymentIntent",
  ).value;
  const impossibleCreatedIntent = structuredClone(paymentFixture);
  impossibleCreatedIntent.state = "CREATED";
  delete impossibleCreatedIntent.unknownObservationProofDigest;
  delete impossibleCreatedIntent.reconciliationDeadline;
  impossibleCreatedIntent.settlementReceiptDigest =
    "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  assert.equal(validatorFor("paymentIntent")(impossibleCreatedIntent), false);

  const rejectedWithoutLineage = structuredClone(paymentFixture);
  rejectedWithoutLineage.state = "SETTLEMENT_REJECTED";
  for (const field of [
    "reservationId",
    "authorizationDigest",
    "unknownObservationProofDigest",
    "reconciliationDeadline",
  ]) delete rejectedWithoutLineage[field];
  assert.equal(validatorFor("paymentIntent")(rejectedWithoutLineage), false);

  const rejectedWithLineage = structuredClone(rejectedWithoutLineage);
  rejectedWithLineage.reservationId = "reservation_1";
  rejectedWithLineage.authorizationDigest =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  assert.equal(validatorFor("paymentIntent")(rejectedWithLineage), true);
});

test("FAILED_BEFORE_SETTLEMENT cannot carry an orphan payment proof", () => {
  const failed = structuredClone(
    reviewPaymentCases.find(({ definition }) => definition === "invocation").value,
  );
  failed.state = "FAILED_BEFORE_SETTLEMENT";
  failed.paymentProofDigest =
    "sha256:1010101010101010101010101010101010101010101010101010101010101010";
  assert.equal(validatorFor("invocation")(failed), false);
  failed.paymentIntentRef = "payment_intent_1";
  assert.equal(validatorFor("invocation")(failed), true);
});

test("funding metadata allowlist excludes raw business content", () => {
  const paymentIntentProperties = new Set(
    Object.keys(schema.$defs.paymentIntent.properties),
  );
  for (const forbidden of contract.privacy.forbiddenFundingAndTelemetryProperties) {
    assert.equal(paymentIntentProperties.has(forbidden), false, forbidden);
  }
  const commonFingerprintFields = contract.idempotency.paymentIntentFingerprintCommonFields;
  const conditionalFingerprintFields = contract.idempotency.paymentIntentFingerprintConditionalFields;
  assert.deepEqual(Object.keys(conditionalFingerprintFields).sort(), ["MANDATE_PROTECTED", "WALLET_SIGNED"]);
  for (const [profile, fields] of Object.entries({
    COMMON: commonFingerprintFields,
    ...conditionalFingerprintFields,
  })) assert.equal(new Set(fields).size, fields.length, `${profile} fingerprint fields must be unique`);
  for (const binding of [
    "fundingLedgerNamespace",
    "fundingAuthority.issuer",
    "fundingAuthority.keyId",
    "settlementAuthority.issuer",
    "settlementAuthority.keyId",
    "observationAuthority.issuer",
    "observationAuthority.keyId",
    "payerAddress",
    "mode",
    "requestedAssurance.authorization",
    "requestedAssurance.settlement",
    "requestedAssurance.delivery",
    "requestedAssurance.contentCustody",
    "requestedAssurance.identity",
  ]) {
    assert.equal(
      commonFingerprintFields.includes(binding),
      true,
      binding,
    );
  }
  for (const binding of ["mandateId", "mandateVersion", "runtimeCapabilityDigest", "tenantId", "memberSuborgId", "treasuryRef", "agentId", "runtimeId"]) {
    assert.equal(conditionalFingerprintFields.MANDATE_PROTECTED.includes(binding), true, binding);
    assert.equal(commonFingerprintFields.includes(binding), false, `${binding} must not be common`);
  }
  assert.deepEqual(conditionalFingerprintFields.WALLET_SIGNED, []);
  const paymentIntent = reviewPaymentCases.find(
    ({ definition }) => definition === "paymentIntent",
  ).value;
  for (const projectionPath of [
    ...commonFingerprintFields,
    ...conditionalFingerprintFields.MANDATE_PROTECTED,
  ]) {
    const value = projectionPath.split(".").reduce(
      (current, segment) => current?.[segment],
      paymentIntent,
    );
    assert.notEqual(value, undefined, `missing fingerprint path ${projectionPath}`);
  }
});

test("PaymentIntent authorization profiles separate delegated mandate and anonymous wallet state", () => {
  const mandate = structuredClone(reviewPaymentCases.find(
    ({ definition }) => definition === "paymentIntent",
  ).value);
  assert.equal(validatorFor("paymentIntent")(mandate), true);

  const wallet = structuredClone(mandate);
  wallet.requestedAssurance.authorization = "WALLET_SIGNED";
  wallet.requestedAssurance.identity = "ANONYMOUS_WALLET";
  wallet.buyerActorRef = "wallet_eip155_8453_2222222222222222222222222222222222222222";
  wallet.state = "AUTHORIZING";
  for (const field of [
    "tenantId",
    "memberSuborgId",
    "treasuryProfile",
    "treasuryRef",
    "agentId",
    "runtimeId",
    "runtimeCapabilityDigest",
    "mandateId",
    "mandateVersion",
    "reservationId",
    "authorizationDigest",
    "unknownObservationProofDigest",
    "reconciliationDeadline",
  ]) delete wallet[field];
  assert.equal(validatorFor("paymentIntent")(wallet), true, JSON.stringify(validatorFor("paymentIntent").errors));
  assert.equal(hasBinding("BIND-WALLET-PAYMENT-INTENT-BUYER-DERIVATION"), true);
  assert.equal(
    wallet.buyerActorRef,
    `wallet_eip155_8453_${wallet.payerAddress.slice(2).toLowerCase()}`,
  );

  const walletWithTenant = structuredClone(wallet);
  walletWithTenant.tenantId = "tenant_must_not_be_smuggled";
  assert.equal(validatorFor("paymentIntent")(walletWithTenant), false);
  const walletReserved = structuredClone(wallet);
  walletReserved.state = "RESERVED";
  assert.equal(validatorFor("paymentIntent")(walletReserved), false);
  const walletImpersonation = structuredClone(wallet);
  walletImpersonation.buyerActorRef = "wallet_eip155_8453_ffffffffffffffffffffffffffffffffffffffff";
  assert.equal(validatorFor("paymentIntent")(walletImpersonation), true);
  assert.notEqual(
    walletImpersonation.buyerActorRef,
    `wallet_eip155_8453_${walletImpersonation.payerAddress.slice(2).toLowerCase()}`,
  );
  const walletAuthorized = structuredClone(wallet);
  walletAuthorized.state = "AUTHORIZED";
  walletAuthorized.authorizationDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  assert.equal(validatorFor("paymentIntent")(walletAuthorized), true);

  const mandateWithoutCapability = structuredClone(mandate);
  delete mandateWithoutCapability.runtimeCapabilityDigest;
  assert.equal(validatorFor("paymentIntent")(mandateWithoutCapability), false);
  const noAuthorization = structuredClone(wallet);
  noAuthorization.requestedAssurance.authorization = "NONE";
  assert.equal(validatorFor("paymentIntent")(noAuthorization), false);

  const machine = contract.stateMachines.paymentIntent;
  const globalPairs = new Set(machine.transitions.map(([from, to]) => `${from}->${to}`));
  const profilePairs = Object.fromEntries(Object.entries(machine.authorizationProfileTransitions)
    .map(([profile, transitions]) => [profile, new Set(transitions.map(([from, to]) => `${from}->${to}`))]));
  const profileUnion = new Set();
  for (const [profile, transitions] of Object.entries(profilePairs)) {
    assert.equal(
      transitions.size,
      machine.authorizationProfileTransitions[profile].length,
      `${profile} contains duplicate edges`,
    );
    for (const pair of transitions) {
      assert.ok(globalPairs.has(pair), pair);
      profileUnion.add(pair);
    }
  }
  assert.deepEqual([...profileUnion].sort(), [...globalPairs].sort());
  assert.ok(profilePairs.MANDATE_PROTECTED.has("CREATED->RESERVED"));
  assert.equal(profilePairs.MANDATE_PROTECTED.has("CREATED->AUTHORIZING"), false);
  assert.ok(profilePairs.WALLET_SIGNED.has("CREATED->AUTHORIZING"));
  assert.equal(profilePairs.WALLET_SIGNED.has("CREATED->RESERVED"), false);
  for (const edge of [
    "AUTHORIZING->AUTHORIZED",
    "AUTHORIZING->AUTHORIZATION_UNKNOWN",
    "SUBMITTED->SETTLEMENT_UNKNOWN",
    "CONFIRMED->FINALIZED",
  ]) {
    assert.equal(profilePairs.MANDATE_PROTECTED.has(edge), true, edge);
    assert.equal(profilePairs.WALLET_SIGNED.has(edge), true, edge);
  }
  const selector = contract.operationKindApplicability.INVOCATION.stateMachines
    .find(({ name }) => name === "paymentIntent").profileSelector;
  assert.equal(selector, "requestedAssurance.authorization");
  const profileAllows = (profile, edge) =>
    profilePairs[profile]?.has(edge) === true;
  assert.equal(profileAllows(undefined, "CREATED->AUTHORIZING"), false);
  assert.equal(profileAllows("UNKNOWN", "CREATED->AUTHORIZING"), false);
  assert.equal(profileAllows("MANDATE_PROTECTED", "CREATED->AUTHORIZING"), false);
  assert.equal(profileAllows("WALLET_SIGNED", "CREATED->AUTHORIZING"), true);
  assert.equal(semanticResult({
    kind: "illegalTransition",
    machine: "paymentIntent",
    authorizationProfile: "MANDATE_PROTECTED",
    from: "CREATED",
    to: "AUTHORIZING",
  }), "ILLEGAL_STATE_TRANSITION");
  assert.equal(semanticResult({
    kind: "illegalTransition",
    machine: "paymentIntent",
    authorizationProfile: "WALLET_SIGNED",
    from: "CREATED",
    to: "AUTHORIZING",
  }), null);
  for (const authorizationProfile of ["MANDATE_PROTECTED", "WALLET_SIGNED"]) {
    assert.equal(semanticResult({
      kind: "illegalTransition",
      machine: "paymentIntent",
      authorizationProfile,
      from: "AUTHORIZING",
      to: "AUTHORIZED",
    }), null, `${authorizationProfile} common continuation`);
  }
  assert.equal(semanticResult({
    kind: "illegalTransition",
    machine: "paymentIntent",
    from: "CREATED",
    to: "AUTHORIZING",
  }), "ILLEGAL_STATE_TRANSITION", "missing profile selector fails closed");
});

test("every digest property has an exact preimage profile", () => {
  const digestProperties = new Set();
  const visit = (value) => {
    if (!value || typeof value !== "object") return;
    if (value.properties) {
      for (const propertyName of Object.keys(value.properties)) {
        if (propertyName.endsWith("Digest")) digestProperties.add(propertyName);
      }
    }
    for (const child of Object.values(value)) visit(child);
  };
  visit(schema.$defs);

  const covered = new Set(Object.keys(contract.digestProfiles.referenceFields));
  for (const profile of Object.values(contract.digestProfiles.profiles)) {
    for (const output of profile.outputFields ?? []) covered.add(output.split(".").at(-1));
  }
  assert.deepEqual(
    [...digestProperties].filter((property) => !covered.has(property)).sort(),
    [],
    "digest fields without exact preimage/exclusion/framing",
  );
  for (const [profileName, profile] of Object.entries(contract.digestProfiles.profiles)) {
    assert.equal(typeof profile.input, "string", `${profileName}.input`);
    assert.equal(Array.isArray(profile.outputFields), true, `${profileName}.outputFields`);
    assert.equal(profile.outputFields.length > 0, true, `${profileName}.outputFields`);
    assert.equal(
      Array.isArray(profile.exclude) || typeof profile.includeOnly === "string" || profile.framing === "byteFraming",
      true,
      `${profileName} must specify exclusions, include-only projection, or exact byte framing`,
    );
  }
});

test("every digest schema path has one profile binding and acknowledged content has an explicit kind", () => {
  const schemaPaths = new Set();
  const visitDefinition = (definitionName, value) => {
    if (!value || typeof value !== "object") return;
    if (value.properties) {
      for (const [propertyName, property] of Object.entries(value.properties)) {
        if (propertyName.endsWith("Digest")) {
          schemaPaths.add(`${definitionName}.${propertyName}`);
        }
        visitDefinition(definitionName, property);
      }
    }
    for (const [key, child] of Object.entries(value)) {
      if (key !== "properties") visitDefinition(definitionName, child);
    }
  };
  for (const [definitionName, definition] of Object.entries(schema.$defs)) {
    visitDefinition(definitionName, definition);
  }

  const pathBindings = contract.digestProfiles.pathBindings;
  assert.equal(Array.isArray(pathBindings), true, "pathBindings registry is required");
  const declaredPaths = pathBindings.flatMap(({ paths }) => paths);
  assert.equal(
    new Set(declaredPaths).size,
    declaredPaths.length,
    "one schema path cannot select two digest bindings",
  );
  assert.deepEqual([...declaredPaths].sort(), [...schemaPaths].sort());
  for (const binding of pathBindings) {
    if (binding.profile) assert.ok(contract.digestProfiles.profiles[binding.profile]);
    if (binding.selector) {
      assert.ok(binding.cases);
      for (const profileName of Object.values(binding.cases)) {
        assert.ok(contract.digestProfiles.profiles[profileName], profileName);
      }
    }
  }

  const acknowledgedContent = pathBindings.find(({ paths }) =>
    paths.includes("deliveryAcknowledgement.receivedContentDigest"));
  assert.deepEqual(acknowledgedContent, {
    paths: ["deliveryAcknowledgement.receivedContentDigest"],
    selector: "DeliveryAcknowledgement.contentKind",
    cases: { RESPONSE: "RESPONSE_BYTES", ARTIFACT: "ARTIFACT_BYTES" },
  });

  const acknowledgement = structuredClone(
    reviewPaymentCases.find(({ definition }) =>
      definition === "deliveryAcknowledgement").value,
  );
  delete acknowledgement.contentKind;
  assert.equal(validatorFor("deliveryAcknowledgement")(acknowledgement), false);
  acknowledgement.contentKind = "RESPONSE";
  assert.equal(validatorFor("deliveryAcknowledgement")(acknowledgement), true);
  acknowledgement.contentKind = "UNKNOWN";
  assert.equal(validatorFor("deliveryAcknowledgement")(acknowledgement), false);
});

test("signed receipt digest selector enumerates every concrete ReceiptEnvelope variant", () => {
  const signatureBinding = contract.digestProfiles.pathBindings.find(({ paths }) =>
    paths.includes("signatureEnvelope.signedObjectDigest"));
  assert.ok(signatureBinding);
  assert.equal(signatureBinding.cases.ReceiptEnvelope, undefined);

  const receiptObjectTypes = schema.$defs.receiptEnvelope.oneOf.map(({ $ref }) => {
    const definitionName = $ref.split("/").at(-1);
    const definition = schema.$defs[definitionName];
    const objectType = definition.allOf
      .flatMap((entry) => Object.values(entry.properties ?? {}))
      .find((property) => property.const)?.const;
    assert.ok(objectType, definitionName);
    return objectType;
  });
  const selectedReceiptTypes = Object.entries(signatureBinding.cases)
    .filter(([, profile]) => profile === "RECEIPT_CLAIMS")
    .map(([objectType]) => objectType);
  assert.deepEqual(
    [...selectedReceiptTypes].sort(),
    receiptObjectTypes.filter((type) => type !== "WalletAuthorizationProof").sort(),
  );
  assert.equal(new Set(selectedReceiptTypes).size, 8);
  assert.equal(signatureBinding.cases.WalletAuthorizationProof, "PAYMENT_AUTHORIZATION");
});

test("content evidence selects exactly one response or artifact digest domain", () => {
  const deliveryReceipt = structuredClone(
    reviewReceiptCases.find(({ value }) =>
      value.objectType === "DeliveryReceipt").value,
  );
  deliveryReceipt.artifactManifestDigest =
    "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  assert.equal(validatorFor("receiptEnvelope")(deliveryReceipt), false);
});

test("operation-kind applicability is complete and leaves no adapter-owned defaults", () => {
  const variants = schema.$defs.commerceOperation.oneOf;
  const applicability = contract.operationKindApplicability;
  const kinds = variants.map((variant) => variant.properties.kind.const);
  assert.deepEqual(Object.keys(applicability).sort(), [...kinds].sort());

  const knownObjects = new Set(Object.keys(contract.objects));
  const knownErrors = new Set(contract.errors.map(({ code }) => code));
  const knownLimits = new Set(Object.keys(contract.limits));
  const knownMachines = new Map(
    Object.entries(contract.stateMachines).map(([name, machine]) => [name, machine.authority]),
  );

  for (const variant of variants) {
    const kind = variant.properties.kind.const;
    const profile = applicability[kind];
    assert.deepEqual(profile.envelopeRequiredFields, variant.required, `${kind} envelope fields`);
    for (const objectType of [
      ...profile.resolvedObjectTypes,
      ...profile.permissionEvidence,
      ...profile.conditionalEvidence.flatMap(({ objectTypes = [] }) => objectTypes),
    ]) {
      assert.ok(knownObjects.has(objectType), `${kind} unknown object ${objectType}`);
    }
    for (const { registryRef } of profile.conditionalEvidence) {
      if (registryRef === undefined) continue;
      if (registryRef === "assuranceRequirements") assert.ok(contract.assuranceRequirements);
      else assert.equal(registryRef, "A2A_ADAPTER_REQUIRED");
    }
    for (const { name, authority } of profile.stateMachines) {
      assert.equal(knownMachines.get(name), authority, `${kind}.${name} authority`);
    }
    for (const code of profile.errorCodes) assert.ok(knownErrors.has(code), `${kind}.${code}`);
    for (const key of profile.limitKeys) assert.ok(knownLimits.has(key), `${kind}.${key}`);
    for (const list of [
      profile.envelopeRequiredFields,
      profile.resolvedObjectTypes,
      profile.permissionEvidence,
      profile.errorCodes,
      profile.limitKeys,
    ]) assert.equal(new Set(list).size, list.length, `${kind} list entries must be unique`);
    for (const permission of profile.permissionEvidence) {
      assert.ok(profile.resolvedObjectTypes.includes(permission), `${kind}.${permission} must resolve`);
    }
    assert.equal(typeof profile.chargeableSuccess.applicable, "boolean");
    assert.equal(typeof profile.pricing.applicable, "boolean");
    for (const rule of [profile.chargeableSuccess, profile.pricing]) {
      if (!rule.applicable) continue;
      const reference = contract.objects[rule.sourceObject];
      assert.ok(reference, `${kind}.${rule.sourceObject}`);
      const definition = schema.$defs[reference.split("/").at(-1)];
      assert.ok(definition.properties[rule.sourceField], `${kind}.${rule.sourceField}`);
      if (rule.requiredValue !== undefined) {
        assert.equal(definition.properties[rule.sourceField].const, rule.requiredValue);
      }
    }
  }

  const invocation = applicability.INVOCATION;
  assert.equal(invocation.permissionEvidence.includes("RuntimeCapability"), false);
  assert.ok(invocation.conditionalEvidence.some(({ when, objectTypes }) =>
    when === "requestedAssurance.authorization=MANDATE_PROTECTED" &&
      objectTypes.includes("RuntimeCapability")));
  assert.deepEqual(invocation.stateMachines.map(({ name }) => name), ["invocation", "paymentIntent"]);
  assert.equal(invocation.pricing.requiredValue, "FIXED_PER_SUCCESSFUL_UNARY_CALL");
  assert.equal(invocation.standardX402WithoutSignedOpenAntExtension,
    "OUTSIDE_OPENANT_COMMERCE_OPERATION_CATALOG");

  const task = applicability.TASK;
  assert.deepEqual(task.stateMachines, []);
  assert.equal(task.externalStateMachineRef, "EXTERNAL_A2A_ESCROW_ADAPTER");
  assert.equal(task.a2mcpPricing, "NOT_APPLICABLE");
  assert.equal(task.commercialTermsSource, "TaskAgreementVersion.agreementTerms");
  assert.equal(task.fundingModel, "EXTERNAL_ESCROW_REF");
  assert.equal(task.externalErrorRegistryRef, "EXTERNAL_A2A_ESCROW_ADAPTER");
  assert.equal(task.externalLimitsSource, "TaskAgreementVersion.agreementTerms");
});
