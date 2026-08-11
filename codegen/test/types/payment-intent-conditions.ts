import type {
  AssuranceVector,
  Identifier,
  PaymentIntent,
  Sha256Digest,
} from "../../generated/commerce-types.js";

type ConditionalFields =
  | "requestedAssurance"
  | "state"
  | "tenantId"
  | "memberSuborgId"
  | "treasuryProfile"
  | "treasuryRef"
  | "agentId"
  | "runtimeId"
  | "runtimeCapabilityDigest"
  | "mandateId"
  | "mandateVersion"
  | "reservationId"
  | "authorizationDigest"
  | "settlementReceiptDigest"
  | "unknownObservationProofDigest"
  | "reconciliationDeadline";

declare const common: Omit<PaymentIntent, ConditionalFields>;
declare const assurance: Omit<AssuranceVector, "authorization">;
declare const id: Identifier;
declare const digest: Sha256Digest;

const mandateContext = {
  tenantId: id,
  memberSuborgId: id,
  treasuryProfile: "OWNER_DELEGATED" as const,
  treasuryRef: id,
  agentId: id,
  runtimeId: id,
  runtimeCapabilityDigest: digest,
  mandateId: id,
  mandateVersion: 1,
};

const validMandateAuthorizing: PaymentIntent = {
  ...common,
  requestedAssurance: { ...assurance, authorization: "MANDATE_PROTECTED" },
  state: "AUTHORIZING",
  ...mandateContext,
  reservationId: id,
};

const validMandateCreated: PaymentIntent = {
  ...common,
  requestedAssurance: { ...assurance, authorization: "MANDATE_PROTECTED" },
  state: "CREATED",
  ...mandateContext,
};

// @ts-expect-error MANDATE_PROTECTED AUTHORIZING requires reservationId
const invalidMandateMissingReservation: PaymentIntent = {
  ...common,
  requestedAssurance: { ...assurance, authorization: "MANDATE_PROTECTED" },
  state: "AUTHORIZING",
  ...mandateContext,
};

// @ts-expect-error MANDATE_PROTECTED requires runtimeCapabilityDigest
const invalidMandateMissingCapability: PaymentIntent = {
  ...common,
  requestedAssurance: { ...assurance, authorization: "MANDATE_PROTECTED" },
  state: "AUTHORIZING",
  tenantId: id,
  memberSuborgId: id,
  treasuryProfile: "OWNER_DELEGATED",
  treasuryRef: id,
  agentId: id,
  runtimeId: id,
  mandateId: id,
  mandateVersion: 1,
  reservationId: id,
};

// @ts-expect-error WALLET_SIGNED forbids native tenant/mandate/reservation fields
const invalidWalletNativeContext: PaymentIntent = {
  ...common,
  requestedAssurance: { ...assurance, authorization: "WALLET_SIGNED" },
  state: "AUTHORIZING",
  tenantId: id,
  mandateId: id,
  reservationId: id,
};

const validWalletCreated: PaymentIntent = {
  ...common,
  requestedAssurance: { ...assurance, authorization: "WALLET_SIGNED" },
  state: "CREATED",
};

const validWalletAuthorizing: PaymentIntent = {
  ...common,
  requestedAssurance: { ...assurance, authorization: "WALLET_SIGNED" },
  state: "AUTHORIZING",
};

const validWalletAuthorized: PaymentIntent = {
  ...common,
  requestedAssurance: { ...assurance, authorization: "WALLET_SIGNED" },
  state: "AUTHORIZED",
  authorizationDigest: digest,
};

// @ts-expect-error AUTHORIZED requires authorizationDigest
const invalidWalletAuthorizedWithoutDigest: PaymentIntent = {
  ...common,
  requestedAssurance: { ...assurance, authorization: "WALLET_SIGNED" },
  state: "AUTHORIZED",
};

const validWalletAuthorizationUnknown: PaymentIntent = {
  ...common,
  requestedAssurance: { ...assurance, authorization: "WALLET_SIGNED" },
  state: "AUTHORIZATION_UNKNOWN",
  reconciliationDeadline: common.expiresAt,
  unknownObservationProofDigest: digest,
};

// @ts-expect-error AUTHORIZATION_UNKNOWN requires observation proof and deadline
const invalidWalletAuthorizationUnknown: PaymentIntent = {
  ...common,
  requestedAssurance: { ...assurance, authorization: "WALLET_SIGNED" },
  state: "AUTHORIZATION_UNKNOWN",
};

const validWalletFinalized: PaymentIntent = {
  ...common,
  requestedAssurance: { ...assurance, authorization: "WALLET_SIGNED" },
  state: "FINALIZED",
  authorizationDigest: digest,
  settlementReceiptDigest: digest,
};

// @ts-expect-error FINALIZED requires settlementReceiptDigest
const invalidWalletFinalizedWithoutSettlement: PaymentIntent = {
  ...common,
  requestedAssurance: { ...assurance, authorization: "WALLET_SIGNED" },
  state: "FINALIZED",
  authorizationDigest: digest,
};

void validMandateAuthorizing;
void validMandateCreated;
void invalidMandateMissingReservation;
void invalidMandateMissingCapability;
void invalidWalletNativeContext;
void validWalletCreated;
void validWalletAuthorizing;
void validWalletAuthorized;
void invalidWalletAuthorizedWithoutDigest;
void validWalletAuthorizationUnknown;
void invalidWalletAuthorizationUnknown;
void validWalletFinalized;
void invalidWalletFinalizedWithoutSettlement;
