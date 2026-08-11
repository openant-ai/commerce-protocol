import { fail } from "./errors.mjs";

function object(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("SOURCE_CONTRACT_INVALID", `${label} must be an object`);
  }
  return value;
}

function array(value, label) {
  if (!Array.isArray(value)) fail("SOURCE_CONTRACT_INVALID", `${label} must be an array`);
  return value;
}

function referencedDefinition(reference) {
  const match = reference?.match(/^#\/\$defs\/([A-Za-z0-9_-]+)$/);
  return match?.[1];
}

export function validateProtocolSource({ contract, schema }) {
  object(contract.protocol, "protocol");
  object(contract.objects, "objects");
  object(contract.limits, "limits");
  object(contract.assuranceRequirements, "assuranceRequirements");
  object(contract.assuranceRequirements.authorization, "assuranceRequirements.authorization");
  const definitions = object(schema.$defs, "$defs");
  const errors = array(contract.errors, "errors");
  const errorCodes = new Set();
  for (const [index, error] of errors.entries()) {
    object(error, `errors[${index}]`);
    if (typeof error.code !== "string" || typeof error.retryable !== "boolean" ||
      typeof error.boundary !== "string") {
      fail("SOURCE_CONTRACT_INVALID", `errors[${index}] must contain code/retryable/boundary`);
    }
    if (errorCodes.has(error.code)) fail("SOURCE_CONTRACT_INVALID", `duplicate error code ${error.code}`);
    errorCodes.add(error.code);
  }
  const schemaErrorCodes = definitions.errorCode?.enum;
  if (!Array.isArray(schemaErrorCodes) || schemaErrorCodes.length !== errorCodes.size ||
      schemaErrorCodes.some((code) => !errorCodes.has(code))) {
    fail("SOURCE_PARITY_INVALID", "spec errors and schema errorCode enum differ");
  }

  for (const [objectName, reference] of Object.entries(contract.objects)) {
    const definition = referencedDefinition(reference);
    if (!definition || !definitions[definition]) {
      fail("SOURCE_CONTRACT_INVALID", `objects.${objectName} references an unknown definition`);
    }
  }

  const variants = array(definitions.commerceOperation?.oneOf, "$defs.commerceOperation.oneOf");
  const kinds = new Set();
  for (const [index, variant] of variants.entries()) {
    const kind = variant?.properties?.kind?.const;
    if (typeof kind !== "string" || !Array.isArray(variant.required)) {
      fail("SOURCE_CONTRACT_INVALID", `commerceOperation.oneOf[${index}] lacks kind/required`);
    }
    if (kinds.has(kind)) fail("SOURCE_CONTRACT_INVALID", `duplicate commerce operation kind ${kind}`);
    kinds.add(kind);
  }
  const applicability = object(contract.operationKindApplicability, "operationKindApplicability");
  const applicabilityKinds = new Set(Object.keys(applicability));
  if (applicabilityKinds.size !== kinds.size || [...kinds].some((kind) => !applicabilityKinds.has(kind))) {
    fail("SOURCE_PARITY_INVALID", "operationKindApplicability keys must exactly match CommerceOperation kinds");
  }
  for (const variant of variants) {
    const kind = variant.properties.kind.const;
    const entry = object(applicability[kind], `operationKindApplicability.${kind}`);
    const envelopeRequiredFields = array(entry.envelopeRequiredFields,
      `operationKindApplicability.${kind}.envelopeRequiredFields`);
    if (JSON.stringify(envelopeRequiredFields) !== JSON.stringify(variant.required)) {
      fail("SOURCE_PARITY_INVALID", `${kind} envelopeRequiredFields differ from its schema required fields`);
    }
    for (const field of ["resolvedObjectTypes", "permissionEvidence", "conditionalEvidence", "stateMachines",
      "errorCodes", "limitKeys"]) {
      array(entry[field], `operationKindApplicability.${kind}.${field}`);
    }
    for (const objectName of [...entry.resolvedObjectTypes, ...entry.permissionEvidence,
      ...entry.conditionalEvidence.flatMap((conditional) => conditional.objectTypes ?? [])]) {
      if (!contract.objects[objectName]) {
        fail("SOURCE_CONTRACT_INVALID", `${kind} applicability references unknown object ${objectName}`);
      }
    }
    const entryErrorCodes = new Set(entry.errorCodes);
    if (entryErrorCodes.size !== entry.errorCodes.length || entry.errorCodes.some((code) => !errorCodes.has(code))) {
      fail("SOURCE_CONTRACT_INVALID", `${kind} applicability contains duplicate or unknown error codes`);
    }
    const entryLimitKeys = new Set(entry.limitKeys);
    if (entryLimitKeys.size !== entry.limitKeys.length || entry.limitKeys.some((key) => !contract.limits[key])) {
      fail("SOURCE_CONTRACT_INVALID", `${kind} applicability contains duplicate or unknown limit keys`);
    }
    for (const stateMachine of entry.stateMachines) {
      if (!contract.stateMachines[stateMachine.name] ||
          contract.stateMachines[stateMachine.name].authority !== stateMachine.authority) {
        fail("SOURCE_PARITY_INVALID", `${kind} state-machine authority differs from the registry`);
      }
    }
    for (const field of ["chargeableSuccess", "pricing"]) {
      const rule = object(entry[field], `operationKindApplicability.${kind}.${field}`);
      if (typeof rule.applicable !== "boolean") {
        fail("SOURCE_CONTRACT_INVALID", `${kind}.${field}.applicable must be boolean`);
      }
      if (rule.applicable) {
        if (!contract.objects[rule.sourceObject]) {
          fail("SOURCE_CONTRACT_INVALID", `${kind}.${field} sourceObject is unknown`);
        }
        const definitionName = referencedDefinition(contract.objects[rule.sourceObject]);
        if (!definitions[definitionName]?.properties?.[rule.sourceField]) {
          fail("SOURCE_CONTRACT_INVALID", `${kind}.${field} sourceField is unknown`);
        }
      } else if (rule.sourceObject !== null || rule.sourceField !== null) {
        fail("SOURCE_CONTRACT_INVALID", `${kind}.${field} non-applicable source must be null`);
      }
    }
  }

  const requiredDefinitions = [
    "serviceDefinitionVersion",
    "offerVersion",
    "listingMandate",
    "runtimeCapability",
    "taskAgreementVersion",
  ];
  for (const name of requiredDefinitions) {
    if (!definitions[name]) fail("SOURCE_CONTRACT_INVALID", `missing required definition ${name}`);
  }
  object(contract.stateMachines, "stateMachines");
  array(contract.crossObjectBindings, "crossObjectBindings");
}

export function validateNarrative(document, operationKinds, objectNames) {
  if (document === undefined) return { operations: {}, objects: {} };
  object(document, "narrative");
  const topLevel = Object.keys(document);
  if (topLevel.some((key) => !["operations", "objects"].includes(key))) {
    fail("NARRATIVE_OVERRIDE_FORBIDDEN", "narrative may contain only operations and objects");
  }
  const result = { operations: {}, objects: {} };
  for (const [group, allowedNames] of [["operations", operationKinds], ["objects", objectNames]]) {
    const entries = document[group] ?? {};
    object(entries, `narrative.${group}`);
    for (const [name, narrative] of Object.entries(entries)) {
      if (!allowedNames.has(name)) fail("NARRATIVE_OVERRIDE_FORBIDDEN", `unknown ${group} narrative ${name}`);
      object(narrative, `narrative.${group}.${name}`);
      if (Object.keys(narrative).some((key) => !["summary", "description"].includes(key)) ||
          Object.values(narrative).some((value) => typeof value !== "string" || value.length === 0)) {
        fail("NARRATIVE_OVERRIDE_FORBIDDEN",
          "manual narrative can set only non-empty summary/description strings");
      }
      result[group][name] = structuredClone(narrative);
    }
  }
  return result;
}
