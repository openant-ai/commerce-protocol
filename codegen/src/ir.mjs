import { GENERATOR_VERSION } from "./source.mjs";
import { validateNarrative, validateProtocolSource } from "./validate.mjs";

function definitionName(reference) {
  return reference.match(/^#\/\$defs\/([A-Za-z0-9_-]+)$/)?.[1];
}

export function buildContractIr(source, narrativeDocument) {
  validateProtocolSource(source);
  const { contract, schema, sourceDigest } = source;
  const definitions = schema.$defs;
  const variants = definitions.commerceOperation.oneOf;
  const kinds = new Set(variants.map((variant) => variant.properties.kind.const));
  const objectNames = new Set(Object.keys(contract.objects));
  const narrative = validateNarrative(narrativeDocument, kinds, objectNames);
  const schemaForObject = (objectName) =>
    structuredClone(definitions[definitionName(contract.objects[objectName])]);
  const ruleSchema = (rule) => rule.applicable
    ? structuredClone(definitions[definitionName(contract.objects[rule.sourceObject])].properties[rule.sourceField])
    : null;

  const operations = variants.map((variant) => {
    const kind = variant.properties.kind.const;
    const applicability = contract.operationKindApplicability[kind];
    const errorsByCode = new Map(contract.errors.map((error) => [error.code, error]));
    const conditionalObjectTypes = [...new Set(applicability.conditionalEvidence
      .flatMap((conditional) => conditional.objectTypes ?? []))];
    return {
      id: kind.toLowerCase(),
      kind,
      required: structuredClone(variant.required),
      schema: structuredClone(variant),
      applicability: structuredClone(applicability),
      resolvedObjects: Object.fromEntries(applicability.resolvedObjectTypes.map((objectName) => [
        objectName,
        schemaForObject(objectName),
      ])),
      errors: applicability.errorCodes.map((code) => structuredClone(errorsByCode.get(code))),
      limits: Object.fromEntries(applicability.limitKeys.map((key) => [key, structuredClone(contract.limits[key])])),
      permissions: {
        authorizationAssurance: structuredClone(contract.assuranceRequirements.authorization),
        requiredEvidence: structuredClone(applicability.permissionEvidence),
        conditionalEvidence: structuredClone(applicability.conditionalEvidence),
        schemas: Object.fromEntries([...new Set([
          ...applicability.permissionEvidence,
          ...conditionalObjectTypes,
        ])].map((objectName) => [objectName, schemaForObject(objectName)])),
      },
      chargeableSuccess: {
        applicability: structuredClone(applicability.chargeableSuccess),
        schema: ruleSchema(applicability.chargeableSuccess),
      },
      pricing: {
        applicability: structuredClone(applicability.pricing),
        schema: ruleSchema(applicability.pricing),
      },
      stateMachines: {
        registry: structuredClone(applicability.stateMachines),
        definitions: Object.fromEntries(applicability.stateMachines.map(({ name }) => [
          name,
          structuredClone(contract.stateMachines[name]),
        ])),
        externalStateMachineRef: applicability.externalStateMachineRef ?? null,
      },
      narrative: structuredClone(narrative.operations[kind] ?? {}),
    };
  });

  return {
    protocolId: contract.protocol.id,
    protocolVersion: contract.protocol.version,
    wireVersion: contract.protocol.wireVersion,
    sourceDigest,
    generatorVersion: GENERATOR_VERSION,
    operations,
    objects: Object.fromEntries(Object.entries(contract.objects).map(([name, reference]) => [name, {
      reference,
      narrative: structuredClone(narrative.objects[name] ?? {}),
    }])),
    errors: structuredClone(contract.errors),
    limits: structuredClone(contract.limits),
    stateMachines: structuredClone(contract.stateMachines),
  };
}
