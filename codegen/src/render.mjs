function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
}

export function jsonBytes(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function rewriteSchemaReferences(value) {
  if (Array.isArray(value)) return value.map(rewriteSchemaReferences);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [key,
    key === "$ref" && typeof child === "string" && child.startsWith("#/$defs/")
      ? child.replace("#/$defs/", "#/components/schemas/")
      : rewriteSchemaReferences(child),
  ]));
}

function typeName(definitionName) {
  return definitionName[0].toUpperCase() + definitionName.slice(1).replace(/[^A-Za-z0-9_$]/g, "_");
}

function propertyName(name) {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name) ? name : JSON.stringify(name);
}

function resolvedSchema(schema, definitions) {
  const name = schema?.$ref?.match(/^#\/\$defs\/([A-Za-z0-9_-]+)$/)?.[1];
  return name && definitions[name] ? definitions[name] : schema;
}

function intersection(parts) {
  const usable = parts.filter((value) => value && value !== "unknown");
  return usable.length > 0 ? usable.join(" & ") : "unknown";
}

function union(parts) {
  const usable = parts.filter((value) => value && value !== "never");
  return usable.length > 0 ? usable.join(" | ") : "never";
}

function negateCondition(condition, originalSchema, inheritedProperties, definitions) {
  if (!condition || typeof condition !== "object") return "unknown";
  const original = resolvedSchema(originalSchema ?? {}, definitions) ?? {};
  if (Object.hasOwn(condition, "const")) {
    return `Exclude<${schemaType(original, {}, [], definitions)}, ${JSON.stringify(condition.const)}>`;
  }
  if (Array.isArray(condition.enum)) {
    return `Exclude<${schemaType(original, {}, [], definitions)}, ${condition.enum
      .map((value) => JSON.stringify(value)).join(" | ")}>`;
  }
  if (condition.not) {
    return schemaType(condition.not, inheritedProperties, [], definitions, originalSchema);
  }
  if (Array.isArray(condition.anyOf)) {
    return intersection(condition.anyOf.map((child) =>
      negateCondition(child, originalSchema, inheritedProperties, definitions)));
  }
  if (Array.isArray(condition.allOf)) {
    return `(${union(condition.allOf.map((child) =>
      negateCondition(child, originalSchema, inheritedProperties, definitions)))})`;
  }
  if (condition.properties || condition.required) {
    const alternatives = [];
    const required = new Set(condition.required ?? []);
    for (const name of required) alternatives.push(`{ readonly ${propertyName(name)}?: never; }`);
    for (const [name, child] of Object.entries(condition.properties ?? {})) {
      const originalChild = inheritedProperties[name] ?? original.properties?.[name] ?? {};
      const nestedOriginal = resolvedSchema(originalChild, definitions);
      const negated = negateCondition(child, originalChild, nestedOriginal?.properties ?? {}, definitions);
      if (negated !== "unknown") {
        alternatives.push(`{ readonly ${propertyName(name)}: ${negated}; }`);
      }
    }
    return `(${union(alternatives)})`;
  }
  return "unknown";
}

function conditionValuePaths(condition, prefix = [], paths = new Map()) {
  if (!condition || typeof condition !== "object") return paths;
  if (prefix.length > 0 && (Object.hasOwn(condition, "const") || Array.isArray(condition.enum) ||
      Object.hasOwn(condition.not ?? {}, "const"))) {
    paths.set(prefix.join("."), prefix);
  }
  for (const [name, child] of Object.entries(condition.properties ?? {})) {
    conditionValuePaths(child, [...prefix, name], paths);
  }
  for (const child of [...(condition.anyOf ?? []), ...(condition.allOf ?? [])]) {
    conditionValuePaths(child, prefix, paths);
  }
  if (condition.not && !Object.hasOwn(condition.not, "const")) {
    conditionValuePaths(condition.not, prefix, paths);
  }
  return paths;
}

function sourceSchemaAtPath(schema, pathSegments, definitions) {
  let current = schema;
  for (const segment of pathSegments) {
    current = resolvedSchema(current, definitions);
    if (!current?.properties?.[segment] || !(current.required ?? []).includes(segment)) return null;
    current = current.properties[segment];
  }
  return resolvedSchema(current, definitions);
}

function finiteValues(schema) {
  if (Array.isArray(schema?.enum)) return schema.enum;
  if (schema && Object.hasOwn(schema, "const")) return [schema.const];
  return null;
}

function cartesianAssignments(entries, index = 0, assignment = new Map(), result = []) {
  if (index === entries.length) {
    result.push(new Map(assignment));
    return result;
  }
  const [pathKey, values] = entries[index];
  for (const value of values) {
    assignment.set(pathKey, value);
    cartesianAssignments(entries, index + 1, assignment, result);
  }
  assignment.delete(pathKey);
  return result;
}

function combineTruth(values, mode) {
  if (mode === "all") {
    if (values.includes(false)) return false;
    return values.every((value) => value === true) ? true : undefined;
  }
  if (values.includes(true)) return true;
  return values.every((value) => value === false) ? false : undefined;
}

function evaluateCondition(condition, assignment, prefix = []) {
  if (!condition || typeof condition !== "object") return undefined;
  const assigned = assignment.get(prefix.join("."));
  if (Object.hasOwn(condition, "const") && assigned !== undefined) return assigned === condition.const;
  if (Array.isArray(condition.enum) && assigned !== undefined) return condition.enum.includes(assigned);
  if (condition.not) {
    const inner = evaluateCondition(condition.not, assignment, prefix);
    if (inner !== undefined) return !inner;
  }
  if (Array.isArray(condition.anyOf)) {
    return combineTruth(condition.anyOf.map((child) => evaluateCondition(child, assignment, prefix)), "any");
  }
  if (Array.isArray(condition.allOf)) {
    return combineTruth(condition.allOf.map((child) => evaluateCondition(child, assignment, prefix)), "all");
  }
  const results = [];
  for (const name of condition.required ?? []) {
    const key = [...prefix, name].join(".");
    const knownPresent = assignment.has(key) || [...assignment.keys()].some((pathKey) => pathKey.startsWith(`${key}.`));
    results.push(knownPresent ? true : undefined);
  }
  for (const [name, child] of Object.entries(condition.properties ?? {})) {
    results.push(evaluateCondition(child, assignment, [...prefix, name]));
  }
  return results.length > 0 ? combineTruth(results, "all") : undefined;
}

function assignmentConstraint(pathSegments, value) {
  let type = JSON.stringify(value);
  for (const segment of [...pathSegments].reverse()) {
    type = `{ readonly ${propertyName(segment)}: ${type}; }`;
  }
  return type;
}

function requiredOnlyTrigger(condition) {
  if (!Array.isArray(condition?.required) || condition.required.length === 0) return null;
  const semanticKeys = Object.keys(condition).filter((key) => key !== "required");
  return semanticKeys.length === 0 ? condition.required : null;
}

function forbiddenFields(fields) {
  return `{ ${fields.map((name) => `readonly ${propertyName(name)}?: never;`).join(" ")} }`;
}

function schemaWithoutApplicators(schema) {
  const {
    allOf: _allOf,
    anyOf: _anyOf,
    oneOf: _oneOf,
    not: _not,
    if: _if,
    then: _then,
    else: _else,
    ...base
  } = schema;
  return base;
}

function fallbackConditionalType(clause, properties, definitions) {
  const positive = schemaType(clause.if, properties, [], definitions);
  const negative = negateCondition(
    clause.if,
    { type: "object", properties },
    properties,
    definitions,
  );
  const positiveBranch = intersection([
    positive,
    clause.then ? schemaType(clause.then, properties, [], definitions) : "unknown",
  ]);
  const negativeBranch = intersection([
    negative,
    clause.else ? schemaType(clause.else, properties, [], definitions) : "unknown",
  ]);
  return `(${positiveBranch} | ${negativeBranch})`;
}

function conditionalMatrixType(schema, properties, definitions) {
  const clauses = schema.allOf ?? [];
  if (!clauses.some((clause) => clause.if)) return null;
  const paths = new Map();
  for (const clause of clauses) {
    if (clause.if) conditionValuePaths(clause.if, [], paths);
    if (clause.not) conditionValuePaths(clause.not, [], paths);
  }
  const discriminants = [];
  for (const [pathKey, pathSegments] of paths) {
    const sourceSchema = sourceSchemaAtPath(schema, pathSegments, definitions);
    const values = finiteValues(sourceSchema);
    if (values) discriminants.push([pathKey, values, pathSegments]);
  }
  const combinations = discriminants.reduce((count, [, values]) => count * values.length, 1);
  if (discriminants.length === 0 || combinations > 128) return null;

  const assignments = cartesianAssignments(discriminants.map(([pathKey, values]) => [pathKey, values]));
  const branches = [];
  for (const assignment of assignments) {
    const parts = discriminants.map(([pathKey, , pathSegments]) =>
      assignmentConstraint(pathSegments, assignment.get(pathKey)));
    let impossible = false;
    for (const clause of clauses) {
      if (clause.not && !clause.if) {
        const truth = evaluateCondition(clause.not, assignment);
        if (truth === true) {
          impossible = true;
          break;
        }
        if (truth === undefined) parts.push(schemaType(clause, properties, [], definitions));
        continue;
      }
      if (!clause.if) {
        parts.push(schemaType(clause, properties, [], definitions));
        continue;
      }
      const truth = evaluateCondition(clause.if, assignment);
      if (truth === undefined) {
        const trigger = requiredOnlyTrigger(clause.if);
        const consequence = clause.then ? evaluateCondition(clause.then, assignment) : true;
        if (trigger && consequence === false) parts.push(forbiddenFields(trigger));
        else if (!(trigger && consequence === true)) {
          parts.push(fallbackConditionalType(clause, properties, definitions));
        }
        continue;
      }
      const selected = truth ? clause.then : clause.else;
      if (!selected) continue;
      if (evaluateCondition(selected, assignment) === false) {
        impossible = true;
        break;
      }
      parts.push(schemaType(selected, properties, [], definitions));
    }
    if (!impossible) branches.push(intersection(parts));
  }
  return branches.length > 0 ? `(${branches.join(" | ")})` : "never";
}

function schemaType(
  schema,
  inheritedProperties = {},
  forbiddenProperties = [],
  definitions = {},
  fallbackSchema = undefined,
) {
  if (!schema || typeof schema !== "object") return "unknown";
  const effectiveProperties = { ...inheritedProperties, ...(schema.properties ?? {}) };
  const base = (() => {
    if (schema.$ref) return typeName(schema.$ref.split("/").at(-1));
    if (Object.hasOwn(schema, "const")) return JSON.stringify(schema.const);
    if (Array.isArray(schema.enum)) return schema.enum.map((value) => JSON.stringify(value)).join(" | ");
    if (schema.type === "string") return "string";
    if (schema.type === "number" || schema.type === "integer") return "number";
    if (schema.type === "boolean") return "boolean";
    if (schema.type === "null") return "null";
    if (schema.type === "array") return `ReadonlyArray<${schemaType(schema.items)}>`;
    if (schema.type === "object" || schema.properties || schema.required || schema.additionalProperties ||
        forbiddenProperties.length > 0) {
      const propertyEntries = schema.properties
        ? Object.entries(schema.properties)
        : (schema.required ?? []).map((name) => [name, effectiveProperties[name] ?? {}]);
      if (propertyEntries.length === 0 && forbiddenProperties.length === 0) {
        const additional = typeof schema.additionalProperties === "object"
          ? schemaType(schema.additionalProperties)
          : "unknown";
        return `Readonly<Record<string, ${additional}>>`;
      }
      const required = new Set(schema.required ?? []);
      const fields = propertyEntries.map(([name, child]) => {
        const originalChild = inheritedProperties[name] ?? child;
        const nestedOriginal = resolvedSchema(originalChild, definitions);
        return `readonly ${propertyName(name)}${required.has(name) ? "" : "?"}: ${schemaType(
          child,
          nestedOriginal?.properties ?? {},
          [],
          definitions,
          originalChild,
        )};`;
      });
      const declared = new Set(propertyEntries.map(([name]) => name));
      for (const name of forbiddenProperties) {
        if (!declared.has(name)) fields.push(`readonly ${propertyName(name)}?: never;`);
      }
      return `{ ${fields.join(" ")} }`;
    }
    return "unknown";
  })();
  const intersections = [];
  const hasApplicator = Array.isArray(schema.allOf) || Array.isArray(schema.oneOf) || Array.isArray(schema.anyOf);
  if (base !== "unknown" && !(hasApplicator && base === "Readonly<Record<string, unknown>>")) {
    intersections.push(base);
  }
  const conditionalMatrix = conditionalMatrixType(schema, effectiveProperties, definitions);
  if (conditionalMatrix) {
    intersections.push(conditionalMatrix);
  } else if (Array.isArray(schema.allOf)) {
    intersections.push(...schema.allOf.map((child) =>
      schemaType(child, effectiveProperties, [], definitions, fallbackSchema)));
  }
  if (Array.isArray(schema.oneOf)) {
    const requiredByBranch = schema.oneOf.map((child) => new Set(child.required ?? []));
    const exclusiveProperties = new Set(requiredByBranch.flatMap((required) => [...required]));
    intersections.push(`(${schema.oneOf.map((child, index) => schemaType(
      child,
      effectiveProperties,
      [...exclusiveProperties].filter((name) => !requiredByBranch[index].has(name)),
      definitions,
      fallbackSchema,
    )).join(" | ")})`);
  }
  if (Array.isArray(schema.anyOf)) {
    intersections.push(`(${schema.anyOf.map((child) =>
      schemaType(child, effectiveProperties, [], definitions, fallbackSchema)).join(" | ")})`);
  }
  if (schema.not) {
    intersections.push(negateCondition(
      schema.not,
      fallbackSchema ?? schemaWithoutApplicators(schema),
      effectiveProperties,
      definitions,
    ));
  }
  if (schema.if && !conditionalMatrix) {
    const positive = schemaType(schema.if, effectiveProperties, [], definitions);
    const negative = negateCondition(
      schema.if,
      { type: "object", properties: effectiveProperties },
      effectiveProperties,
      definitions,
    );
    const positiveBranch = intersection([
      positive,
      schema.then ? schemaType(schema.then, effectiveProperties, [], definitions) : "unknown",
    ]);
    const negativeBranch = intersection([
      negative,
      schema.else ? schemaType(schema.else, effectiveProperties, [], definitions) : "unknown",
    ]);
    intersections.push(`(${positiveBranch} | ${negativeBranch})`);
  }
  return intersections.filter((value) => value !== "unknown").join(" & ") || "unknown";
}

function renderOpenApi(ir, schema) {
  return jsonBytes({
    openapi: "3.1.0",
    info: {
      title: "OpenAnt Commerce Protocol",
      version: ir.protocolVersion,
      description: "Generated transport-neutral Commerce Catalog contract components.",
      "x-source-digest": ir.sourceDigest,
      "x-generator-version": ir.generatorVersion,
    },
    paths: {},
    components: { schemas: rewriteSchemaReferences(schema.$defs) },
    "x-openant-generated": {
      protocolVersion: ir.protocolVersion,
      sourceDigest: ir.sourceDigest,
      generatorVersion: ir.generatorVersion,
    },
    "x-openant-commerce-contract": ir,
  });
}

function renderTypescript(ir, schema) {
  const metadata = {
    protocolVersion: ir.protocolVersion,
    sourceDigest: ir.sourceDigest,
    generatorVersion: ir.generatorVersion,
  };
  const contract = JSON.stringify(sorted(ir));
  const definitions = Object.entries(schema.$defs)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, definition]) =>
      `export type ${typeName(name)} = ${schemaType(definition, {}, [], schema.$defs)};`)
    .join("\n");
  return `/* Generated by @openant/commerce-codegen. Do not edit. */\n` +
    `export const GENERATED_METADATA = ${JSON.stringify(sorted(metadata), null, 2)} as const;\n` +
    `/* COMMERCE_CONTRACT_JSON_START\n${contract}\nCOMMERCE_CONTRACT_JSON_END */\n` +
    `export const COMMERCE_CONTRACT = ${contract} as const;\n` +
    `export const COMMERCE_SCHEMAS = ${JSON.stringify(sorted(schema.$defs))} as const;\n\n` +
    `${definitions}\n`;
}

function renderMcp(ir, schema) {
  return jsonBytes({
    schemaVersion: "2025-06-18",
    metadata: {
      generated: {
        protocolVersion: ir.protocolVersion,
        sourceDigest: ir.sourceDigest,
        generatorVersion: ir.generatorVersion,
      },
      contract: ir,
    },
    tools: ir.operations.map((operation) => ({
      name: `openant_commerce_${operation.id}`,
      title: operation.narrative.summary ?? `OpenAnt Commerce ${operation.kind}`,
      description: operation.narrative.description ??
        `Accepts the canonical ${operation.kind} CommerceOperation envelope.`,
      inputSchema: { ...operation.schema, $defs: schema.$defs },
      _meta: {
        protocolVersion: ir.protocolVersion,
        sourceDigest: ir.sourceDigest,
        generatorVersion: ir.generatorVersion,
      },
    })),
  });
}

function renderCli(ir) {
  const metadata = {
    protocolVersion: ir.protocolVersion,
    sourceDigest: ir.sourceDigest,
    generatorVersion: ir.generatorVersion,
  };
  const commands = ir.operations.map(({ id, kind, required, narrative }) => ({
    name: id,
    kind,
    required,
    summary: narrative.summary ?? `Build a ${kind} CommerceOperation envelope.`,
  }));
  return `#!/usr/bin/env node\n` +
    `/* Generated by @openant/commerce-codegen. Do not edit. */\n` +
    `export const GENERATED_METADATA = ${JSON.stringify(sorted(metadata), null, 2)};\n` +
    `export const COMMERCE_CONTRACT = ${JSON.stringify(sorted(ir), null, 2)};\n` +
    `export const COMMANDS = ${JSON.stringify(sorted(commands), null, 2)};\n` +
    `export function describeCommands() { return { metadata: GENERATED_METADATA, commands: COMMANDS }; }\n` +
    `if (process.argv[1] && import.meta.url === new URL(\`file://\${process.argv[1]}\`).href) {\n` +
    `  process.stdout.write(\`${"${JSON.stringify(describeCommands(), null, 2)}"}\\n\`);\n` +
    `}\n`;
}

function renderSkill(ir) {
  return jsonBytes({
    name: "openant-commerce",
    version: ir.protocolVersion,
    description: "Generated metadata for OpenAnt Commerce operation envelopes.",
    metadata: {
      generated: {
        protocolVersion: ir.protocolVersion,
        sourceDigest: ir.sourceDigest,
        generatorVersion: ir.generatorVersion,
      },
      contract: ir,
    },
    operations: ir.operations.map(({ id, kind, required, narrative }) => ({
      command: id,
      kind,
      required,
      summary: narrative.summary ?? `Construct a ${kind} CommerceOperation envelope.`,
    })),
  });
}

export function renderArtifacts(ir, schema) {
  return new Map([
    ["openapi-3.1.json", renderOpenApi(ir, schema)],
    ["commerce-types.ts", renderTypescript(ir, schema)],
    ["mcp-tools.json", renderMcp(ir, schema)],
    ["cli-skeleton.mjs", renderCli(ir)],
    ["skill-metadata.json", renderSkill(ir)],
  ]);
}
