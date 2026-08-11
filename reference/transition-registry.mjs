import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { canonicalJson, digestCanonical } from "./canonical.mjs";
import { PROTOCOL_DIGEST, PROTOCOL_VERSION } from "./constants.mjs";

const contract = JSON.parse(
  readFileSync(new URL("../spec/commerce.json", import.meta.url), "utf8"),
);

function currentSourceDigest() {
  const hash = createHash("sha256");
  for (const relativePath of contract.digest.files) {
    const document = JSON.parse(
      readFileSync(new URL(`../${relativePath}`, import.meta.url), "utf8"),
    );
    hash.update(relativePath, "utf8");
    hash.update("\n", "utf8");
    hash.update(canonicalJson(document), "utf8");
    hash.update("\n", "utf8");
  }
  return `sha256:${hash.digest("hex")}`;
}

const recordedDigest = readFileSync(
  new URL("../schemas/tests/expected-digest.txt", import.meta.url),
  "utf8",
).trim();

if (
  contract.protocol?.version !== PROTOCOL_VERSION ||
  recordedDigest !== PROTOCOL_DIGEST ||
  currentSourceDigest() !== PROTOCOL_DIGEST
) {
  throw new Error("REFERENCE_REGISTRY_VERSION_MISMATCH");
}

const registries = contract.stateMachines;

export class IllegalTransitionError extends Error {
  constructor(machine, from, to) {
    super(`${machine}:${from}->${to}`);
    this.machine = machine;
    this.from = from;
    this.to = to;
  }
}

function registryEdge(machine, from, to, mode, authorizationProfile) {
  const registry = registries[machine];
  if (!registry) throw new IllegalTransitionError(machine, from, to);
  const fullEdge = registry.transitions.find(
    ([candidateFrom, candidateTo]) => candidateFrom === from && candidateTo === to,
  );
  if (!fullEdge) throw new IllegalTransitionError(machine, from, to);
  let edge = fullEdge;
  if (machine === "invocation") {
    const allowed = registry.modeTransitions?.[mode]?.some(
      ([candidateFrom, candidateTo]) => candidateFrom === from && candidateTo === to,
    );
    if (!allowed) throw new IllegalTransitionError(machine, from, to);
  } else if (machine === "paymentIntent") {
    const profileTable = registry.authorizationProfileTransitions?.[authorizationProfile];
    if (!profileTable) throw new IllegalTransitionError(machine, from, to);
    const profileEdge = profileTable.find(
      ([candidateFrom, candidateTo]) => candidateFrom === from && candidateTo === to,
    );
    if (!profileEdge) {
      throw new IllegalTransitionError(machine, from, to);
    }
    edge = profileEdge;
  }
  return edge;
}

export function transition(
  projection,
  machine,
  to,
  trace,
  { mode = "HOSTED", authorizationProfile } = {},
) {
  const from = projection.state;
  const [, , guard] = registryEdge(
    machine,
    from,
    to,
    mode,
    authorizationProfile,
  );
  projection.state = to;
  trace.push({ machine, from, to, guard });
}

export function digestTransitionTrace(transitions) {
  return digestCanonical({
    domain: "OPENANT_REFERENCE_TRANSITION_TRACE_V1",
    transitions,
  });
}
