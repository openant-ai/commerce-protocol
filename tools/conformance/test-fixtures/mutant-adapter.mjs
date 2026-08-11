import { canonicalJson } from "../../../reference/canonical.mjs";
import { runScenario } from "../../../reference/index.mjs";

let input = "";
process.stdin.setEncoding("utf8");
for await (const chunk of process.stdin) input += chunk;
const request = JSON.parse(input);
const response = runScenario(request.scenario);
response.finalState.invocation.state = "DELIVERED";
process.stdout.write(`${canonicalJson(response)}\n`);
