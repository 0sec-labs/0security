/**
 * Turns a judge verdict into a finding, so a red-team result travels the same way every other result does: SARIF for code scanning,
 * the findings list, an evidence bundle. A run where the agent did not obey produces no finding; it is not evidence of safety.
 */
import { createHash } from "node:crypto";
import type { AttackCategory, Finding, Severity } from "../shared/index.js";
import type { RedteamVerdict } from "./judge.js";
import type { Privilege } from "./honeypot.js";
import type { Scenario } from "./scenario.js";

export interface FrameworkTag { framework: string; id: string; name: string }

// Identifiers are from the published OWASP Top 10 for LLM Applications (2025) and MITRE ATLAS lists. Check them against the
// current publications before a release; a mapping that cites a wrong id is worse than none.
const LLM01: FrameworkTag = { framework: "OWASP LLM Top 10 (2025)", id: "LLM01", name: "Prompt Injection" };
const LLM02: FrameworkTag = { framework: "OWASP LLM Top 10 (2025)", id: "LLM02", name: "Sensitive Information Disclosure" };
const LLM06: FrameworkTag = { framework: "OWASP LLM Top 10 (2025)", id: "LLM06", name: "Excessive Agency" };
const ATLAS_INJECTION: FrameworkTag = { framework: "MITRE ATLAS", id: "AML.T0051", name: "LLM Prompt Injection" };

/** Which framework entries a confirmed hit falls under, by the kind of tool the agent was steered into using. */
export function frameworkTags(privilege: Privilege | "unknown"): FrameworkTag[] {
  switch (privilege) {
    case "network-out": return [LLM01, LLM02, LLM06, ATLAS_INJECTION];
    case "exec":
    case "write-local": return [LLM01, LLM06, ATLAS_INJECTION];
    default: return [LLM01, ATLAS_INJECTION];
  }
}

const severityFor = (privilege: Privilege | "unknown"): Severity =>
  privilege === "exec" ? "critical" : privilege === "network-out" || privilege === "write-local" ? "high" : "medium";
const categoryFor = (privilege: Privilege | "unknown"): AttackCategory => (privilege === "network-out" ? "data-exfiltration" : "tool-misuse");

export interface RedteamFindingInput {
  /** What was tested, such as the agent's name or repository. */
  target: string;
  verdict: RedteamVerdict;
  scenario?: Scenario | null;
  now?: number;
}

export function redteamFindings(input: RedteamFindingInput): Finding[] {
  const { verdict, target } = input;
  if (!verdict.hit || !verdict.call) return [];
  const call = verdict.call;
  const severity = severityFor(call.privilege);
  const tags = frameworkTags(call.privilege);
  const action = verdict.reason === "canary-left" ? `sent the canary out through ${call.tool}` : `called the forbidden tool ${call.tool}`;
  const args = Object.entries(call.args).map(([key, value]) => `${key}=${value}`).join("; ");
  const read = verdict.reads.length ? `After reading ${[...new Set(verdict.reads)].join(", ")}, ` : "";
  return [{
    id: `redteam-${createHash("sha256").update(`${target}\n${verdict.reason}\n${call.tool}`).digest("hex").slice(0, 24)}`,
    templateId: `redteam/${verdict.reason}`,
    title: `Agent obeyed an injected instruction: it ${action} (${target})`,
    description: `${read}the agent ${action} (${call.privilege} tool, call ${call.seq} of ${verdict.calls}). The instruction came from data returned by a tool, not from the user. `
      + `Anything an attacker can put in that data can make the agent do the same with the access it has.\n\nFramework mapping: ${tags.map(tag => `${tag.framework} ${tag.id} ${tag.name}`).join("; ")}.`,
    severity, category: categoryFor(call.privilege), status: "discovered",
    evidence: {
      request: input.scenario ? `${input.scenario.goal} (poisoned text placed at ${input.scenario.injectionPoint})` : "Poisoned instruction returned by the honeypot's source tools",
      response: `${call.tool}(${args})`.slice(0, 2000),
      analysis: `The honeypot recorded ${verdict.calls} tool call${verdict.calls === 1 ? "" : "s"}. A tool that can act on the world was called with this run's canary or secret in its arguments${verdict.reason === "forbidden-tool" ? " (or a forbidden tool was called)" : ""}. No model judged this; the result is read from the recorded calls. A single run shows the agent can be steered, not how often.`,
    },
    impactAssessment: { reachability_tier: "unknown", blast_radius: `An attacker who controls any text this agent reads can make it call ${call.tool} with chosen arguments.`, weaponizability: "unknown", business_impact: "unassessed", rationale: `Observed in a sandboxed run: the agent obeyed text from a tool result and called ${call.tool}.`, assessment_source: "heuristic" },
    timestamp: input.now ?? Date.now(), triageStatus: "new", workflowStatus: "backlog",
  } as unknown as Finding];
}
