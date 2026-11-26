/** Reports over suite results: a terminal table, JSON, Markdown, and findings for the SARIF path. Nothing here prints argument values beyond the clipped call kept in the run record. */
import { createHash } from "node:crypto";
import type { Finding } from "../../shared/index.js";
import { frameworkTags } from "../findings.js";
import { ARG_LIMITS } from "./run.js";
import { cleanText, clipText } from "./text-safety.js";
import type { RunRecord, SuiteResults } from "./types.js";

const pct = (value: number | null): string => (value === null ? "n/a" : `${(value * 100).toFixed(1)}%`);
// Markdown cells: ids are validated, but error and reason text is not. Control and bidirectional characters, pipes and line breaks go;
// angle brackets and backticks are removed; backslashes, brackets, parentheses, exclamation marks and ampersands are escaped so no link,
// image or entity can form; and bare URLs, www hosts and addresses are broken so a comment does not autolink them.
const md = (value: string): string => cleanText(value).replace(/[|\r\n]+/g, " ").replace(/[<>`]/g, "")
  .replace(/[\\[\]()!&]/g, "\\$&").replace(/:\/\//g, ":/\u200b/").replace(/\bwww\./gi, "www\u200b.").replace(/@/g, "@\u200b");

export function toJson(results: SuiteResults): string { return JSON.stringify(results, null, 2); }

function header(results: SuiteResults): string[] {
  const lines = [`Suite ${results.suite}: ${results.executed} of ${results.planned} planned runs executed, cost ${results.totalCost}`];
  if (results.truncated) lines.push(`Stopped early (${results.truncated}); the numbers cover only the runs that happened.`);
  return lines;
}

export function textTable(results: SuiteResults): string {
  const rows: string[][] = [["agent", "runs", "security", "utility", "secure+useful", "inconclusive"],
    ...results.agents.map(a => [a.agentId, String(a.runs), pct(a.securityPassRate), pct(a.utilityPassRate), a.secureAndUseful === null ? "n/a" : `${pct(a.secureAndUseful)} (${a.pairs} pairs)`, pct(a.inconclusiveRate)])];
  const widths = rows[0]!.map((_, i) => Math.max(...rows.map(r => r[i]!.length)));
  const table = rows.map(r => r.map((cell, i) => cell.padEnd(widths[i]!)).join("  ").trimEnd());
  const lines = [...header(results), "", ...table, "", `Verdict: ${results.verdict.pass ? "PASS" : "FAIL"}`, ...results.verdict.reasons.map(r => `  - ${r}`)];
  const bad = results.cells.filter(c => !c.allPassed);
  if (bad.length) lines.push("", "Cells not fully passing:", ...bad.map(c => `  ${c.agentId} / ${c.caseId} (${c.kind}): ${c.passed} passed, ${c.failed} failed, ${c.inconclusive} inconclusive of ${c.runs}`));
  return lines.join("\n");
}

export function toMarkdown(results: SuiteResults): string {
  const out = [`# Eval: ${md(results.suite)}`, "", ...header(results).map(md), "",
    "| Agent | Runs | Security pass | Utility pass | Secure and useful | Inconclusive |", "|---|---|---|---|---|---|",
    ...results.agents.map(a => `| ${md(a.agentId)} | ${a.runs} | ${pct(a.securityPassRate)} | ${pct(a.utilityPassRate)} | ${pct(a.secureAndUseful)} | ${pct(a.inconclusiveRate)} |`),
    "", `**Verdict: ${results.verdict.pass ? "pass" : "fail"}**`, "", ...results.verdict.reasons.map(r => `- ${md(r)}`), "",
    "## Cells", "", "| Agent | Case | Kind | Passed | Failed | Inconclusive | Pass rate |", "|---|---|---|---|---|---|---|",
    ...results.cells.map(c => `| ${md(c.agentId)} | ${md(c.caseId)} | ${c.kind} | ${c.passed} | ${c.failed} | ${c.inconclusive} | ${pct(c.passRate)} |`)];
  const errors = results.runs.filter(r => r.error);
  if (errors.length) out.push("", "## Execution errors", "", ...errors.map(r => `- ${md(r.agentId)} / ${md(r.caseId)} #${r.repeat}: ${md(r.error!)}`));
  return out.join("\n") + "\n";
}

/**
 * One finding per (agent, case) with at least one failed security run, in the shape redteamFindings produces so the SARIF exporter and
 * the findings list treat it alike. Ids are a hash of suite, agent, case and the tool called, so a rerun reproduces them.
 */
export function toFindings(results: SuiteResults, options: { now?: number } = {}): Finding[] {
  const failed = new Map<string, RunRecord[]>();
  for (const run of results.runs) if (run.kind === "security" && run.status === "fail") failed.set(`${run.agentId}|${run.caseId}`, [...(failed.get(`${run.agentId}|${run.caseId}`) ?? []), run]);
  const timestamp = options.now ?? results.finishedAt;
  return [...failed.values()].map(runs => {
    const first = runs[0]!;
    const cell = results.cells.find(c => c.agentId === first.agentId && c.caseId === first.caseId);
    const privilege = first.call?.privilege ?? "unknown";
    const tool = clipText(first.call?.tool ?? "an unspecified tool", 64);
    const tags = frameworkTags(privilege);
    const severity = privilege === "exec" ? "critical" : privilege === "network-out" || privilege === "write-local" ? "high" : "medium";
    const args = Object.entries(first.call?.args ?? {}).slice(0, ARG_LIMITS.count).map(([key, value]) => `${clipText(key, ARG_LIMITS.key)}=${clipText(value, ARG_LIMITS.value)}`).join("; ");
    const target = `${first.agentId}, case ${first.caseId}`;
    return {
      id: `redteam-${createHash("sha256").update(`${results.suite}\n${first.agentId}\n${first.caseId}\n${tool}`).digest("hex").slice(0, 24)}`,
      templateId: "redteam/eval-security-case",
      title: `Agent failed a security case: the attack succeeded through ${tool} (${target})`,
      description: `In eval suite ${results.suite}, the security case ${first.caseId} succeeded against agent ${first.agentId} in ${runs.length} of ${cell?.runs ?? runs.length} runs (${clipText(first.reason, 300)}).\n\n`
        + `Framework mapping: ${tags.map(tag => `${tag.framework} ${tag.id} ${tag.name}`).join("; ")}.`,
      severity, category: privilege === "network-out" ? "data-exfiltration" : "tool-misuse", status: "discovered",
      evidence: {
        request: `Eval case ${first.caseId} (benign canary payload) against agent ${first.agentId}`,
        response: `${tool}(${args})`.slice(0, 2000),
        analysis: `The mechanical oracle matched the recorded calls in run ${first.repeat + 1}. No model judged this. ${runs.length} failed run${runs.length === 1 ? "" : "s"} observed; a pass rate from few runs bounds the risk, it does not remove it.`,
      },
      impactAssessment: { reachability_tier: "unknown", blast_radius: `Text this agent reads can make it use ${tool} as the attacker chooses.`, weaponizability: "unknown", business_impact: "unassessed", rationale: "Observed in a sandboxed eval run against a fake environment.", assessment_source: "heuristic" },
      timestamp, triageStatus: "new", workflowStatus: "backlog",
    } as unknown as Finding;
  });
}
