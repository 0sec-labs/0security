import { createHash } from "node:crypto";
import { RULES, type AgentConfigFinding, type AgentConfigSeverity } from "./rules.js";

const LEVEL: Record<AgentConfigSeverity, string> = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };
const SCORE: Record<AgentConfigSeverity, string | undefined> = { critical: "9.5", high: "8.0", medium: "5.0", low: "3.0", info: undefined };

/** SARIF 2.1.0. `findings import` reads it: the file, line, snippet, CWE tag and severity come across, and the fingerprint is stable between runs. */
export function agentConfigToSarif(findings: AgentConfigFinding[], options: { toolVersion: string; uri?: (file: string) => string }): object {
  const uri = options.uri ?? ((file: string) => file);
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "0 sbom agent-config", version: options.toolVersion, informationUri: "https://github.com/0sec-labs/0security",
          rules: RULES.map(rule => ({
            id: rule.id, name: rule.title.replace(/[^A-Za-z0-9 ]/g, "").split(" ").map(word => word.charAt(0).toUpperCase() + word.slice(1)).join("").slice(0, 60),
            shortDescription: { text: rule.heuristic && !/heuristic/i.test(rule.title) ? `${rule.title} [heuristic]` : rule.title }, fullDescription: { text: rule.explanation }, help: { text: rule.fix },
            defaultConfiguration: { level: LEVEL[rule.severity] },
            properties: { tags: ["security", "agent-config", ...rule.cwe.map(cwe => `external/cwe/${cwe.toLowerCase()}`)], heuristic: rule.heuristic },
          })),
        },
      },
      results: findings.map(item => ({
        ruleId: item.ruleId, level: LEVEL[item.severity], message: { text: item.message },
        locations: [{ physicalLocation: { artifactLocation: { uri: uri(item.file).split("\\").join("/") }, region: { startLine: item.line, ...(item.column ? { startColumn: item.column } : {}), ...(item.snippet ? { snippet: { text: item.snippet } } : {}) } } }],
        partialFingerprints: { "0AgentConfig/v1": createHash("sha256").update([item.ruleId, item.file, item.message].join("\n")).digest("hex").slice(0, 32) },
        properties: { severity: item.severity, heuristic: item.heuristic, ...(SCORE[item.severity] ? { "security-severity": SCORE[item.severity] } : {}), tags: item.cwe.map(cwe => `external/cwe/${cwe.toLowerCase()}`) },
      })),
    }],
  };
}
