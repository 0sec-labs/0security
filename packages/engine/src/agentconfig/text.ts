import type { AgentConfigFinding } from "./rules.js";
import type { AgentConfigReport } from "./scan.js";

/** The report as plain text: one block per finding, then a summary line. */
export function agentConfigToText(report: AgentConfigReport): string {
  const lines: string[] = [];
  for (const item of report.findings) {
    lines.push(`${item.file}:${item.line}${item.column ? `:${item.column}` : ""}  ${item.severity}${item.heuristic ? " (heuristic)" : ""}  ${item.ruleId}`);
    lines.push(`    ${item.message}`);
    if (item.snippet) lines.push(`    > ${item.snippet}`);
    lines.push(`    fix: ${item.fix}`);
  }
  const count = (severity: AgentConfigFinding["severity"]): number => report.findings.filter(item => item.severity === severity).length;
  lines.push(report.findings.length ? `${report.findings.length} finding${report.findings.length === 1 ? "" : "s"} in ${report.filesScanned.length} file${report.filesScanned.length === 1 ? "" : "s"}: ${count("critical")} critical, ${count("high")} high, ${count("medium")} medium, ${count("low")} low.` : `No findings in ${report.filesScanned.length} agent configuration file${report.filesScanned.length === 1 ? "" : "s"}.`);
  return `${lines.join("\n")}\n`;
}
