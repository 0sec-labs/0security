import type { Finding, ScanReport, Severity } from "../shared/index.js";

const SEVERITY: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

/** DefectDojo wants a repository-relative path. Anything else is left out rather than guessed. */
function relativePath(path: unknown): string | undefined {
  if (typeof path !== "string" || !path || path.startsWith("/") || path.includes("\\") || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(path)) return undefined;
  return path.split("/").includes("..") ? undefined : path;
}

function toDojoFinding(finding: Finding, report: ScanReport): Record<string, unknown> {
  const annotation = finding.reviewAnnotation;
  const path = relativePath(annotation?.path);
  const line = path && Number.isInteger(annotation?.startLine) && annotation!.startLine >= 1 ? annotation!.startLine : undefined;
  const triage = finding.triageStatus;
  const mitigation = finding.remediation
    ? [finding.remediation.summary, ...finding.remediation.steps].filter(Boolean).join("\n")
    : annotation?.fixExplanation;
  return {
    title: finding.title,
    date: report.completedAt.slice(0, 10),
    severity: SEVERITY[finding.severity],
    description: finding.description,
    ...(mitigation ? { mitigation } : {}),
    ...(path ? { file_path: path } : {}),
    ...(line ? { line } : {}),
    ...(finding.cvssScore !== undefined ? { cvssv3_score: finding.cvssScore } : {}),
    ...(finding.cvssVector?.startsWith("CVSS:3") ? { cvssv3: finding.cvssVector } : {}),
    unique_id_from_tool: finding.fingerprint ?? finding.id,
    vuln_id_from_tool: finding.templateId,
    active: finding.status !== "fixed" && finding.status !== "false-positive" && triage !== "accepted" && triage !== "suppressed",
    verified: finding.status === "verified" || finding.status === "confirmed",
    false_p: finding.status === "false-positive",
    risk_accepted: triage === "accepted" || triage === "suppressed",
    tags: [finding.category],
  };
}

/** DefectDojo "Generic Findings Import" JSON. Evidence and proof steps stay out of the file. */
export function formatDefectDojo(report: ScanReport): string {
  return JSON.stringify({ findings: report.findings.map(finding => toDojoFinding(finding, report)) }, null, 2);
}
