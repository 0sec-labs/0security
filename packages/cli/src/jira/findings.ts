/**
 * Reads the findings of a scan (`0security scan --format json`, or SARIF) into the shape a Jira issue needs, and keeps only
 * the open ones: findings the agent judged false-positive or fixed, and findings triaged as suppressed, never become issues.
 */
import { createHash } from "node:crypto";
import { looksLikeSarif } from "@0/engine/shared";
import { readInsightFindings, type InsightFinding } from "../code-insights.js";

export type JiraSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface JiraFinding {
  /** Stable id: the scan's finding id, or a hash of rule, place and CWE when the input (SARIF) has none. */
  id: string;
  severity: JiraSeverity;
  title: string;
  location: string;
  description: string;
  impact: string;
  fix: string;
  cwe?: string;
  ruleId: string;
}

type Json = Record<string, unknown>;
const isObject = (value: unknown): value is Json => !!value && typeof value === "object" && !Array.isArray(value);
const str = (value: unknown): string => (typeof value === "string" ? value.trim() : "");
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const severityOf = (value: unknown): JiraSeverity => (typeof value === "string" && SEVERITIES.includes(value) ? value as JiraSeverity : "medium");
const SKIPPED_STATUS = new Set(["false-positive", "fixed"]);

const hashId = (finding: InsightFinding): string => `h${createHash("sha256").update(`${finding.ruleId}\0${finding.path ?? ""}\0${finding.line}\0${finding.cwe ?? ""}`).digest("hex").slice(0, 20)}`;
const place = (path: string | undefined, line: number): string => (path ? (line > 0 ? `${path}:${line}` : path) : "no file cited");

/** The label that marks an issue as the home of one finding. Ids with unusual characters are hashed: Jira labels hold no spaces. */
export function findingLabel(id: string): string {
  return /^[A-Za-z0-9._-]{1,100}$/.test(id) ? `0-finding-${id}` : `0-finding-h${createHash("sha256").update(id).digest("hex").slice(0, 20)}`;
}

export function readJiraFindings(text: string): { open: JiraFinding[]; skipped: number } {
  if (looksLikeSarif(text)) {
    const open = readInsightFindings(text).map((finding): JiraFinding => ({
      id: hashId(finding), severity: finding.severity as JiraSeverity, title: finding.title, location: place(finding.path, finding.line),
      description: finding.description, impact: "", fix: "", ...(finding.cwe ? { cwe: finding.cwe } : {}), ruleId: finding.ruleId,
    }));
    return { open: uniqueById(open), skipped: 0 };
  }
  let document: unknown;
  try { document = JSON.parse(text); } catch { throw new Error("The file is not valid JSON."); }
  if (!isObject(document) || !Array.isArray(document.findings)) throw new Error("Expected `0security scan --format json` output or a SARIF 2.1.0 file.");
  const open: JiraFinding[] = [];
  let skipped = 0;
  for (const raw of document.findings.filter(isObject)) {
    if (SKIPPED_STATUS.has(str(raw.status)) || str(raw.triageStatus) === "suppressed") { skipped++; continue; }
    const [finding] = readInsightFindings(JSON.stringify({ findings: [raw] }));
    if (!finding) continue;
    const impact = isObject(raw.impact) ? str(raw.impact.rationale) : "";
    open.push({
      id: str(raw.id) || hashId(finding), severity: severityOf(raw.severity), title: finding.title, location: place(finding.path, finding.line),
      description: finding.description, impact: impact || finding.rationale || "", fix: fixAdvice(raw, finding), ...(finding.cwe ? { cwe: finding.cwe } : {}), ruleId: finding.ruleId,
    });
  }
  return { open: uniqueById(open), skipped };
}

function fixAdvice(raw: Json, finding: InsightFinding): string {
  const parts: string[] = [];
  if (isObject(raw.remediation)) {
    if (str(raw.remediation.summary)) parts.push(str(raw.remediation.summary));
    if (Array.isArray(raw.remediation.steps)) parts.push(...raw.remediation.steps.filter(step => typeof step === "string").map((step, index) => `${index + 1}. ${step as string}`));
  }
  if (!parts.length && finding.fix) parts.push(finding.fix);
  return parts.join("\n");
}

function uniqueById(findings: JiraFinding[]): JiraFinding[] {
  const seen = new Set<string>();
  return findings.filter(finding => { const label = findingLabel(finding.id); if (seen.has(label)) return false; seen.add(label); return true; });
}
