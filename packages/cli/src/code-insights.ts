/**
 * Bitbucket Code Insights for triaged findings, for Bitbucket Cloud and Data Center.
 *
 * The input is `0 scan --format json` (it carries the agent's verdict, rationale and fix) or any SARIF 2.1.0 file.
 * `buildCodeInsights` is pure: it dedupes, ranks, caps and shapes the payload. `postCodeInsights` sends it with an
 * injected `fetch`, so tests never touch a network.
 *
 * Limits, as published by Atlassian:
 * - Cloud (OpenAPI document of api.bitbucket.org): at most 100 annotations per bulk POST, 1000 per report, 10 report
 *   data items; severities CRITICAL, HIGH, MEDIUM, LOW; report result PASSED, FAILED, PENDING.
 * - Data Center (OpenAPI document of the 9.6 REST reference): at most 6 report data items, title/reporter/externalId
 *   450 characters, annotation message 2000 characters, severities LOW, MEDIUM, HIGH (there is no CRITICAL), report
 *   result PASS or FAIL, 1000 annotations per report by default (`plugin.bitbucket-code-insights.report.annotations.max`);
 *   a request that would exceed the cap is rejected whole. The documents state no per-request limit for Data Center.
 * Not published, so chosen conservatively here: the maximum length of Cloud `summary` and `details`.
 */
import { createHash } from "node:crypto";
import { looksLikeSarif, parseSarif } from "@0/engine/shared";

export type CodeInsightsPlatform = "bitbucket-cloud" | "bitbucket-dc";
export const MAX_ANNOTATIONS = 1000;
export const CLOUD_BATCH_SIZE = 100;
/** Data Center states no per-request limit; this keeps each request small while staying far below the report cap. */
export const DC_BATCH_SIZE = 100;
const CLOUD_SUMMARY_MAX = 450;
const TEXT_MAX = 2000;
export const DEFAULT_REPORT_ID = "0-security";

const SEVERITY_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
type Level = "info" | "low" | "medium" | "high" | "critical";

/** One finding in the shape this reporter needs, whatever file it came from. */
export interface InsightFinding {
  ruleId: string;
  severity: Level;
  title: string;
  /** Repo-relative path with forward slashes; absent when the finding cites no place. */
  path?: string;
  line: number;
  cwe?: string;
  description: string;
  /** The agent's verdict (status and confidence) and its reasoning. */
  verdict?: string;
  rationale?: string;
  fix?: string;
}

type Json = Record<string, unknown>;
const isObject = (value: unknown): value is Json => !!value && typeof value === "object" && !Array.isArray(value);
const str = (value: unknown): string => (typeof value === "string" ? value.trim() : "");
const level = (value: unknown): Level => (typeof value === "string" && value in SEVERITY_RANK ? value as Level : "medium");

/** The agent stores the CWE as a "CWE: CWE-89" tag at the start of its analysis. */
function cweOf(text: string): string | undefined {
  const match = /\bCWE[-: ]+(\d{1,5})\b/i.exec(text);
  return match ? `CWE-${Number(match[1])}` : undefined;
}
/** The analysis without the leading CVE/CWE tag line. */
function withoutTag(text: string): string { return text.replace(/^(?:CVE: \S+)?(?: \| )?(?:CWE: CWE-\d+)?\n*/, "").trim(); }

function normalizePath(path: string): string | undefined {
  const value = path.replace(/\\/g, "/").replace(/^(\.\/)+/, "");
  if (!value || value.startsWith("/") || /^[A-Za-z]:\//.test(value) || value.split("/").includes("..")) return undefined;
  return value;
}

/** Findings from a `0 scan --format json` document or a SARIF file. Throws a short message for anything else. */
export function readInsightFindings(text: string): InsightFinding[] {
  if (looksLikeSarif(text)) {
    return parseSarif(text).findings.map(finding => ({
      ruleId: finding.ruleId, severity: finding.severity as Level, title: finding.title,
      ...(finding.path && normalizePath(finding.path) ? { path: normalizePath(finding.path)! } : {}),
      line: finding.startLine ?? 0, ...(finding.cwe[0] ? { cwe: finding.cwe[0] } : {}), description: finding.description,
    }));
  }
  let document: unknown;
  try { document = JSON.parse(text); } catch { throw new Error("The file is not valid JSON."); }
  if (!isObject(document) || !Array.isArray(document.findings)) throw new Error("Expected `0security scan --format json` output or a SARIF 2.1.0 file.");
  return document.findings.filter(isObject).map(raw => {
    const location = isObject(raw.location) ? raw.location : {};
    const evidence = isObject(raw.evidence) ? raw.evidence : {};
    const impact = isObject(raw.impact) ? raw.impact : {};
    const fix = isObject(raw.suggestedFix) ? str(raw.suggestedFix.replacement) : "";
    const analysis = str(evidence.analysis);
    const path = normalizePath(str(location.path));
    const confidence = typeof raw.confidence === "number" ? `, confidence ${Math.round(raw.confidence * 100)}%` : "";
    const verdict = str(raw.status) ? `${str(raw.status)}${confidence}` : "";
    const rationale = str(impact.rationale) || withoutTag(analysis);
    const cwe = cweOf(analysis) ?? cweOf(str(raw.description));
    return {
      ruleId: str(raw.category) || "finding", severity: level(raw.severity), title: str(raw.title) || str(raw.category) || "Finding",
      ...(path ? { path } : {}), line: typeof location.startLine === "number" && location.startLine > 0 ? Math.floor(location.startLine) : 0,
      ...(cwe ? { cwe } : {}), description: str(raw.description),
      ...(verdict ? { verdict } : {}), ...(rationale ? { rationale } : {}), ...(fix ? { fix: `Suggested replacement:\n${fix}` } : {}),
    };
  });
}

/** One finding per (path, line, CWE), the most severe; the rule id stands in when there is no CWE. First occurrence keeps its place. */
export function dedupeFindings(findings: readonly InsightFinding[]): InsightFinding[] {
  const kept = new Map<string, InsightFinding>();
  for (const finding of findings) {
    const key = `${finding.path ?? ""}\0${finding.line}\0${finding.cwe ?? `rule:${finding.ruleId}`}`;
    const current = kept.get(key);
    if (!current || SEVERITY_RANK[finding.severity]! > SEVERITY_RANK[current.severity]!) kept.set(key, finding);
  }
  return [...kept.values()];
}

/** Bitbucket Cloud has no INFO and Data Center has neither INFO nor CRITICAL. */
export function mapSeverity(platform: CodeInsightsPlatform, severity: Level): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" {
  switch (severity) {
    case "critical": return platform === "bitbucket-cloud" ? "CRITICAL" : "HIGH";
    case "high": return "HIGH";
    case "medium": return "MEDIUM";
    default: return "LOW";
  }
}

const truncate = (text: string, max: number): string => (text.length <= max ? text : `${text.slice(0, Math.max(0, max - 3))}...`);
const externalId = (finding: InsightFinding): string => `0-${createHash("sha256").update(`${finding.ruleId}\0${finding.path ?? ""}\0${finding.line}\0${finding.cwe ?? ""}`).digest("hex").slice(0, 24)}`;

function detailText(finding: InsightFinding): string {
  const lines = [`Rule: ${finding.ruleId}`];
  if (finding.cwe) lines.push(`CWE: ${finding.cwe}`);
  if (finding.verdict) lines.push(`Verdict: ${finding.verdict}`);
  if (finding.description) lines.push("", finding.description);
  if (finding.rationale && finding.rationale !== finding.description) lines.push("", `Rationale: ${finding.rationale}`);
  if (finding.fix) lines.push("", `Fix: ${finding.fix}`);
  return lines.join("\n");
}

function annotation(platform: CodeInsightsPlatform, finding: InsightFinding): Json {
  const head = `[${finding.ruleId}${finding.cwe ? `, ${finding.cwe}` : ""}] ${finding.title}`;
  const location = finding.path ? { path: finding.path, line: finding.line } : {};
  if (platform === "bitbucket-cloud") {
    return {
      external_id: externalId(finding), annotation_type: "VULNERABILITY", severity: mapSeverity(platform, finding.severity),
      ...(finding.path ? { path: finding.path, line: Math.max(1, finding.line) } : {}),
      title: truncate(finding.title, 450), summary: truncate(head, CLOUD_SUMMARY_MAX), details: truncate(detailText(finding), TEXT_MAX),
    };
  }
  // Data Center has one `message` field (2000 characters): the verdict and the fix go in it, after the heading.
  return { externalId: externalId(finding), type: "VULNERABILITY", severity: mapSeverity(platform, finding.severity), ...location, message: truncate(`${head}\n${detailText(finding)}`, TEXT_MAX) };
}

export interface CodeInsightsPayload {
  platform: CodeInsightsPlatform;
  reportId: string;
  /** Body of the report PUT. */
  report: Json;
  /** Bodies of the annotation POSTs: arrays for Cloud, `{ annotations }` objects for Data Center. */
  batches: unknown[];
  total: number;
  emitted: number;
  /** Unique findings that did not fit the 1000-annotation cap (the least severe ones). */
  dropped: number;
}

export function buildCodeInsights(findings: readonly InsightFinding[], platform: CodeInsightsPlatform, options: { reportId?: string } = {}): CodeInsightsPayload {
  const unique = dedupeFindings(findings);
  // Stable sort: most severe first, so the cap drops the least severe.
  const ranked = unique.map((finding, index) => ({ finding, index })).sort((a, b) => SEVERITY_RANK[b.finding.severity]! - SEVERITY_RANK[a.finding.severity]! || a.index - b.index).map(entry => entry.finding);
  const total = ranked.length;
  const kept = ranked.slice(0, MAX_ANNOTATIONS);
  const dropped = total - kept.length;
  const count = (...levels: Level[]) => ranked.filter(finding => levels.includes(finding.severity)).length;

  const cloud = platform === "bitbucket-cloud";
  const number = (title: string, value: number) => ({ title, type: "NUMBER", value });
  const data = cloud
    ? [number("Findings", total), number("Critical", count("critical")), number("High", count("high")), number("Medium", count("medium")), number("Low", count("low", "info")), ...(dropped ? [number("Not annotated (cap)", dropped)] : [])]
    // Data Center allows 6 data items and has no CRITICAL.
    : [number("Findings", total), number("High or critical", count("high", "critical")), number("Medium", count("medium")), number("Low", count("low", "info")), ...(dropped ? [number("Not annotated (cap)", dropped)] : [])];
  const details = `${total ? `${total} triaged finding${total === 1 ? "" : "s"} after deduplicating by file, line and CWE.` : "No findings."}${dropped ? ` ${dropped} less severe finding${dropped === 1 ? "" : "s"} exceeded the ${MAX_ANNOTATIONS}-annotation limit and ${dropped === 1 ? "is" : "are"} not annotated.` : ""}`;
  const report: Json = {
    title: "0 security scan", details, reporter: "0", data,
    result: cloud ? (total ? "FAILED" : "PASSED") : (total ? "FAIL" : "PASS"),
    ...(cloud ? { report_type: "SECURITY" } : {}),
  };

  const annotations = kept.map(finding => annotation(platform, finding));
  const size = cloud ? CLOUD_BATCH_SIZE : DC_BATCH_SIZE;
  const batches: unknown[] = [];
  for (let start = 0; start < annotations.length; start += size) {
    const chunk = annotations.slice(start, start + size);
    batches.push(cloud ? chunk : { annotations: chunk });
  }
  return { platform, reportId: options.reportId ?? DEFAULT_REPORT_ID, report, batches, total, emitted: annotations.length, dropped };
}

export interface CodeInsightsTarget {
  /** Cloud: workspace and repository slug. Data Center: project key and repository slug. */
  owner: string;
  repo: string;
  commit: string;
  /** Data Center base URL, for example https://bitbucket.example.com (a context path is kept). */
  baseUrl?: string;
  /** Cloud API root, default https://api.bitbucket.org/2.0. Only for a proxy or a test server. */
  cloudApiUrl?: string;
}

export type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body: string; redirect: "manual" }) => Promise<{ ok: boolean; status: number; text(): Promise<string> }>;

/** The requests that publish the payload, in order, without the token. */
export function planRequests(payload: CodeInsightsPayload, target: CodeInsightsTarget): Array<{ method: "PUT" | "POST"; url: string; body: unknown }> {
  const part = (value: string) => encodeURIComponent(value);
  let base: string;
  if (payload.platform === "bitbucket-cloud") base = `${(target.cloudApiUrl ?? "https://api.bitbucket.org/2.0").replace(/\/+$/, "")}/repositories/${part(target.owner)}/${part(target.repo)}/commit/${part(target.commit)}/reports/${part(payload.reportId)}`;
  else {
    if (!target.baseUrl) throw new Error("Data Center needs the server's base URL (--url or BITBUCKET_URL).");
    base = `${target.baseUrl.replace(/\/+$/, "")}/rest/insights/latest/projects/${part(target.owner)}/repos/${part(target.repo)}/commits/${part(target.commit)}/reports/${part(payload.reportId)}`;
  }
  return [{ method: "PUT", url: base, body: payload.report }, ...payload.batches.map(body => ({ method: "POST" as const, url: `${base}/annotations`, body }))];
}

/** Send the report, then its annotation batches. The token goes only in the Authorization header and never into a message. */
export async function postCodeInsights(payload: CodeInsightsPayload, target: CodeInsightsTarget, token: string, fetcher: FetchLike): Promise<{ requests: number }> {
  const requests = planRequests(payload, target);
  for (const request of requests) {
    let response;
    try {
      response = await fetcher(request.url, { method: request.method, headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", Accept: "application/json" }, body: JSON.stringify(request.body), redirect: "manual" });
    } catch (error) {
      throw new Error(`${request.method} ${new URL(request.url).pathname} failed: ${(error instanceof Error ? error.message : String(error)).split(token).join("***")}`);
    }
    if (!response.ok) {
      const body = (await response.text().catch(() => "")).split(token).join("***").replace(/\s+/g, " ").slice(0, 300);
      throw new Error(`Bitbucket answered ${response.status} to ${request.method} ${new URL(request.url).pathname}${body ? `: ${body}` : ""}`);
    }
  }
  return { requests: requests.length };
}
