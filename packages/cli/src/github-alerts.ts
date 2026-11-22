// Auth: every request goes through `gh api` (GithubAlertsDeps.gh) with the user's own
// `gh auth login` session. The 0 GitHub extension connector is neither used nor declared
// for this; its approval prompt and token handling do not apply here.
import { createHash } from "node:crypto";
import { osecDB, recordAudit, resolveOsecDbPath, type AuditInput } from "@0/engine/storage";
import {
  CWE_CATEGORY,
  cweNumbers,
  type AttackCategory,
  type Finding,
  type ScanReport,
  type Severity,
} from "@0/engine/shared";
import { UsageError } from "./commands/output.js";
import { audit } from "./web/audit.js";

const REPO_PATTERN = /^(?!\.{1,2}\/)[A-Za-z0-9_.-]{1,100}\/(?!\.{1,2}$)[A-Za-z0-9_.-]{1,100}$/;
const severities = ["critical", "high", "medium", "low", "info"] as const;

export type GithubAlertKind = "code-scanning" | "dependabot" | "secret-scanning";
export type GithubAlertState = "open" | "dismissed" | "fixed" | "all";

export interface GithubCodeScanningAlert {
  number: number;
  created_at?: string;
  url?: string;
  html_url: string;
  state: "open" | "dismissed" | "fixed" | (string & {});
  dismissed_reason?: string | null;
  rule: {
    id: string;
    name?: string;
    severity?: string | null;
    security_severity_level?: string | null;
    description?: string;
    tags?: string[];
  };
  tool?: {
    name: string;
    guid?: string | null;
    version?: string | null;
  };
  most_recent_instance?: {
    ref?: string;
    analysis_key?: string;
    environment?: string;
    category?: string;
    state?: string;
    commit_sha?: string;
    message?: {
      text?: string;
    };
    location?: {
      path?: string;
      start_line?: number;
      end_line?: number;
      start_column?: number;
      end_column?: number;
    };
    classifications?: string[];
  };
}

export interface GithubDependabotAlert {
  number: number;
  state: "auto_dismissed" | "dismissed" | "fixed" | "open" | (string & {});
  dismissed_reason?: string | null;
  dependency: {
    package: {
      ecosystem?: string;
      name: string;
    };
    manifest_path?: string;
    scope?: string;
  };
  security_advisory: {
    ghsa_id: string;
    cve_id?: string | null;
    summary: string;
    description?: string;
    severity: "low" | "medium" | "high" | "critical" | (string & {});
    cvss?: {
      score?: number;
      vector_string?: string | null;
    };
    cwes?: Array<{
      cwe_id: string;
      name?: string;
    }>;
  };
  security_vulnerability?: {
    package?: {
      ecosystem?: string;
      name: string;
    };
    severity?: string;
    vulnerable_version_range?: string;
    first_patched_version?: {
      identifier?: string;
    } | null;
  };
  url?: string;
  html_url: string;
  created_at?: string;
}

export interface GithubSecretScanningAlert {
  number: number;
  created_at?: string;
  updated_at?: string;
  url?: string;
  html_url: string;
  locations_url?: string;
  state: "open" | "resolved" | (string & {});
  resolution?: string | null;
  secret_type: string;
  secret_type_display_name?: string;
  validity?: "active" | "inactive" | "unknown" | (string & {});
  locations?: Array<{
    type?: string;
    details?: {
      path?: string;
      start_line?: number;
      end_line?: number;
      start_column?: number;
      end_column?: number;
      blob_sha?: string;
    };
  }>;
}

export interface FetchedGithubAlerts {
  codeScanning: GithubCodeScanningAlert[];
  dependabot: GithubDependabotAlert[];
  secretScanning: GithubSecretScanningAlert[];
  warnings: AlertWarning[];
  /** A fetch failed part-way: the imported set is partial. */
  failed: boolean;
  /** The set is partial, because a fetch failed or the page cap was hit. */
  incomplete: boolean;
}

export interface AlertWarning {
  stage: string;
  kind: "unavailable" | "failed" | "truncated" | "locations";
  message: string;
}

export interface GithubAlertsDeps {
  gh(args: string[], input?: string): Promise<string>;
}

export interface FetchGithubAlertsOptions {
  repo: string;
  state?: GithubAlertState;
  types?: GithubAlertKind[];
  ref?: string;
  tool?: string;
}

export interface ImportGithubAlertsOptions extends FetchGithubAlertsOptions {
  dbPath: string;
  now?: Date;
}

export interface GithubAlertsImportResult {
  scanId: string;
  findings: number;
  alreadyImported: boolean;
  dbPath: string;
  warnings: AlertWarning[];
  incomplete: boolean;
  failed: boolean;
}

function canonical(value: unknown, depth = 0): string {
  if (depth > 64) throw new Error("Report JSON nesting exceeds the limit.");
  if (Array.isArray(value)) return `[${value.map(item => canonical(item, depth + 1)).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => `${JSON.stringify(key)}:${canonical(item, depth + 1)}`).join(",")}}`;
  }
  if (typeof value === "number" && !Number.isFinite(value)) throw new Error("Report JSON contains a nonfinite number.");
  return JSON.stringify(value);
}

function hash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

/**
 * Alert text comes from third-party scanners and rule authors. Remove control
 * characters (terminal escapes, NUL, bidi overrides) and bound the length
 * before it reaches a finding. Newlines and tabs survive unless `oneLine`.
 */
export function cleanAlertText(value: unknown, max: number, oneLine = false): string {
  if (typeof value !== "string") return "";
  // eslint-disable-next-line no-control-regex
  let text = value.replace(oneLine ? /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]+/g : /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, oneLine ? " " : "");
  if (oneLine) text = text.replace(/ {2,}/g, " ").trim();
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

const TITLE_MAX = 200;
const TEXT_MAX = 2000;
const FIELD_MAX = 500;
const line = (v: unknown, max = FIELD_MAX) => cleanAlertText(v, max, true);

export function parseAlertKinds(raw?: string): GithubAlertKind[] {
  if (!raw || raw.trim() === "" || raw === "all") {
    return ["code-scanning", "dependabot", "secret-scanning"];
  }
  const parts = raw.split(",").map(part => part.trim().toLowerCase());
  const kinds = new Set<GithubAlertKind>();
  for (const part of parts) {
    if (part === "all") {
      return ["code-scanning", "dependabot", "secret-scanning"];
    }
    if (part === "code-scanning" || part === "dependabot" || part === "secret-scanning") {
      kinds.add(part);
    } else {
      throw new UsageError(`Unknown alert kind "${part}". Use code-scanning, dependabot, secret-scanning, or all.`);
    }
  }
  return [...kinds];
}

export function detectCategoryFromRule(ruleId: string, tags?: string[]): AttackCategory {
  const cwes = cweNumbers(tags ?? []);
  for (const cwe of cwes) {
    const match = CWE_CATEGORY[cwe];
    if (match) return match;
  }
  const lower = ruleId.toLowerCase();
  if (lower.includes("sql")) return "sql-injection";
  if (lower.includes("xss")) return "xss";
  if (lower.includes("path") || lower.includes("traversal")) return "path-traversal";
  if (lower.includes("command") || lower.includes("exec")) return "command-injection";
  if (lower.includes("code") || lower.includes("eval")) return "code-injection";
  if (lower.includes("ssrf")) return "ssrf";
  if (lower.includes("crypto") || lower.includes("cipher") || lower.includes("hash")) return "crypto-misuse";
  if (lower.includes("deserial")) return "unsafe-deserialization";
  if (lower.includes("regex") || lower.includes("dos")) return "regex-dos";
  if (lower.includes("pollution")) return "prototype-pollution";
  if (lower.includes("disclosure") || lower.includes("secret") || lower.includes("leak") || lower.includes("credential")) {
    return "information-disclosure";
  }
  if (lower.includes("overflow") || lower.includes("oob")) return "stack-buffer-overflow";
  if (lower.includes("cors")) return "cors";
  return "security-misconfiguration";
}

export function detectSeverityFromRule(securitySeverityLevel?: string | null, ruleSeverity?: string | null): Severity {
  if (securitySeverityLevel) {
    const lower = securitySeverityLevel.toLowerCase();
    if (lower === "critical" || lower === "high" || lower === "medium" || lower === "low") return lower;
  }
  if (ruleSeverity) {
    const lower = ruleSeverity.toLowerCase();
    if (lower === "error") return "high";
    if (lower === "warning") return "medium";
    if (lower === "note") return "low";
    if (lower === "none") return "info";
  }
  return "medium";
}

export function detectCategoryFromAdvisory(cwes?: Array<{ cwe_id?: string }>): AttackCategory {
  if (cwes) {
    const nums = cweNumbers(cwes.map(c => c.cwe_id ?? ""));
    for (const n of nums) {
      const match = CWE_CATEGORY[n];
      if (match) return match;
    }
  }
  return "known-vulnerable-package";
}

function isAuthError(msg: string): boolean {
  return /auth login|authentication|not logged in|unauthorized|bad credentials/i.test(msg);
}

/** Pages fetched per endpoint; more than this is reported as truncated, never silently dropped. */
export const MAX_PAGES = 20;
/** Secret scanning alerts whose location is looked up (one request each). */
export const MAX_LOCATION_LOOKUPS = 50;
const UNAVAILABLE = /404|403|not found|not enabled|disabled|forbidden|advanced security|must be enabled/i;

type FetchOutcome<T> = {
  items: T[];
  /** The endpoint is off or not permitted for this repository: expected, not a failed fetch. */
  unavailable?: string;
  /** A request or its JSON failed after the endpoint was reached: the set is not complete. */
  failed?: string;
  /** The page cap was reached while more pages may exist. */
  truncated?: string;
};

async function fetchEndpointPages<T>(
  repo: string,
  subpath: string,
  params: Record<string, string>,
  deps: GithubAlertsDeps,
  extraArgs: string[] = [],
): Promise<FetchOutcome<T>> {
  const items: T[] = [];
  const perPage = 100;

  for (let page = 1; page <= MAX_PAGES; page++) {
    const query = new URLSearchParams({ ...params, per_page: String(perPage), page: String(page) }).toString();
    const endpoint = `repos/${repo}/${subpath}?${query}`;
    let stdout: string;
    try {
      stdout = await deps.gh(["api", endpoint, ...extraArgs]);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (isAuthError(msg)) throw new Error(`GitHub authentication required: ${msg}`);
      if (page === 1 && UNAVAILABLE.test(msg)) return { items, unavailable: msg };
      return { items, failed: page === 1 ? msg : `page ${page} failed after ${items.length} alerts: ${msg}` };
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(stdout.trim());
    } catch {
      return { items, failed: `page ${page} was not valid JSON (${items.length} alerts read before it)` };
    }
    if (!Array.isArray(parsed)) {
      return { items, failed: `page ${page} was not a list (${items.length} alerts read before it)` };
    }
    items.push(...(parsed as T[]));
    if (parsed.length < perPage) return { items };
  }
  return { items, truncated: `stopped after ${MAX_PAGES} pages (${items.length} alerts); more may exist` };
}

/** Whitelist only: the list endpoint returns the secret itself, which must never be read or stored. */
function pickSecretAlert(raw: GithubSecretScanningAlert): GithubSecretScanningAlert {
  const { number, created_at, updated_at, url, html_url, state, resolution, secret_type, secret_type_display_name, validity } = raw;
  return { number, created_at, updated_at, url, html_url, state, resolution, secret_type, secret_type_display_name, validity };
}

// gh filters with jq before the output reaches this process, so the secret value is never read.
const SECRET_LIST_JQ =
  "map({number,created_at,updated_at,url,html_url,state,resolution,secret_type,secret_type_display_name,validity})";
const SECRET_LOCATION_JQ =
  "map({type,details:{path:.details.path,start_line:.details.start_line,end_line:.details.end_line}})";

async function attachSecretLocations(
  repo: string,
  alerts: GithubSecretScanningAlert[],
  deps: GithubAlertsDeps,
): Promise<string | undefined> {
  const lookups = alerts.slice(0, MAX_LOCATION_LOOKUPS);
  let failures = 0;
  for (const alert of lookups) {
    if (!Number.isInteger(alert.number) || alert.number < 0) { failures++; continue; }
    try {
      // The URL is built here, not taken from the response; only path and lines are kept.
      const out = await deps.gh([
        "api", `repos/${repo}/secret-scanning/alerts/${alert.number}/locations?per_page=1`,
        "--jq", SECRET_LOCATION_JQ,
      ]);
      const parsed: unknown = JSON.parse(out.trim());
      const first = Array.isArray(parsed) ? parsed[0] : undefined;
      const d = first && typeof first === "object" ? (first as { details?: Record<string, unknown> }).details : undefined;
      if (d && typeof d.path === "string") {
        alert.locations = [{
          details: {
            path: d.path,
            ...(typeof d.start_line === "number" ? { start_line: d.start_line } : {}),
            ...(typeof d.end_line === "number" ? { end_line: d.end_line } : {}),
          },
        }];
      }
    } catch {
      failures++;
    }
  }
  const skipped = Math.max(0, alerts.length - lookups.length);
  if (!failures && !skipped) return undefined;
  const parts: string[] = [];
  if (failures) parts.push(`${failures} location lookup${failures === 1 ? "" : "s"} failed`);
  if (skipped) parts.push(`${skipped} alert${skipped === 1 ? "" : "s"} beyond the first ${MAX_LOCATION_LOOKUPS} have no location`);
  return `${parts.join("; ")}; those findings carry no file or line`;
}

export async function fetchGithubAlerts(
  options: FetchGithubAlertsOptions,
  deps: GithubAlertsDeps,
): Promise<FetchedGithubAlerts> {
  const repo = options.repo.trim();
  if (!REPO_PATTERN.test(repo)) {
    throw new UsageError(`Invalid repository name "${repo}". Expected format: owner/repo.`);
  }

  const state = options.state ?? "open";
  if (!["open", "dismissed", "fixed", "all"].includes(state)) {
    throw new UsageError(`Unknown alert state "${state}". Use one of: open, dismissed, fixed, all.`);
  }

  const types = options.types ?? ["code-scanning", "dependabot", "secret-scanning"];
  const warnings: AlertWarning[] = [];
  let unavailableCount = 0;

  /** Records the outcome's problems; returns the items to keep (partial sets are kept and flagged). */
  const settle = <T>(stage: string, outcome: FetchOutcome<T>): T[] => {
    if (outcome.unavailable) {
      if (types.length === 1) throw new Error(`Failed to fetch ${stage} alerts for ${repo}: ${outcome.unavailable}`);
      unavailableCount++;
      warnings.push({ stage, kind: "unavailable", message: outcome.unavailable });
      return [];
    }
    if (outcome.failed) {
      if (!outcome.items.length && types.length === 1) throw new Error(`Failed to fetch ${stage} alerts for ${repo}: ${outcome.failed}`);
      warnings.push({ stage, kind: "failed", message: `${outcome.failed}; ${outcome.items.length} alerts imported, the set is incomplete` });
    }
    if (outcome.truncated) warnings.push({ stage, kind: "truncated", message: `${outcome.truncated}; the set is incomplete` });
    return outcome.items;
  };

  let codeScanning: GithubCodeScanningAlert[] = [];
  let dependabot: GithubDependabotAlert[] = [];
  let secretScanning: GithubSecretScanningAlert[] = [];

  for (const type of types) {
    if (type === "code-scanning") {
      const params: Record<string, string> = {};
      if (state !== "all") params.state = state;
      if (options.ref) params.ref = options.ref;
      if (options.tool) params.tool_name = options.tool;
      codeScanning = settle("code-scanning", await fetchEndpointPages<GithubCodeScanningAlert>(repo, "code-scanning/alerts", params, deps));
    } else if (type === "dependabot") {
      const params: Record<string, string> = {};
      if (state === "open") params.state = "open";
      else if (state === "dismissed") params.state = "dismissed,auto_dismissed";
      else if (state === "fixed") params.state = "fixed";
      dependabot = settle("dependabot", await fetchEndpointPages<GithubDependabotAlert>(repo, "dependabot/alerts", params, deps));
    } else if (type === "secret-scanning") {
      const params: Record<string, string> = {};
      if (state === "open") params.state = "open";
      else if (state === "dismissed" || state === "fixed") params.state = "resolved";
      const raw = settle("secret-scanning", await fetchEndpointPages<GithubSecretScanningAlert>(repo, "secret-scanning/alerts", params, deps, ["--jq", SECRET_LIST_JQ]));
      secretScanning = raw.map(pickSecretAlert);
      if (secretScanning.length) {
        const note = await attachSecretLocations(repo, secretScanning, deps);
        if (note) warnings.push({ stage: "secret-scanning", kind: "locations", message: note });
      }
    }
  }

  if (unavailableCount === types.length && codeScanning.length === 0 && dependabot.length === 0 && secretScanning.length === 0) {
    throw new Error(`Failed to fetch GitHub security alerts for ${repo}: ${warnings.map(w => w.message).join("; ")}`);
  }

  return {
    codeScanning, dependabot, secretScanning, warnings,
    failed: warnings.some(w => w.kind === "failed"),
    incomplete: warnings.some(w => w.kind === "failed" || w.kind === "truncated"),
  };
}

export function mapGithubAlertsToFindings(
  alerts: FetchedGithubAlerts,
  scanId: string,
  now: Date,
  toolOverride?: string,
): Finding[] {
  const timestamp = now.getTime();
  const findings: Finding[] = [];
  const seenIds = new Set<string>();

  // 1. Code scanning alerts
  for (const alert of alerts.codeScanning) {
    const tool = line(toolOverride ?? alert.tool?.name ?? "code-scanning", 100) || "code-scanning";
    const templateId = `${tool}/${line(alert.rule.id, 200)}`;
    const messageText = cleanAlertText(alert.most_recent_instance?.message?.text, TEXT_MAX);
    const ruleText = cleanAlertText(alert.rule.description, TEXT_MAX);
    const category = detectCategoryFromRule(alert.rule.id, alert.rule.tags);
    const severity = detectSeverityFromRule(alert.rule.security_severity_level, alert.rule.severity);
    const loc = alert.most_recent_instance?.location;
    const path = line(loc?.path) || undefined;
    const startLine = loc?.start_line;
    const endLine = loc?.end_line;
    const where = path ? `${path}${startLine ? `:${startLine}` : ""}` : "repository";

    const findingKey = hash(`code-scanning:${alert.number}:${alert.rule.id}:${path ?? ""}`);
    let id = `${scanId}-${findingKey}`;
    if (seenIds.has(id)) id = `${id}-${alert.number}`;
    seenIds.add(id);

    findings.push({
      id,
      fingerprint: `${scanId}:${findingKey}`,
      templateId,
      title: line(alert.rule.description || alert.rule.name || alert.rule.id, TITLE_MAX),
      description: messageText || ruleText || line(alert.rule.id, 200),
      category,
      severity,
      tool,
      evidence: {
        request: where,
        response: cleanAlertText(messageText || alert.state, 1000),
        analysis: `Imported from GitHub Code Scanning (${line(alert.html_url)}). Alert #${alert.number}, state: ${line(alert.state, 50)}. Tool: ${line(alert.tool?.name) || "unknown"}${alert.tool?.version ? ` ${line(alert.tool.version, 50)}` : ""}.`,
      },
      ...(path && startLine ? { reviewAnnotation: { path, startLine, ...(endLine && endLine >= startLine ? { endLine } : {}) } } : {}),
      timestamp: alert.created_at ? Date.parse(alert.created_at) || timestamp : timestamp,
      status: "discovered",
      triageStatus: alert.state === "dismissed" ? "suppressed" : "new",
      workflowStatus: "backlog",
    });
  }

  // 2. Dependabot alerts
  for (const alert of alerts.dependabot) {
    const tool = line(toolOverride ?? "dependabot", 100) || "dependabot";
    const templateId = line(alert.security_advisory.ghsa_id) || `dependabot/${line(alert.dependency.package.name)}`;
    const category = detectCategoryFromAdvisory(alert.security_advisory.cwes);
    const advisorySev = alert.security_advisory.severity?.toLowerCase();
    const severity: Severity = severities.includes(advisorySev as Severity) ? (advisorySev as Severity) : "medium";
    const manifestPath = line(alert.dependency.manifest_path) || undefined;
    const pkg = line(alert.dependency.package.name);
    const ecosystem = line(alert.dependency.package.ecosystem, 50) || "package";

    const findingKey = hash(`dependabot:${alert.number}:${alert.security_advisory.ghsa_id}:${pkg}`);
    let id = `${scanId}-${findingKey}`;
    if (seenIds.has(id)) id = `${id}-${alert.number}`;
    seenIds.add(id);

    const cve = line(alert.security_advisory.cve_id, 50);
    const cwes = alert.security_advisory.cwes?.map(c => line(c.cwe_id, 30)).join(", ");

    findings.push({
      id,
      fingerprint: `${scanId}:${findingKey}`,
      templateId,
      title: line(alert.security_advisory.summary, TITLE_MAX) || `${pkg} vulnerability`,
      description: cleanAlertText(alert.security_advisory.description || alert.security_advisory.summary, TEXT_MAX),
      category,
      severity,
      tool,
      evidence: {
        request: `${manifestPath ?? "manifest"}: ${pkg} (${ecosystem})`,
        response: `Vulnerable range: ${line(alert.security_vulnerability?.vulnerable_version_range, 100) || "unknown"}. Patched version: ${line(alert.security_vulnerability?.first_patched_version?.identifier, 100) || "none"}.`,
        analysis: `Imported from GitHub Dependabot (${line(alert.html_url)}). Alert #${alert.number}, state: ${line(alert.state, 50)}.${cve ? ` CVE: ${cve}.` : ""}${cwes ? ` CWEs: ${cwes}.` : ""}`,
      },
      ...(manifestPath ? { reviewAnnotation: { path: manifestPath, startLine: 1 } } : {}),
      ...(alert.security_advisory.cvss?.score != null ? { cvssScore: alert.security_advisory.cvss.score } : {}),
      ...(alert.security_advisory.cvss?.vector_string ? { cvssVector: alert.security_advisory.cvss.vector_string } : {}),
      timestamp: alert.created_at ? Date.parse(alert.created_at) || timestamp : timestamp,
      status: "discovered",
      triageStatus: alert.state === "dismissed" || alert.state === "auto_dismissed" ? "suppressed" : "new",
      workflowStatus: "backlog",
    });
  }

  // 3. Secret scanning alerts
  for (const alert of alerts.secretScanning) {
    const tool = line(toolOverride ?? "secret-scanning", 100) || "secret-scanning";
    const templateId = `secret-scanning/${line(alert.secret_type, 100)}`;
    const category: AttackCategory = "information-disclosure";
    const severity: Severity = alert.validity === "active" ? "critical" : "high";
    const displayName = line(alert.secret_type_display_name || alert.secret_type, 100);

    const loc = alert.locations?.[0]?.details;
    const path = line(loc?.path) || undefined;
    const startLine = loc?.start_line;
    const endLine = loc?.end_line;

    const findingKey = hash(`secret-scanning:${alert.number}:${alert.secret_type}`);
    let id = `${scanId}-${findingKey}`;
    if (seenIds.has(id)) id = `${id}-${alert.number}`;
    seenIds.add(id);

    findings.push({
      id,
      fingerprint: `${scanId}:${findingKey}`,
      templateId,
      title: `${displayName} exposed`,
      description: `GitHub Secret Scanning detected a potential secret of type ${displayName} (alert #${alert.number}).`,
      category,
      severity,
      tool,
      evidence: {
        request: displayName,
        response: `Validity: ${line(alert.validity, 50) || "unknown"}. State: ${line(alert.state, 50)}.${alert.resolution ? ` Resolution: ${line(alert.resolution, 100)}.` : ""}`,
        analysis: `Imported from GitHub Secret Scanning (${line(alert.html_url)}). Alert #${alert.number}, state: ${line(alert.state, 50)}.${path ? "" : " No location was available."}`,
      },
      ...(path && startLine ? { reviewAnnotation: { path, startLine, ...(endLine && endLine >= startLine ? { endLine } : {}) } } : {}),
      timestamp: alert.created_at ? Date.parse(alert.created_at) || timestamp : timestamp,
      status: "discovered",
      triageStatus: alert.state === "resolved" ? "suppressed" : "new",
      workflowStatus: "backlog",
    });
  }

  return findings;
}

export function prepareGithubAlertsImport(
  repo: string,
  alerts: FetchedGithubAlerts,
  options: { state?: GithubAlertState; types?: GithubAlertKind[]; ref?: string; tool?: string; now?: Date } = {},
): Parameters<osecDB["importCiReport"]>[0] {
  const now = options.now ?? new Date();
  const importedAt = now.toISOString();
  const selectedTypes = options.types ?? ["code-scanning", "dependabot", "secret-scanning"];
  const target = `github:${repo}`;

  const payload = {
    repo,
    state: options.state ?? "open",
    types: selectedTypes,
    ref: options.ref ?? null,
    tool: options.tool ?? null,
    codeScanningCount: alerts.codeScanning.length,
    dependabotCount: alerts.dependabot.length,
    secretScanningCount: alerts.secretScanning.length,
    complete: !alerts.incomplete,
    // `content` hashes the whole alert (updated_at, text, location, state), so an
    // alert that changed on GitHub gets a new digest and imports again as updated.
    codeScanning: alerts.codeScanning.map(a => ({ number: a.number, state: a.state, rule: a.rule?.id, content: hash(canonical(a)) })),
    dependabot: alerts.dependabot.map(a => ({ number: a.number, state: a.state, ghsa: a.security_advisory?.ghsa_id, content: hash(canonical(a)) })),
    secretScanning: alerts.secretScanning.map(a => ({ number: a.number, state: a.state, type: a.secret_type, content: hash(canonical(a)) })),
  };

  const digest = hash(canonical(payload));
  const scanId = `ci-${digest}`;
  const findings = mapGithubAlertsToFindings(alerts, scanId, now, options.tool);

  const report = {
    target,
    scanDepth: "default",
    startedAt: importedAt,
    completedAt: importedAt,
    durationMs: 0,
    findings: [],
    warnings: alerts.warnings,
  } as unknown as ScanReport;

  const provenance = {
    schemaVersion: 1,
    source: "github-alerts",
    trust: "unverified",
    sourceExecutionStatus: "unknown",
    digest,
    importedAt,
    repository: repo,
    ref: options.ref ?? null,
    state: options.state ?? "open",
    types: selectedTypes,
    complete: !alerts.incomplete,
    ...(alerts.warnings.length ? { warnings: alerts.warnings } : {}),
    metadata: null,
  };

  return {
    scanId,
    report,
    findings,
    status: "completed",
    provenance,
    summary: {
      totalAttacks: 0,
      totalFindings: findings.length,
      ...Object.fromEntries(severities.map(severity => [severity, findings.filter(f => f.severity === severity).length])),
      executionSuccessful: !alerts.incomplete,
      exitReason: alerts.incomplete ? "partial-fetch" : "completed",
    },
  };
}

export async function importGithubAlerts(
  options: ImportGithubAlertsOptions,
  deps: GithubAlertsDeps,
): Promise<GithubAlertsImportResult> {
  const dbPath = resolveOsecDbPath(options.dbPath);
  if (!dbPath) throw new UsageError("An explicit destination database path is required.");

  const alerts = await fetchGithubAlerts(options, deps);
  const input = prepareGithubAlertsImport(options.repo, alerts, options);

  const db = new osecDB(dbPath);
  let result: { scanId: string; alreadyImported: boolean };
  try {
    result = db.importCiReport(input);
  } finally {
    db.close();
  }

  const selectedTypes = options.types ?? ["code-scanning", "dependabot", "secret-scanning"];
  const auditEvent: AuditInput = {
    actor: "cli",
    action: "findings.import.github",
    subject: options.repo,
    outcome: "ok",
    detail: {
      id: result.scanId,
      count: input.findings.length,
      repo: options.repo,
      kind: selectedTypes.join(","),
      status: result.alreadyImported ? "already_imported" : "imported",
      ...(alerts.incomplete ? { complete: false } : {}),
    },
  };

  try {
    recordAudit(auditEvent, { dbPath });
  } catch {
    /* Audit recording should not block import completion */
  }

  try {
    audit(auditEvent);
  } catch {
    /* Optional runtime audit */
  }

  return {
    scanId: result.scanId,
    findings: input.findings.length,
    alreadyImported: result.alreadyImported,
    dbPath,
    warnings: alerts.warnings,
    incomplete: alerts.incomplete,
    failed: alerts.failed,
  };
}
