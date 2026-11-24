/**
 * Read findings from a SARIF 2.1.0 log written by another scanner.
 *
 * The input is untrusted text from a file: every string is length-limited and
 * stripped of control characters, locations are repo-relative paths that cannot
 * leave the repository, and nothing in the log is executed or fetched.
 */
import { createHash } from "node:crypto";
import { CWE_CATEGORY } from "./finding-category.js";
import { normalizeAttackCategory } from "./finding-schemas.js";
import type { AttackCategory, Severity } from "./types.js";

export const MAX_SARIF_RESULTS = 5000;
const MAX_RUNS = 20;

export interface ImportedFinding {
  /** Scanner that produced the finding, for example `CodeQL` or `foxguard`. */
  tool: string;
  toolVersion?: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  category: AttackCategory;
  /** Repo-relative path, forward slashes. */
  path?: string;
  startLine?: number;
  endLine?: number;
  snippet?: string;
  /** Stable across runs of the same scanner on the same code. */
  fingerprint: string;
  cwe: string[];
  /** For a web finding: the URL (or route) that was tested, and the HTTP method. Such a finding has no repo path. */
  endpoint?: string;
  method?: string;
  /** Proof or evidence text the scanner gave (a request, a matched value, a proof-of-concept description). Never a runnable exploit. */
  evidence?: string;
  /** Set when the rule came from a file the user supplied (`0 scan --rules`), not from the scanner's own rules. */
  ruleSource?: "custom";
}

export interface SarifImport {
  findings: ImportedFinding[];
  tools: string[];
  repository?: string;
}

type Json = Record<string, unknown>;
const isObject = (value: unknown): value is Json => !!value && typeof value === "object" && !Array.isArray(value);
const list = (value: unknown): unknown[] => Array.isArray(value) ? value : [];
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;
function clean(value: unknown, max: number): string {
  return typeof value === "string" ? value.replace(CONTROL, "").trim().slice(0, max) : "";
}
const positive = (value: unknown): number | undefined => typeof value === "number" && Number.isInteger(value) && value > 0 ? value : undefined;

/** A SARIF artifact URI as a path inside the repository, or undefined when it points anywhere else. */
export function repoRelativePath(uri: unknown, roots: readonly string[] = []): string | undefined {
  let value = clean(uri, 2048);
  if (!value) return undefined;
  value = value.replace(/^file:\/\/(?:localhost)?/i, "");
  try { value = decodeURIComponent(value); } catch { return undefined; }
  value = value.replace(/\\/g, "/").replace(/^\.\//, "");
  // An absolute path is kept only when it is inside a root the caller named (the folder that was scanned).
  for (const root of roots) {
    const base = root.replace(/\\/g, "/").replace(/\/+$/, "");
    if (base && value.startsWith(`${base}/`)) { value = value.slice(base.length + 1); break; }
  }
  if (/^[a-z][a-z0-9+.-]*:/i.test(value) && !/^[a-z]:\//i.test(value)) return undefined;
  if (value.startsWith("/") || /^[a-z]:\//i.test(value)) return undefined;
  const parts = value.split("/").filter(part => part && part !== ".");
  if (!parts.length || parts.includes("..")) return undefined;
  return parts.join("/");
}


export function cweNumbers(...sources: unknown[]): number[] {
  const found = new Set<number>();
  for (const source of sources) {
    for (const entry of list(source)) {
      const match = /cwe[-_/ ]?0*(\d{1,5})\b/i.exec(typeof entry === "string" ? entry : "");
      if (match) found.add(Number(match[1]));
    }
  }
  return [...found];
}

function severityOf(level: unknown, rule: Json | undefined, result: Json): Severity {
  const properties = isObject(rule?.properties) ? rule.properties : {};
  const resultProperties = isObject(result.properties) ? result.properties : {};
  const score = Number(resultProperties["security-severity"] ?? properties["security-severity"]);
  if (Number.isFinite(score) && score > 0) return score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low";
  switch (level) {
    case "error": return "high";
    case "warning": return "medium";
    case "note": return "low";
    case "none": return "info";
    default: return "medium";
  }
}

/** The folder a SARIF base id points at, when it is an absolute file URI. */
function repoUriBase(uri: unknown): string {
  const value = clean(uri, 2048).replace(/^file:\/\/(?:localhost)?/i, "");
  try { const decoded = decodeURIComponent(value); return decoded.startsWith("/") || /^[a-z]:[\\/]/i.test(decoded) ? decoded : ""; } catch { return ""; }
}

const SENSITIVE_PARAM = /token|key|secret|pass|pwd|auth|signature|sig$|session|sid$|cookie|credential|bearer|jwt|otp/i;
const SENSITIVE_HEADER = "authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|x-access-token|x-csrf-token|x-amz-security-token";
/** A long run of URL-safe characters that mixes letters and digits looks like a key or token, whatever the parameter is called. */
const looksLikeSecret = (value: string): boolean => value.length >= 24 && /^[A-Za-z0-9_\-+/=.]+$/.test(value) && /\d/.test(value) && /[A-Za-z]/.test(value);

/** A URL without user name, password or fragment, and with the value of a secret-looking query parameter replaced. */
function redactUrl(raw: string): string {
  try {
    const url = new URL(raw);
    url.username = ""; url.password = ""; url.hash = "";
    for (const [name, value] of [...url.searchParams.entries()]) if (SENSITIVE_PARAM.test(name) || looksLikeSecret(value)) url.searchParams.set(name, "REDACTED");
    return url.href;
  } catch { return raw.replace(/(\b[a-z][a-z0-9+.-]*:\/\/)[^\s'"\/?#@]+@/gi, "$1"); }
}

/**
 * Text with credentials taken out: user names, passwords and secret-looking query values in every URL, the value of curl options
 * and of headers that carry a secret (Authorization, Cookie, Set-Cookie, API keys, tokens). The scanner's own file keeps them;
 * the finding does not.
 */
export function redactEvidence(text: string): string {
  return text
    .replace(/https?:\/\/[^\s'"<>)\]]+/gi, redactUrl)
    .replace(/(\b[a-z][a-z0-9+.-]*:\/\/)[^\s'"\/?#@]+@/gi, "$1")
    .replace(/(\s(?:-u|--user|--oauth2-bearer|--proxy-user)\s+)(?:'[^']*'|"[^"]*"|\S+)/g, "$1[removed]")
    .replace(new RegExp(`("?(?:${SENSITIVE_HEADER})"?\\s*[:=]\\s*)"[^"]*"`, "gi"), '$1"[removed]"')
    .replace(new RegExp(`((?:${SENSITIVE_HEADER})\\s*:\\s*)(?:[^'"\\r\\n]*)`, "gi"), "$1[removed]");
}

/** `clean`, then credentials out. For every text a scanner supplies that ends up in a finding. */
const scrub = (value: unknown, max: number): string => redactEvidence(clean(value, max)).slice(0, max);
const scrubText = (value: unknown, max: number): string => isObject(value) ? scrub(value.text ?? value.markdown, max) : scrub(value, max);

/** An http(s) URL without credentials or a fragment, or undefined when the value is anything else. */
export function safeUrl(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length > 2048) return undefined;
  const text = clean(value, 2048);
  if (!/^https?:\/\//i.test(text)) return undefined;
  try {
    const url = new URL(text);
    if (url.protocol !== "http:" && url.protocol !== "https:") return undefined;
    return redactUrl(url.href).slice(0, 2048);
  } catch { return undefined; }
}

/** A tested endpoint: an http(s) URL, or a route such as /api/users joined to `origin` when that is a URL. */
function endpointOf(value: unknown, origin?: unknown): string | undefined {
  const url = safeUrl(value);
  if (url) return url;
  const route = clean(value, 500);
  if (!route.startsWith("/") || route.startsWith("//") || route.includes("..")) return undefined;
  if (route.includes("?")) { const redacted = new URL(redactUrl(new URL(route, "http://route.invalid").href)); if (!safeUrl(origin)) return `${redacted.pathname}${redacted.search}`; }
  const base = safeUrl(origin);
  if (base) { try { return redactUrl(new URL(route, base).href).slice(0, 2048); } catch { /* use the route alone */ } }
  return route;
}

function methodOf(value: unknown): string | undefined {
  const text = clean(value, 16).toUpperCase();
  return /^[A-Z]{3,10}$/.test(text) ? text : undefined;
}

/** What the importer shows as the place of a finding: file and line, or method and URL, or `no location`. */
export function locationLabel(item: Pick<ImportedFinding, "path" | "startLine" | "endpoint" | "method">): string {
  if (item.path) return `${item.path}${item.startLine ? `:${item.startLine}` : ""}`;
  if (item.endpoint) return `${item.method ? `${item.method} ` : ""}${item.endpoint}`;
  return "no location";
}

const sha = (value: string): string => createHash("sha256").update(value).digest("hex").slice(0, 24);

/** Parse a SARIF log. Throws a short message when the document is not SARIF 2.1.0 or is too large. */
export function parseSarif(text: string, options: { tool?: string; roots?: readonly string[] } = {}): SarifImport {
  let log: unknown;
  try { log = JSON.parse(text); } catch { throw new Error("The file is not valid JSON."); }
  if (!isObject(log) || !Array.isArray(log.runs)) throw new Error("This is not a SARIF log: it has no runs.");
  if (typeof log.version === "string" && !log.version.startsWith("2.1")) throw new Error(`Unsupported SARIF version ${clean(log.version, 16)}; expected 2.1.0.`);
  if (log.runs.length > MAX_RUNS) throw new Error(`The log has more than ${MAX_RUNS} runs.`);

  const findings: ImportedFinding[] = [];
  const tools = new Set<string>();
  let repository: string | undefined;
  for (const run of log.runs) {
    if (!isObject(run)) continue;
    const driver = isObject(run.tool) && isObject(run.tool.driver) ? run.tool.driver : {};
    const tool = options.tool?.trim() ? clean(options.tool, 80) : clean(driver.name, 80) || "unknown";
    const toolVersion = clean(driver.semanticVersion ?? driver.version, 40) || undefined;
    tools.add(tool);
    const provenance = list(run.versionControlProvenance).find(isObject);
    repository ??= provenance ? clean(provenance.repositoryUri, 300) || undefined : undefined;
    const bases = isObject(run.originalUriBaseIds) ? Object.values(run.originalUriBaseIds).filter(isObject).map(entry => repoUriBase(entry.uri)).filter(Boolean) : [];
    const roots = [...(options.roots ?? []), ...bases];
    const rules = list(driver.rules).filter(isObject);
    const byId = new Map(rules.map(rule => [clean(rule.id, 200), rule] as const));
    for (const raw of list(run.results)) {
      if (!isObject(raw)) continue;
      if (findings.length >= MAX_SARIF_RESULTS) throw new Error(`The log has more than ${MAX_SARIF_RESULTS} results; split it and import the parts.`);
      if (raw.suppressions && list(raw.suppressions).length) continue;
      // Coverage and not-applicable entries (Strix writes them beside its findings) are not findings.
      const kind = clean(raw.kind, 20);
      if (kind === "pass" || kind === "notApplicable" || (kind && kind !== "fail" && (raw.level === undefined || raw.level === "none"))) continue;
      const index = typeof raw.ruleIndex === "number" ? raw.ruleIndex : -1;
      const ruleId = clean(raw.ruleId, 200) || clean(isObject(raw.rule) ? raw.rule.id : "", 200) || clean(rules[index]?.id, 200) || "unknown-rule";
      const rule = byId.get(ruleId) ?? rules[index];
      const message = scrubText(raw.message, 4000);
      const ruleTitle = scrubText(rule?.shortDescription, 300) || scrub(rule?.name, 300);
      const title = (ruleTitle || message.split("\n")[0] || ruleId).slice(0, 300);
      const help = scrubText(rule?.fullDescription, 2000) || scrubText(rule?.help, 2000);
      const description = [message, help && help !== message ? help : ""].filter(Boolean).join("\n\n").slice(0, 6000) || title;

      const physical = list(raw.locations).filter(isObject).map(location => location.physicalLocation).find(isObject);
      const artifact = physical && isObject(physical.artifactLocation) ? physical.artifactLocation : undefined;
      const resultProperties = isObject(raw.properties) ? raw.properties : {};
      const strix = isObject(resultProperties.strix) ? resultProperties.strix : {};
      // A scanner that anchors a location-less finding to a placeholder file says so; that file is not where the problem is.
      const synthetic = resultProperties.synthetic_location === true;
      const path = synthetic ? undefined : repoRelativePath(artifact?.uri, roots);
      const region = physical && isObject(physical.region) ? physical.region : undefined;
      const startLine = positive(region?.startLine);
      const endLine = positive(region?.endLine);
      const snippet = region && isObject(region.snippet) ? scrub(region.snippet.text, 2000) || undefined : undefined;

      const ruleProperties = isObject(rule?.properties) ? rule.properties : {};
      const cwe = cweNumbers(ruleProperties.tags, resultProperties.tags, ruleProperties.cwe, resultProperties.cwe, [strix.cwe]);
      const fromCwe = cwe.map(number => CWE_CATEGORY[number]).find(Boolean);
      const category = fromCwe ?? normalizeAttackCategory(ruleId).category;

      // Web findings: ZAP puts the request on the result, Strix an endpoint, Nuclei and others a URL as the artifact.
      const request = isObject(raw.webRequest) ? raw.webRequest : {};
      const logical = list(raw.locations).filter(isObject).flatMap(location => list(location.logicalLocations)).filter(isObject)
        .find(entry => entry.kind === "endpoint" || entry.kind === "resource");
      const endpoint = path ? undefined
        : safeUrl(request.target) ?? safeUrl(artifact?.uri) ?? endpointOf(strix.endpoint, strix.target) ?? endpointOf(logical?.fullyQualifiedName, strix.target);
      const method = endpoint ? methodOf(request.method ?? strix.method) : undefined;
      const poc = isObject(strix.poc) ? clean(strix.poc.description, 1500) : "";
      const evidenceText = redactEvidence([clean(resultProperties.evidence, 1500), poc].filter(Boolean).join("\n\n")).slice(0, 3000) || undefined;

      const partial = isObject(raw.partialFingerprints) ? Object.entries(raw.partialFingerprints).find(([, value]) => typeof value === "string" && value) : undefined;
      const key = partial
        ? `${partial[0]}:${clean(partial[1], 200)}`
        : `${path ?? ""}:${startLine ?? ""}:${method ?? ""} ${endpoint ?? ""}:${message.slice(0, 200)}`;
      findings.push({
        tool, ...(toolVersion ? { toolVersion } : {}), ruleId, title, description,
        severity: severityOf(raw.level ?? (isObject(rule?.defaultConfiguration) ? rule.defaultConfiguration.level : undefined), rule, raw),
        category, ...(path ? { path } : {}), ...(startLine ? { startLine } : {}), ...(endLine ? { endLine } : {}), ...(snippet ? { snippet } : {}),
        ...(endpoint ? { endpoint } : {}), ...(method ? { method } : {}), ...(evidenceText ? { evidence: evidenceText } : {}),
        fingerprint: `sarif:${sha(`${tool}\n${ruleId}\n${path ?? ""}\n${method ?? ""} ${endpoint ?? ""}\n${key}`)}`,
        cwe: cwe.map(number => `CWE-${number}`),
      });
    }
  }
  return { findings, tools: [...tools], ...(repository ? { repository } : {}) };
}

/** True when the parsed JSON looks like a SARIF log rather than one of 0's own reports. */
export function looksLikeSarif(text: string): boolean {
  if (!/"runs"\s*:/.test(text)) return false;
  try { const value = JSON.parse(text); return isObject(value) && Array.isArray(value.runs); } catch { return false; }
}

const MAX_JSONL_LINE = 512 * 1024;
const NUCLEI_SEVERITY: Record<string, Severity> = { critical: "critical", high: "high", medium: "medium", low: "low", info: "info", unknown: "info" };

/** True when the text is Nuclei's JSON Lines output (`-jsonl-export`): the first line is an object with a `template-id`. */
export function looksLikeNucleiJsonl(text: string): boolean {
  const newline = text.indexOf("\n");
  const first = (newline === -1 ? text : text.slice(0, newline)).trim();
  if (!first.startsWith("{") || first.length > MAX_JSONL_LINE) return false;
  try { const value = JSON.parse(first); return isObject(value) && typeof value["template-id"] === "string"; } catch { return false; }
}

/**
 * Read Nuclei's JSON Lines output. Nuclei's own SARIF export names only the host and drops the matched URL, the CWE and the
 * severity name, so this reads the richer file. Same limits as the SARIF reader: untrusted text, nothing is executed or fetched.
 */
export function parseNucleiJsonl(text: string, options: { tool?: string } = {}): SarifImport {
  const tool = options.tool?.trim() ? clean(options.tool, 80) : "Nuclei";
  const findings: ImportedFinding[] = [];
  // Walk the text line by line instead of splitting it: a file of millions of empty lines must not become an array.
  for (let start = 0; start < text.length;) {
    const newline = text.indexOf("\n", start);
    const end = newline === -1 ? text.length : newline;
    const line = end - start > MAX_JSONL_LINE ? "" : text.slice(start, end);
    start = end + 1;
    if (!line.trim()) continue;
    let raw: unknown;
    try { raw = JSON.parse(line); } catch { continue; }
    if (!isObject(raw) || typeof raw["template-id"] !== "string") continue;
    if (findings.length >= MAX_SARIF_RESULTS) throw new Error(`The file has more than ${MAX_SARIF_RESULTS} results; split it and import the parts.`);
    const info = isObject(raw.info) ? raw.info : {};
    const classification = isObject(info.classification) ? info.classification : {};
    const ruleId = clean(raw["template-id"], 200) || "unknown-rule";
    const title = (scrub(info.name, 300) || ruleId).slice(0, 300);
    const remediation = scrub(info.remediation, 1500);
    const description = [scrub(info.description, 3000), remediation ? `Fix: ${remediation}` : ""].filter(Boolean).join("\n\n") || title;
    const severity = NUCLEI_SEVERITY[clean(info.severity, 12).toLowerCase()] ?? "info";
    const cwe = cweNumbers(list(classification["cwe-id"]).map(value => typeof value === "string" ? value : ""));
    const category = cwe.map(number => CWE_CATEGORY[number]).find(Boolean) ?? normalizeAttackCategory(ruleId).category;
    const endpoint = safeUrl(raw["matched-at"]) ?? safeUrl(raw.url) ?? endpointOf(raw["matched-at"]);
    const requestText = typeof raw.request === "string" ? raw.request : "";
    const method = methodOf(/^([A-Za-z]{3,10}) /.exec(requestText)?.[1]);
    const status = typeof raw.response === "string" ? /^HTTP\/[\d.]+ (\d{3})/.exec(raw.response)?.[1] : undefined;
    const extracted = list(raw["extracted-results"]).map(value => clean(value, 300)).filter(Boolean).slice(0, 10);
    const evidence = [
      clean(raw["curl-command"], 1500) ? `Request: ${redactEvidence(clean(raw["curl-command"], 1500))}` : "",
      status ? `Response status: ${status}` : "",
      extracted.length ? `Matched: ${redactEvidence(extracted.join(", "))}` : "",
    ].filter(Boolean).join("\n").slice(0, 3000) || undefined;
    findings.push({
      tool, ruleId, title, description, severity, category,
      ...(endpoint ? { endpoint } : {}), ...(method ? { method } : {}), ...(evidence ? { evidence } : {}),
      fingerprint: `sarif:${sha(`${tool}\n${ruleId}\n${method ?? ""} ${endpoint ?? ""}\n${clean(raw["matcher-name"], 100)}`)}`,
      cwe: cwe.map(number => `CWE-${number}`),
    });
  }
  if (!findings.length && !text.trim()) throw new Error("The file is empty.");
  return { findings, tools: [tool] };
}

/** Read a scanner's output: Nuclei JSON Lines, or SARIF 2.1.0 (ZAP, Strix, Nuclei's SARIF export and most others). */
export function parseScannerOutput(text: string, options: { tool?: string; roots?: readonly string[] } = {}): SarifImport {
  return looksLikeNucleiJsonl(text) ? parseNucleiJsonl(text, options.tool ? { tool: options.tool } : {}) : parseSarif(text, options);
}
