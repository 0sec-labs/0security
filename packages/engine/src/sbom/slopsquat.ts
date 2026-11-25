/**
 * Slopsquatting check: flag dependencies that look invented or planted. AI coding tools sometimes name packages that do
 * not exist, and attackers register those names (Spracklen et al., USENIX Security 2025, arXiv 2406.10279). This looks
 * each npm and PyPI package up on its public registry and reports signals: the name is not registered, the package is
 * brand new, or the name is one edit from a very popular package. No model is involved.
 *
 * Opt-in network use: only the package name goes out (registry.npmjs.org, api.npmjs.org, pypi.org). Registry answers
 * are untrusted: size-capped, parsed with a fixed set of reads, and every value is bounded before use.
 */
import { EnterpriseEgressError, assertEgressAllowed } from "../policy/enterprise.js";
import { POPULAR_NPM, POPULAR_PYPI } from "./popular-packages.js";

export type SlopSeverity = "high" | "medium" | "low";
export type SlopRule = "slopsquat/nonexistent" | "slopsquat/new-package" | "slopsquat/typosquat-candidate";

export interface SlopFinding {
  ruleId: SlopRule;
  severity: SlopSeverity;
  purl: string;
  ecosystem: "npm" | "pypi";
  name: string;
  /** One plain sentence with the signal values. */
  message: string;
  /** Where to read the package on its registry. */
  url: string;
  signals: { ageDays?: number; releases?: number; maintainers?: number; weeklyDownloads?: number; installScript?: boolean; lookalikeOf?: string };
}
export interface SlopSkip { purl: string; reason: string }
export interface SlopResult {
  /** Packages looked up. */
  checked: number;
  /** Packages left out because they are private, local, or workspace members. */
  skipped: SlopSkip[];
  /** Packages in ecosystems this check does not cover. */
  unsupported: number;
  overCap: number;
  /** Lookups that failed (network error, bad answer, over the size limit): not checked, not ok. */
  failed: string[];
  cap: number;
  /** Set when no lookup was made at all, for example `offline`. The check never reports ok in that case. */
  notChecked?: string;
  findings: SlopFinding[];
}
export interface SlopOptions {
  fetch?: typeof fetch;
  /** Replace the registry hosts (tests). */
  baseUrls?: { npm?: string; npmDownloads?: string; pypi?: string };
  cap?: number;
  /** A package younger than this many days is "new" (default 30). */
  newDays?: number;
  /** Names or `@scope/*` patterns to treat as private. */
  privatePatterns?: string[];
  now?: Date;
  timeoutMs?: number;
  maxBytes?: number;
}

export const SLOPSQUAT_CAP = 200;
export const SLOPSQUAT_NEW_DAYS = 30;
const CONCURRENCY = 4;
const TIMEOUT_MS = 10_000;
const MAX_BYTES = 8 * 1024 * 1024;
const LOW_DOWNLOADS = 1000;
const FEW_RELEASES = 3;
const DAY_MS = 86_400_000;
/** Scopes of well-known public organisations. Any other scope is treated as private and skipped. */
const PUBLIC_SCOPES = new Set(["types", "babel", "angular", "vue", "nestjs", "aws-sdk", "azure", "google-cloud", "octokit", "sentry", "testing-library", "tanstack", "emotion", "mui", "radix-ui", "reduxjs", "typescript-eslint", "eslint", "jest", "storybook", "vitejs", "rollup", "swc", "opentelemetry", "grpc", "smithy", "nx", "prisma", "supabase", "stripe", "apollo", "playwright", "vitest", "fastify", "svgr", "floating-ui", "headlessui", "lezer", "codemirror"]);
const NPM_NAME = /^(?:@[a-z0-9][a-z0-9._~-]{0,63}\/)?[a-z0-9][a-z0-9._~-]{0,213}$/;
const PYPI_NAME = /^[a-z0-9](?:[a-z0-9._-]{0,98}[a-z0-9])?$/;
const POPULAR = { npm: new Set(POPULAR_NPM), pypi: new Set(POPULAR_PYPI) };

const isObject = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);
const own = (value: Record<string, unknown>, key: string): unknown => Object.hasOwn(value, key) ? value[key] : undefined;
const truthyEnv = (value: string | undefined): boolean => { const text = value?.trim().toLowerCase(); return text !== undefined && text !== "" && text !== "0" && text !== "false" && text !== "no"; };

/** Edit distance where swapping two neighbouring letters counts as one edit. */
export function editDistance(a: string, b: string): number {
  const rows: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array<number>(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) rows[0]![j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let best = Math.min(rows[i - 1]![j]! + 1, rows[i]![j - 1]! + 1, rows[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) best = Math.min(best, rows[i - 2]![j - 2]! + 1);
      rows[i]![j] = best;
    }
  }
  return rows[a.length]![b.length]!;
}

/** The popular package a name imitates: one edit away (two for long names), or the same letters with other separators. */
export function lookalikeOf(ecosystem: "npm" | "pypi", name: string): string | undefined {
  const list = ecosystem === "npm" ? POPULAR_NPM : POPULAR_PYPI;
  if (POPULAR[ecosystem].has(name) || name.startsWith("@")) return undefined;
  const bare = (value: string): string => value.replace(/[-_.]/g, "");
  let best: { name: string; distance: number } | undefined;
  for (const popular of list) {
    if (popular.length < 4 || Math.abs(popular.length - name.length) > 2) continue;
    const distance = bare(popular) === bare(name) ? 0 : editDistance(popular, name);
    const limit = Math.min(popular.length, name.length) >= 9 ? 2 : 1;
    if (distance <= limit && (!best || distance < best.distance)) best = { name: popular, distance };
  }
  return best?.name;
}

/** The package URL's ecosystem and name, or undefined when it is not an npm or PyPI package URL. */
function target(purl: string): { ecosystem: "npm" | "pypi"; name: string; version: string; qualified: boolean } | undefined {
  const match = /^pkg:(npm|pypi)\/([^@?#]+)@([^?#]+)(\?[^#]*)?/.exec(purl);
  if (!match) return undefined;
  let name: string; let version: string;
  try { name = decodeURIComponent(match[2]!); version = decodeURIComponent(match[3]!); } catch { return undefined; }
  return { ecosystem: match[1] as "npm" | "pypi", name, version, qualified: /(?:^|[?&])(repository_url|download_url|vcs_url)=/.test(match[4] ?? "") };
}

function privateByPattern(name: string, patterns: string[]): boolean {
  return patterns.some(pattern => pattern === name || (pattern.endsWith("/*") && name.startsWith(pattern.slice(0, -1))));
}

/** Read a response body up to a byte limit, then parse it as JSON. Throws when the body is too large or not JSON. */
async function readJson(response: Response, maxBytes: number): Promise<unknown> {
  const length = Number(response.headers.get("content-length"));
  if (Number.isFinite(length) && length > maxBytes) { await response.body?.cancel().catch(() => undefined); throw new Error("response over the size limit"); }
  const reader = response.body?.getReader();
  if (!reader) throw new Error("empty response");
  const chunks: Uint8Array[] = []; let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) { await reader.cancel().catch(() => undefined); throw new Error("response over the size limit"); }
    chunks.push(value);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
}

interface Facts { missing?: boolean; created?: number; releases?: number; maintainers?: number; installScript?: boolean }

const isoTime = (value: unknown): number | undefined => {
  if (typeof value !== "string" || value.length > 40) return undefined;
  const time = Date.parse(value);
  return Number.isFinite(time) ? time : undefined;
};
const INSTALL_HOOKS = ["preinstall", "install", "postinstall"];

function npmFacts(body: unknown, version: string): Facts {
  if (!isObject(body)) throw new Error("unexpected answer");
  const time = own(body, "time");
  const versions = own(body, "versions");
  const maintainers = own(body, "maintainers");
  const created = isObject(time) ? isoTime(own(time, "created")) : undefined;
  const releases = isObject(versions) ? Object.keys(versions).length : undefined;
  if (created === undefined || releases === undefined) throw new Error("unexpected answer");
  const installed = isObject(versions) ? own(versions, version) : undefined;
  const scripts = isObject(installed) ? own(installed, "scripts") : undefined;
  const installScript = isObject(installed) && (own(installed, "hasInstallScript") === true || (isObject(scripts) && INSTALL_HOOKS.some(hook => typeof own(scripts, hook) === "string")));
  return { created, releases, ...(Array.isArray(maintainers) ? { maintainers: maintainers.length } : {}), installScript };
}

function pypiFacts(body: unknown): Facts {
  if (!isObject(body)) throw new Error("unexpected answer");
  const releases = own(body, "releases");
  if (!isObject(releases)) throw new Error("unexpected answer");
  let created: number | undefined; let count = 0;
  for (const files of Object.values(releases)) {
    if (!Array.isArray(files) || !files.length) continue;
    count += 1;
    for (const file of files) {
      const time = isObject(file) ? isoTime(own(file, "upload_time_iso_8601")) ?? isoTime(own(file, "upload_time")) : undefined;
      if (time !== undefined && (created === undefined || time < created)) created = time;
    }
  }
  if (created === undefined) throw new Error("unexpected answer");
  return { created, releases: count };
}

export async function checkSlopsquat(bom: unknown, options: SlopOptions = {}): Promise<SlopResult> {
  const cap = options.cap ?? SLOPSQUAT_CAP;
  const base: SlopResult = { checked: 0, skipped: [], unsupported: 0, overCap: 0, failed: [], cap, findings: [] };
  const injected = !!(options.fetch || options.baseUrls);
  if (!injected) {
    if (truthyEnv(process.env["ZERO_OFFLINE"])) return { ...base, notChecked: "offline (ZERO_OFFLINE is set)" };
    try { assertEgressAllowed("registry.npmjs.org, api.npmjs.org, pypi.org (slopsquat check)"); }
    catch (error) { if (error instanceof EnterpriseEgressError) return { ...base, notChecked: "offline (ZERO_ENTERPRISE is set)" }; throw error; }
  }
  const fetcher = options.fetch ?? fetch;
  const npmBase = (options.baseUrls?.npm ?? "https://registry.npmjs.org").replace(/\/$/, "");
  const downloadsBase = (options.baseUrls?.npmDownloads ?? "https://api.npmjs.org").replace(/\/$/, "");
  const pypiBase = (options.baseUrls?.pypi ?? "https://pypi.org").replace(/\/$/, "");
  const timeoutMs = options.timeoutMs ?? TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? MAX_BYTES;
  const newDays = options.newDays ?? SLOPSQUAT_NEW_DAYS;
  const now = (options.now ?? new Date()).getTime();
  const patterns = options.privatePatterns ?? [];
  const components = isObject(bom) && Array.isArray(bom.components) ? bom.components.filter(isObject) : [];
  const metadata = isObject(bom) && isObject(bom.metadata) ? bom.metadata : {};
  const projectName = isObject(metadata.component) && typeof metadata.component.name === "string" ? metadata.component.name.toLowerCase() : "";
  const ordered = [...components].sort((a, b) => Number(a.scope === "excluded") - Number(b.scope === "excluded"));

  const wanted = new Map<string, { purl: string; ecosystem: "npm" | "pypi"; name: string; version: string }>();
  const skipped: SlopSkip[] = [];
  let unsupported = 0;
  for (const component of ordered) {
    const purl = typeof component.purl === "string" && /^pkg:[a-z]+\/\S{1,380}$/.test(component.purl) ? component.purl : undefined;
    if (!purl) continue;
    const found = target(purl);
    if (!found) { unsupported += 1; continue; }
    const key = `${found.ecosystem}:${found.name}`;
    if (wanted.has(key) || skipped.some(item => item.purl === purl)) continue;
    const properties = Array.isArray(component.properties) ? component.properties.filter(isObject) : [];
    const local = properties.some(property => property.name === "0:local");
    const scope = found.name.startsWith("@") ? found.name.slice(1, found.name.indexOf("/")) : "";
    const valid = found.ecosystem === "npm" ? NPM_NAME.test(found.name) : PYPI_NAME.test(found.name);
    if (local || found.qualified || (projectName && found.name === projectName) || privateByPattern(found.name, patterns) || (scope && !PUBLIC_SCOPES.has(scope)) || /^(file|link|git|https?|workspace):/.test(found.version)) { skipped.push({ purl, reason: "skipped: private or local" }); continue; }
    if (!valid) { skipped.push({ purl, reason: "skipped: not a public registry name" }); continue; }
    wanted.set(key, { purl, ...found });
  }
  const chosen = [...wanted.values()].slice(0, cap);

  const get = async (url: string): Promise<{ status: number; body?: unknown }> => {
    const response = await fetcher(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(timeoutMs), redirect: "error" });
    if (response.status === 404) { await response.body?.cancel().catch(() => undefined); return { status: 404 }; }
    if (!response.ok) { await response.body?.cancel().catch(() => undefined); throw new Error(`registry answered ${response.status}`); }
    return { status: response.status, body: await readJson(response, maxBytes) };
  };
  const findings: SlopFinding[] = []; const failed: string[] = [];
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, chosen.length) }, async () => {
    while (next < chosen.length) {
      const item = chosen[next++]!;
      const url = item.ecosystem === "npm" ? `https://www.npmjs.com/package/${item.name}` : `https://pypi.org/project/${item.name}/`;
      const make = (ruleId: SlopRule, severity: SlopSeverity, message: string, signals: SlopFinding["signals"]): void => { findings.push({ ruleId, severity, purl: item.purl, ecosystem: item.ecosystem, name: item.name, message, url, signals }); };
      try {
        const answer = item.ecosystem === "npm" ? await get(`${npmBase}/${encodeURIComponent(item.name).replace(/^%40/, "@")}`) : await get(`${pypiBase}/pypi/${encodeURIComponent(item.name)}/json`);
        if (answer.status === 404) {
          make("slopsquat/nonexistent", "medium", `${item.name} was not found on the public registry: if this is private, ignore. If an AI tool wrote this name, it may be invented and open to registration by an attacker.`, {});
          continue;
        }
        const facts = item.ecosystem === "npm" ? npmFacts(answer.body, item.version) : pypiFacts(answer.body);
        const ageDays = Math.max(0, Math.floor((now - facts.created!) / DAY_MS));
        const young = ageDays < newDays;
        const lookalike = lookalikeOf(item.ecosystem, item.name);
        let weeklyDownloads: number | undefined;
        if (item.ecosystem === "npm" && (young || lookalike)) {
          try {
            const downloads = await get(`${downloadsBase}/downloads/point/last-week/${encodeURIComponent(item.name).replace(/^%40/, "@")}`);
            const count = downloads.status === 200 && isObject(downloads.body) ? own(downloads.body, "downloads") : undefined;
            if (typeof count === "number" && Number.isFinite(count) && count >= 0) weeklyDownloads = Math.floor(count);
          } catch { /* downloads are one signal among several; the rest still apply */ }
        }
        const signals: SlopFinding["signals"] = { ageDays, ...(facts.releases !== undefined ? { releases: facts.releases } : {}), ...(facts.maintainers !== undefined ? { maintainers: facts.maintainers } : {}), ...(weeklyDownloads !== undefined ? { weeklyDownloads } : {}), ...(facts.installScript ? { installScript: true } : {}) };
        const facing = [`first published ${ageDays} day${ageDays === 1 ? "" : "s"} ago`, `${facts.releases} release${facts.releases === 1 ? "" : "s"}`,
          ...(facts.maintainers !== undefined ? [`${facts.maintainers} maintainer${facts.maintainers === 1 ? "" : "s"}`] : []),
          ...(weeklyDownloads !== undefined ? [`${weeklyDownloads} downloads last week`] : []), ...(facts.installScript ? ["runs an install script"] : [])].join(", ");
        const lowUse = weeklyDownloads !== undefined && weeklyDownloads < LOW_DOWNLOADS;
        const fewReleases = (facts.releases ?? 0) <= FEW_RELEASES;
        if (lookalike && (young || lowUse || (item.ecosystem === "pypi" && fewReleases))) {
          make("slopsquat/typosquat-candidate", young || facts.installScript ? "high" : "medium", `${item.name} is one or two edits from the popular package ${lookalike} and is little used (${facing}).`, { ...signals, lookalikeOf: lookalike });
        } else if (young && fewReleases) {
          make("slopsquat/new-package", facts.installScript ? "high" : lowUse ? "medium" : "low", `${item.name} is new (${facing}).`, signals);
        }
      } catch (error) { failed.push(`${item.name} (${error instanceof Error ? error.message : "failed"})`.slice(0, 160)); }
    }
  }));
  const order: Record<SlopSeverity, number> = { high: 0, medium: 1, low: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity] || (a.purl < b.purl ? -1 : a.purl > b.purl ? 1 : 0) || (a.ruleId < b.ruleId ? -1 : 1));
  skipped.sort((a, b) => (a.purl < b.purl ? -1 : 1));
  return { ...base, checked: chosen.length, skipped, unsupported, overCap: wanted.size - chosen.length, failed: failed.sort().slice(0, 50), findings };
}

const LEVEL: Record<SlopSeverity, "error" | "warning" | "note"> = { high: "error", medium: "warning", low: "note" };
const SCORE: Record<SlopSeverity, string> = { high: "8", medium: "5", low: "2" };
const RULE_TEXT: Record<SlopRule, { name: string; text: string }> = {
  "slopsquat/nonexistent": { name: "DependencyNotFound", text: "Dependency not found on the public registry. AI tools sometimes invent package names, and attackers register them." },
  "slopsquat/new-package": { name: "NewPackage", text: "Dependency first published very recently with few releases." },
  "slopsquat/typosquat-candidate": { name: "TyposquatCandidate", text: "Dependency name is close to a very popular package and the package is new or little used." },
};

/** Rules and results to add to the SARIF run of `0 sbom check`. */
export function slopsquatSarifParts(findings: SlopFinding[], locate: (purl: string) => string): { rules: object[]; results: object[] } {
  const used = [...new Set(findings.map(finding => finding.ruleId))].sort();
  return {
    rules: used.map(id => ({ id, name: RULE_TEXT[id].name, shortDescription: { text: RULE_TEXT[id].text }, helpUri: "https://arxiv.org/abs/2406.10279", properties: { tags: ["dependency", "slopsquatting"] } })),
    results: findings.map(finding => ({
      ruleId: finding.ruleId, level: LEVEL[finding.severity], message: { text: `${finding.message} ${finding.url}` },
      locations: [{ physicalLocation: { artifactLocation: { uri: locate(finding.purl).split("\\").join("/") }, region: { startLine: 1 } } }],
      partialFingerprints: { "0slopsquat/v1": `${finding.ruleId}:${finding.purl}` },
      properties: { purl: finding.purl, severity: finding.severity, "security-severity": SCORE[finding.severity] },
    })),
  };
}

const ORDER = ["high", "medium", "low"] as const;
/** True when a finding is at or above the severity named by `--fail-on` (critical counts as high; info as low). */
export function slopsquatFails(findings: SlopFinding[], failOn: string | undefined): boolean {
  if (!failOn) return false;
  const level = failOn === "critical" ? "high" : failOn === "info" ? "low" : failOn;
  const index = ORDER.indexOf(level as typeof ORDER[number]);
  return index >= 0 && findings.some(finding => ORDER.indexOf(finding.severity) <= index);
}

export function slopsquatToText(result: SlopResult): string {
  const lines = ["Invented or planted packages (npm and PyPI; signals only, not proof):"];
  if (result.notChecked) lines.push(`  Not checked: ${result.notChecked}. No package was looked up, so this is not a clean result.`);
  else if (!result.findings.length) lines.push(`  No signals for ${result.checked} package${result.checked === 1 ? "" : "s"} checked.`);
  for (const finding of result.findings) lines.push(`  ${finding.severity}  ${finding.ruleId}  ${finding.message}`, `    ${finding.url}`);
  if (result.skipped.length) {
    lines.push(`  ${result.skipped.length} skipped: private or local:`);
    for (const item of result.skipped.slice(0, 20)) lines.push(`    ${item.purl}`);
    if (result.skipped.length > 20) lines.push(`    and ${result.skipped.length - 20} more`);
  }
  if (result.overCap) lines.push(`  Looked up the first ${result.cap} of ${result.checked + result.overCap} public packages; ${result.overCap} were not checked.`);
  if (result.unsupported) lines.push(`  ${result.unsupported} components are in ecosystems this check does not cover.`);
  if (result.failed.length) { lines.push(`  ${result.failed.length} lookups failed and were not checked:`); for (const item of result.failed.slice(0, 10)) lines.push(`    ${item}`); }
  return `${lines.join("\n")}\n`;
}
