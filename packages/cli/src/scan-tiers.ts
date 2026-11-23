/**
 * Scan tiers: an operator-owned map from repository to how much effort a scan spends on it.
 *
 * The map lives with the operator (`--tiers <file>`, or `scan-tiers.yaml|yml|json` in the 0 state folder). It is never found
 * or read from the repository being scanned: that folder is written by whoever can change the code under review, and a
 * change that could lower its own tier could skip its own scan.
 */
import { lstatSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import type { ScanTierInfo } from "@0/engine/shared";
import { UsageError } from "./commands/output.js";

export const TIER_NAMES = ["critical", "standard", "light", "skip"] as const;
export type TierName = typeof TIER_NAMES[number];
export const TIER_FILE_NAMES = ["scan-tiers.yaml", "scan-tiers.yml", "scan-tiers.json"] as const;
const MAX_TIER_FILE_BYTES = 256 * 1024;
const MAX_RULES = 1000;
const MAX_REASON = 300;

export interface TierSettings {
  /** USD for the scan, the same as --budget. */
  budget?: number;
  /** The same as --batches. */
  batches?: "auto" | "on" | "off";
  /** The skill that holds the scan method, the same as --skill. */
  skill?: string;
  /** Run the pattern scanners only; no model reviews the code. */
  prepassOnly?: boolean;
  /** Why the tier (or the repository in it) is set this way. Shown in the report. */
  reason?: string;
}

/** What each tier does when the file does not say otherwise. */
export const BUILTIN_TIERS: Record<TierName, TierSettings> = {
  critical: { budget: 20, batches: "on", skill: "scan" },
  standard: { budget: 5, batches: "auto", skill: "scan" },
  light: { budget: 1, batches: "off", skill: "scan" },
  skip: {},
};

export interface TierRule { kind: "repo" | "path"; pattern: string; tier: TierName; reason?: string }
export interface TierMap { file: string; default: TierName; tiers: Record<TierName, TierSettings>; rules: TierRule[] }

export interface ResolvedTier extends ScanTierInfo { settings: TierSettings; file: string }

const REPO_PATTERN = /^[A-Za-z0-9._*?-]+\/[A-Za-z0-9._*?-]+$/;
const SETTING_KEYS = ["budget", "batches", "skill", "prepassOnly", "prepass-only", "reason"];

const isObject = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);
const hasWildcard = (pattern: string): boolean => /[*?]/.test(pattern);

function fail(file: string, message: string): never { throw new UsageError(`${file}: ${message}`); }

function reasonOf(value: unknown, where: string, file: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !value.trim()) fail(file, `${where}: reason must be a non-empty text.`);
  // eslint-disable-next-line no-control-regex
  const text = value.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim();
  if (text.length > MAX_REASON) fail(file, `${where}: reason is longer than ${MAX_REASON} characters.`);
  return text;
}

function settingsOf(raw: unknown, name: TierName, file: string): TierSettings {
  if (!isObject(raw)) fail(file, `tiers.${name} must be a mapping.`);
  for (const key of Object.keys(raw)) if (!SETTING_KEYS.includes(key)) fail(file, `tiers.${name}: unknown setting '${key}'. Known: budget, batches, skill, prepassOnly, reason.`);
  const settings: TierSettings = {};
  if (raw.budget !== undefined) {
    if (typeof raw.budget !== "number" || !Number.isFinite(raw.budget) || raw.budget <= 0 || raw.budget > 1000) fail(file, `tiers.${name}.budget must be a positive USD amount up to 1000.`);
    settings.budget = raw.budget;
  }
  if (raw.batches !== undefined) {
    if (raw.batches !== "auto" && raw.batches !== "on" && raw.batches !== "off") fail(file, `tiers.${name}.batches must be auto, on or off.`);
    settings.batches = raw.batches;
  }
  if (raw.skill !== undefined) {
    if (typeof raw.skill !== "string" || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(raw.skill)) fail(file, `tiers.${name}.skill must be a skill id such as scan.`);
    settings.skill = raw.skill;
  }
  const only = raw.prepassOnly ?? raw["prepass-only"];
  if (only !== undefined) {
    if (typeof only !== "boolean") fail(file, `tiers.${name}.prepassOnly must be true or false.`);
    settings.prepassOnly = only;
  }
  const reason = reasonOf(raw.reason, `tiers.${name}`, file);
  if (reason) settings.reason = reason;
  if (name === "skip" && (settings.budget !== undefined || settings.batches !== undefined || settings.skill !== undefined || settings.prepassOnly !== undefined)) fail(file, "tiers.skip takes only a reason: a skipped scan runs nothing.");
  if (settings.prepassOnly && settings.skill !== undefined) fail(file, `tiers.${name}: skill has no effect with prepassOnly (no model runs).`);
  return settings;
}

const tierNameOf = (value: unknown, where: string, file: string): TierName => {
  if (typeof value !== "string" || !(TIER_NAMES as readonly string[]).includes(value)) fail(file, `${where}: tier must be one of ${TIER_NAMES.join(", ")}.`);
  return value as TierName;
};

/** The map in a tier file's text (JSON or YAML). Throws a UsageError that names the file and the entry. */
export function parseTierMap(text: string, file: string): TierMap {
  let raw: unknown;
  try { raw = /^\s*\{/.test(text) ? JSON.parse(text) : parseYaml(text); }
  catch (error) { fail(file, `could not be read: ${error instanceof Error ? error.message.split("\n")[0] : String(error)}`); }
  if (!isObject(raw)) fail(file, "must be a mapping with 'repositories' (and optionally 'default' and 'tiers').");
  for (const key of Object.keys(raw)) if (!["version", "default", "tiers", "repositories"].includes(key)) fail(file, `unknown key '${key}'. Known: version, default, tiers, repositories.`);
  if (raw.version !== undefined && raw.version !== 1) fail(file, "version must be 1.");
  const tiers = Object.fromEntries(TIER_NAMES.map(name => [name, { ...BUILTIN_TIERS[name] }])) as Record<TierName, TierSettings>;
  if (raw.tiers !== undefined) {
    if (!isObject(raw.tiers)) fail(file, "tiers must be a mapping of tier name to settings.");
    for (const [name, value] of Object.entries(raw.tiers)) {
      const tier = tierNameOf(name, "tiers", file);
      // A setting given in the file replaces the built-in value for that tier; the others keep theirs.
      tiers[tier] = { ...BUILTIN_TIERS[tier], ...settingsOf(value, tier, file) };
    }
  }
  const defaultTier = raw.default === undefined ? "standard" : tierNameOf(raw.default, "default", file);
  const rules: TierRule[] = [];
  if (raw.repositories !== undefined) {
    if (!Array.isArray(raw.repositories)) fail(file, "repositories must be a list.");
    if (raw.repositories.length > MAX_RULES) fail(file, `repositories has more than ${MAX_RULES} entries.`);
    raw.repositories.forEach((entry, index) => {
      const where = `repositories[${index}]`;
      if (!isObject(entry)) fail(file, `${where} must be a mapping with repo or path, and tier.`);
      for (const key of Object.keys(entry)) if (!["repo", "path", "tier", "reason"].includes(key)) fail(file, `${where}: unknown key '${key}'. Known: repo, path, tier, reason.`);
      if ((entry.repo === undefined) === (entry.path === undefined)) fail(file, `${where} needs exactly one of repo (owner/name) or path.`);
      const tier = tierNameOf(entry.tier, where, file);
      const reason = reasonOf(entry.reason, where, file);
      if (entry.repo !== undefined) {
        if (typeof entry.repo !== "string" || !REPO_PATTERN.test(entry.repo)) fail(file, `${where}.repo must look like owner/name (a * or ? matches part of a name).`);
        rules.push({ kind: "repo", pattern: entry.repo.toLowerCase(), tier, ...(reason ? { reason } : {}) });
      } else {
        if (typeof entry.path !== "string" || !/^(\/|~\/)/.test(entry.path)) fail(file, `${where}.path must be an absolute folder pattern starting with / or ~/.`);
        if (entry.path.split("/").includes("..")) fail(file, `${where}.path must not contain '..'.`);
        const expanded = entry.path.startsWith("~/") ? join(homedir(), entry.path.slice(2)) : entry.path;
        rules.push({ kind: "path", pattern: expanded.replace(/\/+$/, "") || "/", tier, ...(reason ? { reason } : {}) });
      }
    });
  }
  return { file, default: defaultTier, tiers, rules };
}

/** A glob as a regular expression: `*` and `?` stay inside one path segment, `**` crosses segments, and a trailing `/**` also matches the folder itself. */
export function globToRegExp(pattern: string, caseInsensitive = false): RegExp {
  let source = "";
  for (let index = 0; index < pattern.length; index++) {
    const char = pattern[index]!;
    if (char === "*") {
      if (pattern[index + 1] === "*") {
        index++;
        if (pattern[index + 1] === "/") { index++; source += "(?:.*/)?"; } else source += ".*";
      } else source += "[^/]*";
    } else if (char === "?") source += "[^/]";
    else source += char.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  source = source.replace(/\/\.\*$/, "(?:/.*)?");
  return new RegExp(`^${source}$`, caseInsensitive ? "i" : "");
}

/** `owner/name` from a git remote or URL (`git@host:owner/name.git`, `https://host/owner/name`), lower case, or undefined. */
export function repoIdentifier(remote: string | undefined): string | undefined {
  if (!remote) return undefined;
  const cleaned = remote.trim().replace(/[?#].*$/, "").replace(/\/+$/, "").replace(/\.git$/i, "");
  const parts = cleaned.split(/[/:]/).filter(Boolean);
  if (parts.length < 2) return undefined;
  const [owner, name] = parts.slice(-2) as [string, string];
  return /^[A-Za-z0-9._-]+$/.test(owner) && /^[A-Za-z0-9._-]+$/.test(name) ? `${owner}/${name}`.toLowerCase() : undefined;
}

export interface TierTarget { /** `owner/name` of the git remote or URL. */ repo?: string; /** The folder's real path on this machine. */ path?: string }

const norm = (path: string): string => path.replace(/\\/g, "/").replace(/\/+$/, "") || "/";

/**
 * The tier for a target. An exact repository wins over an exact path, which wins over a pattern (the first that matches, in file
 * order), which wins over the file's default. Pure.
 */
export function resolveTier(map: TierMap, target: TierTarget): ResolvedTier {
  const repo = target.repo?.toLowerCase();
  const path = target.path ? norm(target.path) : undefined;
  const pick = (rule: TierRule, source: ScanTierInfo["source"]): ResolvedTier => {
    const base = map.tiers[rule.tier];
    const reason = rule.reason ?? base.reason;
    return {
      name: rule.tier, source, match: rule.pattern, ...(reason ? { reason } : {}),
      ...(rule.tier === "skip" ? { skipped: true } : base.prepassOnly ? { prepassOnly: true } : {}),
      settings: { ...base, ...(reason ? { reason } : {}) }, file: map.file,
    };
  };
  const exactRepo = repo ? map.rules.find(rule => rule.kind === "repo" && !hasWildcard(rule.pattern) && rule.pattern === repo) : undefined;
  if (exactRepo) return pick(exactRepo, "exact-repo");
  const exactPath = path ? map.rules.find(rule => rule.kind === "path" && !hasWildcard(rule.pattern) && norm(rule.pattern) === path) : undefined;
  if (exactPath) return pick(exactPath, "exact-path");
  const pattern = map.rules.find(rule => (rule.kind === "repo" ? !!repo && hasWildcard(rule.pattern) && globToRegExp(rule.pattern, true).test(repo) : !!path && hasWildcard(rule.pattern) && globToRegExp(rule.pattern).test(path)));
  if (pattern) return pick(pattern, "glob");
  const base = map.tiers[map.default];
  return {
    name: map.default, source: "default", ...(base.reason ? { reason: base.reason } : {}),
    ...(map.default === "skip" ? { skipped: true } : base.prepassOnly ? { prepassOnly: true } : {}), settings: base, file: map.file,
  };
}

/** Read and check one tier file. */
export function readTierMap(file: string): TierMap {
  let size: number;
  try { size = statSync(file).size; if (!statSync(file).isFile()) throw new Error("not a file"); }
  catch { throw new UsageError(`--tiers ${file} is not a file.`); }
  if (size > MAX_TIER_FILE_BYTES) throw new UsageError(`${file} is ${size} bytes; the limit is ${MAX_TIER_FILE_BYTES}.`);
  return parseTierMap(readFileSync(file, "utf8"), file);
}

/**
 * The tier map the operator named with --tiers, else the first of `scan-tiers.yaml|yml|json` in the state folder. Never a file
 * of the scanned repository, unless the operator names it (and then the scan warns).
 */
export function loadTierMap(explicit: string | undefined, stateDir: string): TierMap | undefined {
  if (explicit) return readTierMap(explicit);
  for (const name of TIER_FILE_NAMES) {
    const path = join(stateDir, name);
    try { if (lstatSync(path).isFile()) return readTierMap(path); } catch (error) { if (error instanceof UsageError) throw error; }
  }
  return undefined;
}

/** One sentence: which tier applied and why. */
export function tierSentence(tier: ResolvedTier): string {
  const how = tier.source === "default" ? "no entry matched, so the default applies" : tier.source === "glob" ? `pattern ${tier.match} matched` : `${tier.source === "exact-repo" ? "repository" : "path"} ${tier.match} matched exactly`;
  return `tier ${tier.name} (${how}${tier.reason ? `; reason: ${tier.reason}` : ""})`;
}

/** The settings a tier sets, as text, for the line that says what the scan will do. */
export function settingsSentence(tier: ResolvedTier): string {
  if (tier.skipped) return "the scan is skipped";
  const { settings } = tier;
  if (tier.prepassOnly) return "pattern scanners only, no model review";
  return [settings.budget !== undefined ? `budget $${settings.budget}` : "", settings.batches ? `batches ${settings.batches}` : "", settings.skill ? `skill ${settings.skill}` : ""].filter(Boolean).join(", ") || "no settings";
}

/** The options a tier fills in: the budget, batches and skill the person did not type. Policy scans keep their skill. */
export function applyTierSettings<T extends { budget: string; batches?: string; skill: string; policy?: string[]; orgPolicy?: string[] }>(options: T, tier: ResolvedTier, explicit: ReadonlySet<string>): { options: T; notes: string[] } {
  const next = { ...options };
  const notes: string[] = [];
  const { settings } = tier;
  if (tier.skipped || tier.prepassOnly) return { options: next, notes };
  if (settings.budget !== undefined) {
    if (explicit.has("budget")) notes.push(`--budget ${options.budget} overrides the tier budget $${settings.budget}`);
    else next.budget = String(settings.budget);
  }
  if (settings.batches !== undefined) {
    if (explicit.has("batches")) notes.push(`--batches ${options.batches} overrides the tier setting ${settings.batches}`);
    else next.batches = settings.batches;
  }
  if (settings.skill !== undefined && settings.skill !== options.skill) {
    if (explicit.has("skill")) notes.push(`--skill ${options.skill} overrides the tier skill ${settings.skill}`);
    else if (options.policy?.length || options.orgPolicy?.length) notes.push(`the tier skill ${settings.skill} is not used: --policy runs the policy-check skill`);
    else next.skill = settings.skill;
  }
  return { options: next, notes };
}
