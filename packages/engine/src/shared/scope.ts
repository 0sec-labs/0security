/**
 * Declared scope: which attack vectors a team cares about and which it does not.
 *
 * It lives in a `## Scope` section of a Markdown file (usually SECURITY.md) that a person wrote:
 *
 *   ## Scope
 *   ### In scope
 *   - broken-access-control: tenants must never see each other's data [paths: src/api/**]
 *   ### Out of scope
 *   - denial of service: the service sits behind a rate-limiting gateway (until 2027-06-30)
 *
 * The parser is pure and defensive: the text comes from a file, so lengths are capped, markup and control
 * characters are removed, and at most MAX_SCOPE_ENTRIES entries are read. An entry whose vector matches no category
 * is kept and reported (`unmatched scope entry`); it labels nothing.
 *
 * Findings that match an out-of-scope entry are labelled, never removed. Labelling is the only effect.
 */
import { categoryFromLabel } from "./finding-category.js";
import type { AttackCategory } from "./types.js";

export const MAX_SCOPE_ENTRIES = 100;
export const MAX_SCOPE_VECTOR_CHARS = 120;
export const MAX_SCOPE_REASON_CHARS = 400;
export const MAX_SCOPE_PATH_CHARS = 200;
export const MAX_SCOPE_PATHS = 10;
export const MAX_SCOPE_TEXT_BYTES = 256 * 1024;

export type ScopeKind = "in" | "out";

/**
 * Classes that are real vulnerabilities in nearly every application: nobody needs to make a scope call about them.
 * `0 threat-model --interview` never asks about them, and the parser warns when a hand-written entry declares one out of scope.
 */
export const ALWAYS_IN_SCOPE_CATEGORIES: ReadonlySet<string> = new Set<string>([
  "code-injection", "command-injection", "sql-injection", "hardcoded-secret", "insecure-storage", "path-traversal", "xxe", "unsafe-deserialization",
  "xss", "ssrf", "prototype-pollution", "insecure-randomness", "mass-assignment", "format-string", "heap-overflow", "stack-buffer-overflow", "out-of-bounds-read",
  "out-of-bounds-write", "use-after-free", "double-free", "type-confusion", "uninitialized-memory", "integer-overflow", "integer-truncation",
  "prompt-injection", "jailbreak", "system-prompt-extraction", "tool-misuse",
]);

export const isAlwaysInScope = (category: string | undefined): boolean => category !== undefined && ALWAYS_IN_SCOPE_CATEGORIES.has(category);

/**
 * Classes where "we do not care" is a plausible answer, most plausible first: a missing limit, a route that is public on purpose,
 * data that goes to a third party, a rule the code conflicts with, a weakness accepted for now.
 */
export const SCOPE_QUESTION_CATEGORIES: readonly AttackCategory[] = [
  "denial-of-service", "regex-dos", "missing-rate-limit", "broken-access-control", "data-exfiltration", "information-disclosure", "cors",
  "policy-violation", "known-vulnerable-package", "insecure-transport",
];

/** Classes the model may ask about from reading the code: the ones above, and weaknesses a team may accept knowingly for a while. */
export const MODEL_QUESTION_CATEGORIES: ReadonlySet<string> = new Set<string>([...SCOPE_QUESTION_CATEGORIES, "csrf", "open-redirect", "security-misconfiguration", "supply-chain", "crypto-misuse"]);

export interface ScopeEntry {
  kind: ScopeKind;
  /** The vector as written (cleaned): a category id, an alias or free text. */
  vector: string;
  /** The category the vector names, when it names one. */
  category?: AttackCategory;
  /** Why, in the writer's words. Empty when none was given. */
  reason: string;
  /** Last day (YYYY-MM-DD, inclusive, UTC) the entry applies. Absent: no expiry. */
  until?: string;
  /** Path globs; when present a finding must be in one of them. */
  paths: string[];
  /** Line in the source file (1-based). */
  line: number;
}

export interface ParsedScope {
  /** A `## Scope` section was present. */
  found: boolean;
  entries: ScopeEntry[];
  warnings: string[];
  /** Entries whose vector named no category. */
  unmatched: ScopeEntry[];
}

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]/g;

/** Plain one-line text: no control characters, no HTML tags or comments, no emphasis markers, single spaces. */
export function cleanScopeText(text: string, max: number): string {
  return text
    .replace(CONTROL, "")
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<\/?[A-Za-z!][^>]*>?/g, " ")
    .replace(/[<>]/g, "")
    .replace(/\*\*|__|`/g, "")
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, max);
}

/** A path glob: control characters, markup and spaces removed; stars stay. */
const cleanGlob = (text: string): string => text.replace(CONTROL, "").replace(/[<>`\s]/g, "").slice(0, MAX_SCOPE_PATH_CHARS);

const HEADING = /^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$/;
const BULLET = /^(\s*)(?:[-*+•–—]|\d{1,3}[.)])\s+(.*)$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;

const validDate = (value: string): boolean => {
  if (!DATE.test(value)) return false;
  const time = Date.parse(`${value}T00:00:00Z`);
  return Number.isFinite(time) && new Date(time).toISOString().slice(0, 10) === value;
};

const sectionKind = (title: string): ScopeKind | undefined => {
  const t = title.toLowerCase().replace(/[^a-z]+/g, " ").trim();
  if (/^in scope$/.test(t)) return "in";
  if (/^out of scope$/.test(t)) return "out";
  return undefined;
};

/** The lines of the `## Scope` section: from the heading to the next heading of level 1 or 2. Fenced code is skipped. */
function scopeLines(lines: readonly string[]): { start: number; body: Array<{ text: string; line: number }> } | undefined {
  let fence: string | undefined;
  let start = -1;
  const body: Array<{ text: string; line: number }> = [];
  for (let index = 0; index < lines.length; index++) {
    const text = lines[index]!;
    const fenced = /^\s{0,3}(`{3,}|~{3,})/.exec(text);
    if (fenced) { fence = fence === undefined ? fenced[1]![0] : fence === fenced[1]![0] ? undefined : fence; continue; }
    if (fence !== undefined) continue;
    const heading = HEADING.exec(text);
    if (start < 0) {
      if (heading && heading[1]!.length === 2 && /^scope$/i.test(cleanScopeText(heading[2]!, 80))) start = index;
      continue;
    }
    if (heading && heading[1]!.length <= 2) break;
    body.push({ text, line: index + 1 });
  }
  return start < 0 ? undefined : { start, body };
}

const pathKey = (paths: readonly string[]) => paths.join("\u0000");

/** Parse the `## Scope` section of a Markdown text. Never throws. */
export function parseScope(markdown: string): ParsedScope {
  const warnings: string[] = [];
  const text = markdown.length > MAX_SCOPE_TEXT_BYTES ? markdown.slice(0, MAX_SCOPE_TEXT_BYTES) : markdown;
  if (markdown.length > MAX_SCOPE_TEXT_BYTES) warnings.push(`the file is longer than ${MAX_SCOPE_TEXT_BYTES} characters; only the start was read`);
  const section = scopeLines(text.replace(/^﻿/, "").split(/\r\n|\r|\n/));
  if (!section) return { found: false, entries: [], warnings, unmatched: [] };

  const entries: ScopeEntry[] = [];
  const unmatched: ScopeEntry[] = [];
  const seen = new Set<string>();
  let kind: ScopeKind | undefined;
  let baseIndent: number | undefined;
  let last: ScopeEntry | undefined;
  let skipped = 0;
  let overflow = false;

  for (const { text: raw, line } of section.body) {
    const heading = HEADING.exec(raw);
    if (heading) {
      const found = sectionKind(cleanScopeText(heading[2]!, 80));
      if (found) { kind = found; baseIndent = undefined; last = undefined; }
      else { kind = undefined; last = undefined; warnings.push(`line ${line}: the heading '${cleanScopeText(heading[2]!, 60)}' is not 'In scope' or 'Out of scope'; its list is ignored`); }
      continue;
    }
    const bullet = BULLET.exec(raw);
    if (!bullet) {
      // A wrapped line continues the reason of the entry above.
      if (last && raw.trim() && /^\s+\S/.test(raw)) last.reason = cleanScopeText(`${last.reason} ${raw}`, MAX_SCOPE_REASON_CHARS);
      continue;
    }
    if (!kind) { skipped++; continue; }
    const indent = bullet[1]!.replace(/\t/g, "    ").length;
    baseIndent ??= indent;
    if (indent >= baseIndent + 2 && last) {
      // A nested bullet adds to the reason of its parent.
      const extra = cleanScopeText(bullet[2]!, MAX_SCOPE_REASON_CHARS);
      if (extra) last.reason = cleanScopeText(`${last.reason}${last.reason ? "; " : ""}${extra}`, MAX_SCOPE_REASON_CHARS);
      continue;
    }
    let body = bullet[2]!;
    const paths: string[] = [];
    body = body.replace(/\[\s*paths?\s*:\s*([^\]]*)\]/gi, (_all, list: string) => {
      for (const part of list.split(",")) {
        const glob = cleanGlob(part).replace(/\\/g, "/").replace(/^\.\//, "");
        if (glob && !glob.startsWith("/") && !glob.split("/").includes("..") && paths.length < MAX_SCOPE_PATHS) paths.push(glob);
      }
      return " ";
    });
    let until: string | undefined;
    let badDate: string | undefined;
    body = body.replace(/\(\s*until\s+([^)]*)\)/gi, (_all, value: string) => {
      const date = value.trim();
      if (validDate(date)) until = date; else badDate = date;
      return " ";
    });
    const cleaned = cleanScopeText(body, 2000);
    const split = /^(.*?)\s*(?::|\s[-–—]\s)\s*(.*)$/.exec(cleaned);
    const vector = cleanScopeText(split ? split[1]! : cleaned, MAX_SCOPE_VECTOR_CHARS);
    const reason = cleanScopeText(split ? split[2]! : "", MAX_SCOPE_REASON_CHARS);
    if (!vector) { warnings.push(`line ${line}: an empty entry was ignored`); continue; }
    if (badDate !== undefined) { warnings.push(`line ${line}: '${cleanScopeText(badDate, 30)}' is not a date (YYYY-MM-DD); the entry '${vector}' was ignored`); continue; }
    if (entries.length >= MAX_SCOPE_ENTRIES) { overflow = true; continue; }
    const category = categoryFromLabel(vector);
    const key = `${kind}|${category ?? vector.toLowerCase()}|${pathKey(paths)}|${until ?? ""}`;
    if (seen.has(key)) { warnings.push(`line ${line}: '${vector}' repeats an earlier entry; the first one counts`); continue; }
    seen.add(key);
    const entry: ScopeEntry = { kind, vector, ...(category ? { category } : {}), reason, ...(until ? { until } : {}), paths, line };
    entries.push(entry);
    last = entry;
    if (kind === "out" && isAlwaysInScope(category)) warnings.push(`line ${line}: '${vector}' declared out of scope: this class is usually a real vulnerability`);
    if (!category) { unmatched.push(entry); warnings.push(`unmatched scope entry (line ${line}): '${vector}' names no vulnerability category I know; it labels nothing. Use a category id such as denial-of-service or broken-access-control`); }
  }
  if (overflow) warnings.push(`more than ${MAX_SCOPE_ENTRIES} entries; the rest were ignored`);
  if (skipped) warnings.push(`${skipped} bullet${skipped === 1 ? "" : "s"} outside an 'In scope' or 'Out of scope' heading ${skipped === 1 ? "was" : "were"} ignored`);
  const conflicts = entries.filter(e => e.kind === "in" && e.category && !e.paths.length && entries.some(o => o.kind === "out" && o.category === e.category && !o.paths.length));
  for (const entry of conflicts) warnings.push(`'${entry.vector}' is both in scope and out of scope; in scope wins`);
  return { found: true, entries, warnings, unmatched };
}

/** Whether an entry no longer applies on `now`. An entry applies through the end of its `until` day (UTC). */
export function scopeEntryExpired(entry: Pick<ScopeEntry, "until">, now: Date | number = Date.now()): boolean {
  if (!entry.until) return false;
  return (typeof now === "number" ? now : now.getTime()) >= Date.parse(`${entry.until}T00:00:00Z`) + 24 * 3600 * 1000;
}

/** A path glob as a regular expression: `**` any depth, `*` within a folder, `?` one character. A bare folder name covers what is under it. */
export function globToRegExp(glob: string): RegExp {
  let pattern = glob.replace(/\\/g, "/").replace(/^\.\//, "").replace(/\/+$/, "/**");
  if (!/[*?]/.test(pattern) && !/\.[A-Za-z0-9]+$/.test(pattern.split("/").pop() ?? "")) pattern = `${pattern}/**`;
  let out = "";
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]!;
    if (ch === "*") {
      if (pattern[i + 1] === "*") { i++; if (pattern[i + 1] === "/") { i++; out += "(?:.*/)?"; } else out += ".*"; }
      else out += "[^/]*";
    } else if (ch === "?") out += "[^/]";
    else out += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${out}$`);
}

const pathMatches = (paths: readonly string[], path: string | undefined): boolean => {
  if (!paths.length) return true;
  if (!path) return false;
  const value = path.replace(/\\/g, "/").replace(/^\.\//, "");
  return paths.some(glob => globToRegExp(glob).test(value));
};

/** Categories a declared category also covers: a regular-expression denial of service is a denial of service. */
const COVERS: Partial<Record<AttackCategory, readonly AttackCategory[]>> = { "denial-of-service": ["regex-dos"] };

const covers = (declared: AttackCategory, found: string): boolean => declared === found || (COVERS[declared] ?? []).includes(found as AttackCategory);

export interface ScopeSubject { category: string; path?: string }
export interface ScopeMatch { scope: "in-scope" | "out-of-scope"; entry: ScopeEntry }

/**
 * The declared entry that applies to a finding, or undefined. Entries that expired are ignored. An entry with paths
 * is more specific than one without; among equally specific entries an in-scope one wins, so nothing is labelled
 * out of scope when the team also said it cares.
 */
export function matchesScope(finding: ScopeSubject, entries: readonly ScopeEntry[], now: Date | number = Date.now()): ScopeMatch | undefined {
  const hits = entries.filter(entry => entry.category && covers(entry.category, finding.category) && !scopeEntryExpired(entry, now) && pathMatches(entry.paths, finding.path));
  if (!hits.length) return undefined;
  const rank = (entry: ScopeEntry) => (entry.paths.length ? 2 : 0) + (entry.kind === "in" ? 1 : 0);
  const best = hits.reduce((a, b) => (rank(b) > rank(a) ? b : a));
  return { scope: best.kind === "in" ? "in-scope" : "out-of-scope", entry: best };
}

export interface ScopeLabelled { scope?: "in-scope" | "out-of-scope"; scopeReason?: string; scopeSource?: string }

/** A finding with its scope label. Findings no entry names are returned unchanged. */
export function labelWithScope<T extends { category: string; reviewAnnotation?: { path: string } }>(finding: T, entries: readonly ScopeEntry[], source: string, now: Date | number = Date.now()): T & ScopeLabelled {
  const match = matchesScope({ category: finding.category, ...(finding.reviewAnnotation ? { path: finding.reviewAnnotation.path } : {}) }, entries, now);
  if (!match) return finding;
  return { ...finding, scope: match.scope, scopeReason: match.entry.reason || "no reason given", scopeSource: source };
}

export const isOutOfScope = (finding: { scope?: string | null }): boolean => finding.scope === "out-of-scope";

/** In-scope (declared or not) first, then out of scope; the order within each part is kept. */
export function splitByScope<T extends { scope?: string | null }>(findings: readonly T[]): { inScope: T[]; outOfScope: T[] } {
  return { inScope: findings.filter(f => !isOutOfScope(f)), outOfScope: findings.filter(isOutOfScope) };
}

/** The findings in report order: in scope first (those that match a declared in-scope entry before the rest), then out of scope. Each part is sorted by `compare`. */
export function orderByScope<T extends { scope?: string | null }>(findings: readonly T[], compare: (a: T, b: T) => number): T[] {
  const { inScope, outOfScope } = splitByScope(findings);
  const declared = (finding: T) => (finding.scope === "in-scope" ? 0 : 1);
  return [...inScope].sort((a, b) => declared(a) - declared(b) || compare(a, b)).concat([...outOfScope].sort(compare));
}

function sanitizeEntryPaths(paths: readonly string[]): string[] {
  return paths
    .map(p => cleanGlob(p).replace(/\\/g, "/").replace(/^\.\//, ""))
    .filter(p => Boolean(p) && !/[,[\]\s]/.test(p) && !p.startsWith("/") && !p.split("/").includes(".."))
    .slice(0, MAX_SCOPE_PATHS);
}

/** Fail closed: an entry whose paths were all rejected would render without paths, which means the whole repository. */
const keepsItsPaths = (entry: Pick<ScopeEntry, "paths">): boolean => entry.paths.length === 0 || sanitizeEntryPaths(entry.paths).length > 0;

/** The Markdown of a Scope section for these entries, in the format `parseScope` reads. */
export function renderScopeSection(entries: readonly Pick<ScopeEntry, "kind" | "vector" | "reason" | "until" | "paths">[]): string {
  const part = (title: string, kind: ScopeKind) => {
    const items = entries.filter(entry => entry.kind === kind && keepsItsPaths(entry));
    return [`### ${title}`, "", ...(items.length ? items.map(scopeBullet) : ["_Nothing declared._"]), ""];
  };
  return ["## Scope", "", ...part("In scope", "in"), ...part("Out of scope", "out")].join("\n");
}

/** One entry as a bullet line, in the format `parseScope` reads. */
export function scopeBullet(entry: Pick<ScopeEntry, "vector" | "reason" | "until" | "paths">): string {
  const safePaths = sanitizeEntryPaths(entry.paths);
  return `- ${cleanScopeText(entry.vector, MAX_SCOPE_VECTOR_CHARS)}: ${cleanScopeText(entry.reason, MAX_SCOPE_REASON_CHARS) || "not given"}${entry.until ? ` (until ${entry.until})` : ""}${safePaths.length ? ` [paths: ${safePaths.join(", ")}]` : ""}`;
}

/**
 * The text with these entries added to its `## Scope` section: each goes at the end of its `### In scope` or
 * `### Out of scope` list, and a missing list or section is created. Nothing else changes, byte for byte, and
 * the text the person already wrote in the section stays. An entry the section already holds (same side, vector
 * and paths) is not added again.
 */
export function addScopeEntries(text: string, entries: readonly Pick<ScopeEntry, "kind" | "vector" | "reason" | "until" | "paths">[]): string {
  const existing = parseScope(text);
  const same = (a: Pick<ScopeEntry, "kind" | "vector" | "paths">, b: Pick<ScopeEntry, "kind" | "vector" | "paths">) =>
    a.kind === b.kind && (categoryFromLabel(a.vector) ?? a.vector.toLowerCase()) === (categoryFromLabel(b.vector) ?? b.vector.toLowerCase()) && pathKey(a.paths) === pathKey(b.paths);
  const fresh = entries.filter((entry, index) => keepsItsPaths(entry) && !existing.entries.some(old => same(old, entry)) && !entries.slice(0, index).some(earlier => same(earlier, entry)));
  if (!fresh.length) return text;
  if (!existing.found) return replaceScopeSection(text, renderScopeSection(fresh));
  const eol = dominantEol(text);
  const parts = text.split(/(\r\n|\r|\n)/);
  // Lines with their endings kept: [text, ending].
  const lines: Array<[string, string]> = [];
  for (let i = 0; i < parts.length; i += 2) lines.push([parts[i]!, parts[i + 1] ?? ""]);
  let fence: string | undefined;
  let start = -1;
  let end = lines.length;
  const sub: Partial<Record<ScopeKind, { heading: number; last: number }>> = {};
  let current: ScopeKind | undefined;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]![0];
    const fenced = /^\s{0,3}(`{3,}|~{3,})/.exec(line);
    if (fenced) { fence = fence === undefined ? fenced[1]![0] : fence === fenced[1]![0] ? undefined : fence; if (start >= 0 && current) sub[current]!.last = i; continue; }
    if (fence !== undefined) { if (start >= 0 && current) sub[current]!.last = i; continue; }
    const heading = HEADING.exec(line);
    if (start < 0) { if (heading && heading[1]!.length === 2 && /^scope$/i.test(cleanScopeText(heading[2]!, 80))) { start = i; } continue; }
    if (heading && heading[1]!.length <= 2) { end = i; break; }
    if (heading) {
      const kind = sectionKind(cleanScopeText(heading[2]!, 80));
      current = kind;
      if (kind && !sub[kind]) sub[kind] = { heading: i, last: i };
      continue;
    }
    if (current && line.trim()) sub[current]!.last = i;
  }
  // The last non-blank line of the whole section, where a new list goes.
  let tail = start;
  for (let i = start + 1; i < end; i++) if (lines[i]![0].trim()) tail = i;
  const inserts: Array<{ after: number; add: string[]; created?: boolean }> = [];
  const create: string[] = [];
  for (const [kind, title] of [["in", "In scope"], ["out", "Out of scope"]] as const) {
    const add = fresh.filter(entry => entry.kind === kind).map(scopeBullet);
    if (!add.length) continue;
    const found = sub[kind];
    if (found) inserts.push({ after: found.last, add });
    else create.push("", `### ${title}`, "", ...add);
  }
  if (create.length) inserts.push({ after: tail, add: create, created: true });
  // Later positions first; at the same position a new list goes in first, so entries added to an existing list land above it.
  inserts.sort((a, b) => b.after - a.after || (a.created ? -1 : 0) - (b.created ? -1 : 0));
  for (const { after, add } of inserts) {
    const row = lines[after]!;
    // The line we insert after may be the file's last, with no ending: give it one.
    const ending = row[1] || eol;
    lines[after] = [row[0], ending];
    const last = after === lines.length - 1 && !row[1];
    lines.splice(after + 1, 0, ...add.map((line, index): [string, string] => [line, last && index === add.length - 1 ? "" : eol]));
  }
  return lines.map(([body, ending]) => body + ending).join("");
}

/** The line ending a text uses most (CRLF when it has more CRLF than bare LF), or LF for a text with none. */
export function dominantEol(text: string): "\r\n" | "\n" {
  const crlf = (text.match(/\r\n/g) ?? []).length;
  const lf = (text.match(/\n/g) ?? []).length - crlf;
  return crlf > lf ? "\r\n" : "\n";
}

/**
 * The text with its `## Scope` section replaced by `section` (or the section appended when there is none).
 * Every byte outside the old section stays as it was, including line endings; the new section uses the file's
 * own line ending. The section ends at the next heading of level 1 or 2.
 */
export function replaceScopeSection(text: string, section: string): string {
  const eol = dominantEol(text);
  const body = `${section.replace(/\r?\n+$/, "").replace(/\r?\n/g, eol)}${eol}`;
  const parts = text.split(/(\r\n|\r|\n)/); // text, eol, text, eol, ...
  let offset = 0;
  let fence: string | undefined;
  let start = -1;
  let end = text.length;
  for (let i = 0; i < parts.length; i += 2) {
    const line = parts[i]!;
    const lineStart = offset;
    offset += line.length + (parts[i + 1]?.length ?? 0);
    const fenced = /^\s{0,3}(`{3,}|~{3,})/.exec(line);
    if (fenced) { fence = fence === undefined ? fenced[1]![0] : fence === fenced[1]![0] ? undefined : fence; continue; }
    if (fence !== undefined) continue;
    const heading = HEADING.exec(line);
    if (!heading) continue;
    if (start < 0) { if (heading[1]!.length === 2 && /^scope$/i.test(cleanScopeText(heading[2]!, 80))) start = lineStart; }
    else if (heading[1]!.length <= 2) { end = lineStart; break; }
  }
  if (start < 0) {
    if (!text) return body;
    const tail = text.endsWith("\n") || text.endsWith("\r") ? "" : eol;
    return `${text}${tail}${eol}${body}`;
  }
  const after = text.slice(end);
  return `${text.slice(0, start)}${body}${after ? eol : ""}${after}`;
}
