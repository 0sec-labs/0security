/**
 * The finding-derived half of `0 threat-model --interview`.
 *
 * A scan of the folder (from the findings database, a saved `0 scan --format json` report, or one run on the spot) tells which
 * vulnerability classes actually came up. This module turns them into one question per class, from templates: the
 * text is built here from the class, the places, the count and the highest severity, and never from a finding's title or
 * description, so text a hostile repository put in a finding cannot reach the person's screen as a question.
 *
 * It also merges these with the questions the model wrote from reading the code, and holds the one-line hint `0 scan` prints.
 */
import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, relative } from "node:path";
import {
  ALWAYS_IN_SCOPE_CATEGORIES, classifyFinding, isAlwaysInScope, matchesScope, MAX_INTERVIEW_QUESTIONS, SCOPE_QUESTION_CATEGORIES, parseScope,
  type AttackCategory, type ScopeEntry,
} from "@0/engine/shared";
import { listOsecRunDatabasePaths, osecDB, resolveOsecDbPath } from "@0/engine/storage";
import { listSessions } from "./state/session-store.js";
import { readRepoScopeFile } from "./scan-steering.js";
import type { InterviewQuestion } from "./threat-interview.js";

export const MAX_REPORT_BYTES = 8 * 1024 * 1024;
export const MAX_REPORT_FINDINGS = 5000;
export const MAX_SCAN_AGE_DAYS = 30;
/** Scan threads of one folder that started this close together count as one scan (passes and batches). */
const SAME_SCAN_MS = 30 * 60 * 1000;
export const MAX_PLACES = 5;

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const severityRank = (severity: string | undefined): number => (severity ? 5 - Math.max(0, SEVERITIES.indexOf(severity as typeof SEVERITIES[number])) : 0);

/** What the interview keeps of a finding: the class, how bad, where, and whether a scope already labelled it. */
export interface ScanFinding { severity: string; category: AttackCategory; path?: string; line?: number; endLine?: number; scope?: string }
export interface ScanSnapshot { findings: ScanFinding[]; source: "database" | "report" | "new"; label: string }

const PLACE_PATH = /^[A-Za-z0-9_@+./ -]{1,200}$/;

/** A path as a report or database holds it, made relative to the folder; undefined when it is not a plain path inside it. */
function relativePath(raw: unknown, folder: string): string | undefined {
  if (typeof raw !== "string") return undefined;
  let path = raw.replace(/\\/g, "/").replace(/^\.\//, "");
  if (isAbsolute(path)) {
    const inside = relative(folder, path).replace(/\\/g, "/");
    if (inside.startsWith("..") || isAbsolute(inside)) return undefined;
    path = inside;
  }
  return PLACE_PATH.test(path) && !path.split("/").includes("..") && !path.startsWith("/") ? path : undefined;
}

const keepLine = (value: unknown): number | undefined => (typeof value === "number" && Number.isInteger(value) && value > 0 && value < 10_000_000 ? value : undefined);

/** Findings a person already dealt with are not asked about again. */
const settled = (item: { status?: unknown; triageStatus?: unknown }): boolean => item.status === "false-positive" || item.triageStatus === "suppressed" || item.triageStatus === "accepted";

/**
 * The findings of a `0 scan --format json` report. Throws an error whose message says what is wrong, for a file that is
 * too big, not JSON, or not a report. Items that are not findings are skipped.
 */
export function findingsFromReport(text: string, folder: string): ScanFinding[] {
  if (text.length > MAX_REPORT_BYTES) throw new Error(`the report is larger than ${MAX_REPORT_BYTES / 1024 / 1024} MB`);
  let data: unknown;
  try { data = JSON.parse(text); } catch { throw new Error("the file is not JSON"); }
  const list = typeof data === "object" && data !== null ? (data as { findings?: unknown }).findings : undefined;
  if (!Array.isArray(list)) throw new Error("the file has no findings list; give a report from 0 scan --format json");
  if (list.length > MAX_REPORT_FINDINGS) throw new Error(`the report has more than ${MAX_REPORT_FINDINGS} findings`);
  const out: ScanFinding[] = [];
  for (const raw of list) {
    if (typeof raw !== "object" || raw === null) continue;
    const item = raw as Record<string, unknown>;
    if (typeof item.title !== "string" || typeof item.severity !== "string" || !SEVERITIES.includes(item.severity as typeof SEVERITIES[number]) || settled(item)) continue;
    const location = typeof item.location === "object" && item.location !== null ? item.location as Record<string, unknown> : undefined;
    const path = relativePath(location?.path, folder);
    const line = keepLine(location?.startLine);
    const endLine = keepLine(location?.endLine);
    const category = classifyFinding({ category: item.category, title: item.title, description: typeof item.description === "string" ? item.description : "" }).category;
    out.push({ severity: item.severity, category, ...(path ? { path, ...(line ? { line, ...(endLine ? { endLine } : {}) } : {}) } : {}), ...(item.scope === "in-scope" || item.scope === "out-of-scope" ? { scope: item.scope } : {}) });
  }
  if (list.length && !out.length) throw new Error("none of the entries in the findings list is a finding");
  return out;
}

/** A report file the person named: checked for size before it is read. */
export function loadReportFile(path: string, folder: string): ScanSnapshot {
  let size: number;
  try { size = statSync(path).size; } catch { throw new Error(`${path} could not be read`); }
  if (!statSync(path).isFile()) throw new Error(`${path} is not a file`);
  if (size > MAX_REPORT_BYTES) throw new Error(`${path} is larger than ${MAX_REPORT_BYTES / 1024 / 1024} MB`);
  let text: string;
  try { text = readFileSync(path, "utf8"); } catch { throw new Error(`${path} could not be read`); }
  try { return { findings: findingsFromReport(text, folder), source: "report", label: path }; }
  catch (error) { throw new Error(`${path}: ${error instanceof Error ? error.message : String(error)}`); }
}

export interface DatabaseOptions { now: Date; home?: string; maxDatabases?: number }

/**
 * The findings of the latest scan of this folder, found the way the findings commands find them: scans keep one console
 * thread per pass or batch, whose working folder is the folder scanned; the findings are in the shared database or a run
 * database. Scan threads that started within 30 minutes of the newest one count as the same scan. Undefined when the
 * folder has no scan newer than 30 days, or the scan has no findings stored.
 */
export function latestScanFindings(folder: string, options: DatabaseOptions): ScanSnapshot | undefined {
  let real: string;
  try { real = realpathSync(folder); } catch { return undefined; }
  const scans = listSessions(options.home, { cwd: real }).filter(session => /^Scan\b/.test(session.summary ?? ""));
  const newest = scans[0];
  if (!newest || options.now.getTime() - newest.savedAt > MAX_SCAN_AGE_DAYS * 24 * 3600 * 1000) return undefined;
  const ids = new Set(scans.filter(session => newest.savedAt - session.savedAt <= SAME_SCAN_MS).map(session => session.id));
  const paths = [...new Set([resolveOsecDbPath(), ...listOsecRunDatabasePaths(options.home)])].filter(path => existsSync(path)).slice(0, options.maxDatabases ?? 200);
  const findings: ScanFinding[] = [];
  const seen = new Set<string>();
  let found = 0;
  for (const dbPath of paths) {
    if (found >= ids.size) break;
    let db: osecDB | undefined;
    try {
      db = new osecDB(dbPath);
      for (const id of ids) {
        const rows = db.getScanFindings(id) as Array<Record<string, unknown>>;
        if (!rows.length) continue;
        found++;
        for (const row of rows) {
          if (typeof row.title !== "string" || typeof row.severity !== "string" || settled(row)) continue;
          let annotation: Record<string, unknown> | undefined;
          try { const parsed: unknown = typeof row.reviewAnnotation === "string" ? JSON.parse(row.reviewAnnotation) : row.reviewAnnotation; if (typeof parsed === "object" && parsed !== null) annotation = parsed as Record<string, unknown>; } catch { /* no location */ }
          const path = relativePath(annotation?.path, real);
          const line = keepLine(annotation?.startLine);
          const endLine = keepLine(annotation?.endLine);
          const category = classifyFinding({ category: row.category, title: row.title, description: typeof row.description === "string" ? row.description : "" }).category;
          const key = `${category}|${path ?? ""}|${line ?? ""}|${row.title}`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push({ severity: SEVERITIES.includes(row.severity as typeof SEVERITIES[number]) ? row.severity : "info", category, ...(path ? { path, ...(line ? { line, ...(endLine ? { endLine } : {}) } : {}) } : {}), ...(row.scope === "in-scope" || row.scope === "out-of-scope" ? { scope: row.scope } : {}) });
        }
      }
    } catch { /* a database that cannot be read has no findings for us */ }
    finally { db?.close(); }
  }
  if (!findings.length) return undefined;
  const day = new Date(newest.savedAt).toISOString().slice(0, 10);
  return { findings, source: "database", label: `the scan of ${day}` };
}

// ── Questions from findings ──

/**
 * One entry per flaw: findings of the same class in the same file whose lines overlap or lie within three lines of each other
 * are one place (a scan's passes and rounds often cite the same code with different line ranges). The worst severity is kept.
 */
export function dedupeFindings(findings: readonly ScanFinding[]): ScanFinding[] {
  const out: ScanFinding[] = [];
  for (const finding of findings) {
    const start = finding.line, end = finding.endLine ?? finding.line;
    const same = start === undefined || finding.path === undefined ? undefined : out.find(other => other.category === finding.category && other.path === finding.path && other.line !== undefined
      && start <= (other.endLine ?? other.line) + 3 && other.line <= (end ?? start) + 3);
    if (!same) { out.push({ ...finding }); continue; }
    if (severityRank(finding.severity) > severityRank(same.severity)) same.severity = finding.severity;
    same.line = Math.min(same.line!, start!);
    same.endLine = Math.max(same.endLine ?? same.line, end ?? start!);
    if (finding.scope && !same.scope) same.scope = finding.scope;
  }
  return out;
}

const HASH = (text: string): number => [...text].reduce((sum, char) => sum + char.charCodeAt(0), 0);

interface Template { one: string; many: string; why: string; ask: readonly string[] }
const GENERIC_ASK = ["Do you want findings like these?", "Should 0 keep reporting issues like these?", "Is this something you want to hear about, or can it stay as it is?"] as const;
const TEMPLATES: Partial<Record<AttackCategory, Template>> = {
  "denial-of-service": { one: "denial-of-service issue", many: "denial-of-service issues", why: "One request can cost a lot or block other users.", ask: GENERIC_ASK },
  "regex-dos": { one: "regular-expression denial-of-service issue", many: "regular-expression denial-of-service issues", why: "A crafted input can keep a regular expression busy for a long time.", ask: GENERIC_ASK },
  "missing-rate-limit": { one: "place with no limit on attempts", many: "places with no limit on attempts", why: "Someone can try passwords, codes or requests as often as they like.", ask: ["Do you want findings about missing limits like these?", "Does your setup limit attempts somewhere else, so these can be left out?", "Should missing limits like these be reported?"] },
  "broken-access-control": { one: "missing access check", many: "missing access checks", why: "Some of these routes may be public on purpose.", ask: ["Do you want findings about missing access checks like these?", "Which of these should anyone be able to call? Do you want the rest reported?", "Should 0 report routes like these that anyone can reach?"] },
  "data-exfiltration": { one: "place where data may leave the system", many: "places where data may leave the system", why: "A field of personal or secret data may go to a third party.", ask: ["Is it fine for this data to go there, or do you want findings like these?", "Do you want findings about data leaving the system like this?", "Should data flows like these be reported?"] },
  "information-disclosure": { one: "place that gives away more than it should", many: "places that give away more than they should", why: "A response or log may show data the caller should not see.", ask: GENERIC_ASK },
  cors: { one: "open cross-origin setting", many: "open cross-origin settings", why: "Other websites can call the service from a browser.", ask: ["Is it intended that other sites can call this? Do you want findings like these?", ...GENERIC_ASK.slice(0, 2)] },
  "insecure-transport": { one: "link without encryption", many: "links without encryption", why: "Data travels in the clear.", ask: ["Is that fine in your setup, or do you want findings like these?", ...GENERIC_ASK.slice(0, 2)] },
  "policy-violation": { one: "place that conflicts with a rule", many: "places that conflict with a rule", why: "The code and a written rule disagree.", ask: ["Which is right, the rule or the code? Do you want findings like these?", ...GENERIC_ASK.slice(0, 2)] },
  "known-vulnerable-package": { one: "dependency with a known flaw", many: "dependencies with a known flaw", why: "An update may fix it.", ask: ["Do you want findings about dependencies like these?", "Is this a weakness you accept for now? Do you want findings like these?", "Should vulnerable dependencies like these be reported?"] },
};

/** `a.js:1, b.js:2, and 3 more`, or just the places when none are left over. */
export function placesText(places: readonly string[], count: number): string {
  const shown = places.slice(0, MAX_PLACES);
  const more = count - shown.length;
  if (!shown.length) return "";
  if (more > 0) return `${shown.join(", ")}, and ${more} more`;
  return shown.length > 1 ? `${shown.slice(0, -1).join(", ")} and ${shown[shown.length - 1]}` : shown[0]!;
}

const INTRO = [
  (n: string, where: string) => `This scan found ${n}${where}.`,
  (n: string, where: string) => `The scan reported ${n}${where}.`,
  (n: string, where: string) => `${n[0]!.toUpperCase()}${n.slice(1)} came up in this scan${where}.`,
] as const;

/** The question text for a class: counts, places, highest severity, a plain reason and a varied ask. */
export function findingQuestionText(category: AttackCategory, count: number, places: readonly string[], severity: string): string {
  const template = TEMPLATES[category];
  const noun = count === 1 ? template?.one ?? `${category.replace(/-/g, " ")} issue` : template?.many ?? `${category.replace(/-/g, " ")} issues`;
  const where = places.length ? ` (${placesText(places, count)})` : "";
  const intro = INTRO[(HASH(category) + 1) % INTRO.length]!(`${count} ${noun}`, where);
  const ask = template?.ask ?? GENERIC_ASK;
  return `${intro} Highest severity: ${severity}. ${template?.why ?? ""} ${ask[HASH(category) % ask.length]!}`.replace(/\s+/g, " ").trim();
}

const humanCovers = (humanText: readonly string[], category: string): boolean => {
  const text = humanText.join("\n").toLowerCase();
  return text.includes(category) || text.includes(category.replace(/-/g, " "));
};

export interface FindingQuestionOptions {
  declared: readonly ScopeEntry[];
  humanText: readonly string[];
  fileExists(relative: string): boolean;
  now: Date;
}
export interface FindingQuestions { questions: InterviewQuestion[]; skipped: string[] }

/**
 * One question per class that produced findings and may plausibly be out of scope. Always-in-scope classes, classes
 * SECURITY.md or a human block already covers, and findings a scope already labelled are skipped.
 */
export function findingQuestions(findings: readonly ScanFinding[], options: FindingQuestionOptions): FindingQuestions {
  const skipped: string[] = [];
  const groups = new Map<AttackCategory, ScanFinding[]>();
  const covered = new Set(options.declared.filter(entry => entry.category && !entry.paths.length).map(entry => entry.category!));
  for (const finding of dedupeFindings(findings)) {
    if (isAlwaysInScope(finding.category) || !SCOPE_QUESTION_CATEGORIES.includes(finding.category)) continue;
    if (covered.has(finding.category) || humanCovers(options.humanText, finding.category)) continue;
    if (finding.scope || matchesScope({ category: finding.category, ...(finding.path ? { path: finding.path } : {}) }, options.declared, options.now)) continue;
    const group = groups.get(finding.category);
    if (group) group.push(finding); else groups.set(finding.category, [finding]);
  }
  const questions: InterviewQuestion[] = [];
  for (const [category, group] of groups) {
    const ranked = [...group].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
    const places: string[] = [];
    const files: string[] = [];
    for (const finding of ranked) {
      if (!finding.path || !options.fileExists(finding.path)) continue;
      const place = finding.line ? `${finding.path}:${finding.line}` : finding.path;
      if (!places.includes(place)) places.push(place);
      if (!files.includes(finding.path)) files.push(finding.path);
    }
    const severity = ranked[0]!.severity;
    questions.push({
      id: `scan-${category}`, category, question: findingQuestionText(category, group.length, places, severity),
      ...(places[0] ? { evidence: places[0] } : {}), places: places.slice(0, MAX_PLACES), files, count: group.length, severity, from: "scan",
    });
  }
  return { questions, skipped };
}

const plausibility = (category: string): number => { const at = SCOPE_QUESTION_CATEGORIES.indexOf(category as AttackCategory); return at < 0 ? SCOPE_QUESTION_CATEGORIES.length : at; };

const parsePlace = (place: string): { path: string; start?: number; end?: number } => {
  const match = /^(.*?)(?::(\d+)(?:-(\d+))?)?$/.exec(place);
  const start = match?.[2] ? Number(match[2]) : undefined;
  return { path: match?.[1] ?? place, ...(start !== undefined ? { start, end: match?.[3] ? Number(match[3]) : start } : {}) };
};

/** Whether two places cite the same code: the same file and lines that overlap or lie within three lines (any line of a file counts when one has no line). */
const samePlace = (a: string, b: string): boolean => {
  const x = parsePlace(a), y = parsePlace(b);
  if (x.path !== y.path) return false;
  if (x.start === undefined || y.start === undefined) return true;
  return x.start <= y.end! + 3 && y.start <= x.end! + 3;
};

/**
 * One list from the finding-derived and the code-reading questions: one question per class (the finding-derived one wins
 * and gains the places the model named), no always-in-scope class, ordered by highest severity and then by how plausible
 * "out of scope" is, at most 8.
 */
export function mergeQuestions(fromFindings: readonly InterviewQuestion[], fromCode: readonly InterviewQuestion[], cap = MAX_INTERVIEW_QUESTIONS): InterviewQuestion[] {
  const byCategory = new Map<string, InterviewQuestion>();
  for (const question of fromFindings) if (!isAlwaysInScope(question.category) && !byCategory.has(question.category)) byCategory.set(question.category, { ...question });
  for (const question of fromCode) {
    if (isAlwaysInScope(question.category)) continue;
    const existing = byCategory.get(question.category);
    if (!existing) { byCategory.set(question.category, { ...question, from: "code" }); continue; }
    // A second question for a class adds its place to the first; the first question's wording stays.
    const path = question.evidence?.replace(/:\d+(?:-\d+)?$/, "");
    if (!question.evidence || !path) continue;
    if (existing.from === "scan") existing.from = "both";
    if (existing.count !== undefined) {
      const places = existing.places ?? [];
      if (!places.some(place => samePlace(place, question.evidence!)) && places.length < MAX_PLACES) {
        existing.places = [...places, question.evidence];
        existing.count += 1;
        existing.question = findingQuestionText(existing.category, existing.count, existing.places, existing.severity ?? "info");
      }
    }
    if (!(existing.files ?? []).includes(path)) existing.files = [...(existing.files ?? []), path];
  }
  return [...byCategory.values()]
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || plausibility(a.category) - plausibility(b.category))
    .slice(0, cap);
}

// ── The hint at the end of `0 scan` ──

/**
 * The one line `0 scan` prints when findings are in classes with no declared scope, or undefined. `declared` is the
 * categories a declared scope names (in or out).
 */
export function scopeHint(findings: ReadonlyArray<{ category: string }>, declared: ReadonlySet<string>): string | undefined {
  const counts = new Map<string, number>();
  for (const finding of findings) {
    if (ALWAYS_IN_SCOPE_CATEGORIES.has(finding.category) || !SCOPE_QUESTION_CATEGORIES.includes(finding.category as AttackCategory) || declared.has(finding.category)) continue;
    counts.set(finding.category, (counts.get(finding.category) ?? 0) + 1);
  }
  if (!counts.size) return undefined;
  const total = [...counts.values()].reduce((sum, n) => sum + n, 0);
  const names = [...counts.keys()].sort((a, b) => plausibility(a) - plausibility(b));
  const shown = names.slice(0, 3);
  const list = names.length > shown.length ? `${shown.join(", ")}, and ${names.length - shown.length} more` : shown.join(", ");
  return `${total} finding${total === 1 ? " is" : "s are"} in classes you have not declared in scope (${list}). Run 0security threat-model --interview to say which you care about.`;
}

/**
 * The hint for the end of a scan: only on a terminal, never in CI, never when a JSON report goes to standard output. The
 * declared scope is the one the scan used; without one, the folder's SECURITY.md is read as data to avoid suggesting what
 * it already declares, and it changes no finding.
 */
export function interactiveScopeHint(findings: ReadonlyArray<{ category: string }>, entries: ReadonlyArray<{ category?: string | undefined }>, folder: string | undefined, jsonToStdout: boolean): string | undefined {
  if (!findings.length || jsonToStdout || process.env.CI || !process.stdin.isTTY || !process.stderr.isTTY) return undefined;
  const declared = new Set(entries.map(entry => entry.category).filter((category): category is string => Boolean(category)));
  if (!entries.length && folder) {
    const text = readRepoScopeFile(folder);
    if (text) for (const entry of parseScope(text).entries) if (entry.category) declared.add(entry.category);
  }
  return scopeHint(findings, declared);
}
