/**
 * Business context for ranking: a small JSON file you write that says which parts of your code matter more or less
 * to your organisation. `0 findings list --context <file>` uses it to order findings and to say why.
 *
 * It only changes the order and adds a line of explanation. It never changes a finding's severity, hides a
 * finding or changes what may run. The file is read only from the path you name, never from a scanned repository.
 */
import { readFileSync, statSync } from "node:fs";
import { UsageError } from "./commands/output.js";

/** Tags and how many severity steps each moves a finding. Raise by one: critical stays critical, low becomes medium. */
export const DEFAULT_WEIGHTS = {
  "internet-facing": 1,
  "payments": 1,
  "personal-data": 1,
  "operationally-critical": 1,
  "internal-only": -1,
  "non-production": -2,
} as const;
export type ContextTag = keyof typeof DEFAULT_WEIGHTS;
export const CONTEXT_TAGS = Object.keys(DEFAULT_WEIGHTS) as ContextTag[];
/** However many tags match, the order moves at most this many severity steps either way. */
export const MAX_SHIFT = 2;
const MAX_FILE_BYTES = 64 * 1024;
const MAX_ENTRIES = 500;
const SEVERITY_STEPS: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export interface ContextEntry {
  /** A path or glob such as src/payments/** or services/billing. Without it the entry applies to every finding. */
  match?: string;
  tags: ContextTag[];
  note?: string;
}
export interface BusinessContext {
  entries: ContextEntry[];
  weights: Record<ContextTag, number>;
}

export interface ContextAdjustment {
  /** Severity steps the order moves: positive raises, negative lowers. */
  shift: number;
  tags: ContextTag[];
  notes: string[];
}

const line = (text: string): string => text.replace(/[\u0000-\u001f\u007f\u2028\u2029]+/g, " ").replace(/\s+/g, " ").trim();

export function parseBusinessContext(text: string, label = "context file"): BusinessContext {
  let value: unknown;
  try { value = JSON.parse(text); } catch { throw new UsageError(`${label} is not valid JSON.`); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new UsageError(`${label} must be a JSON object with an "entries" list.`);
  const obj = value as Record<string, unknown>;
  for (const key of Object.keys(obj)) if (key !== "entries" && key !== "weights") throw new UsageError(`${label}: "${key.slice(0, 40)}" is not a setting. Use entries and weights.`);
  if (!Array.isArray(obj.entries) || obj.entries.length > MAX_ENTRIES) throw new UsageError(`${label}: "entries" must be a list of at most ${MAX_ENTRIES}.`);
  const weights = { ...DEFAULT_WEIGHTS } as Record<ContextTag, number>;
  if (obj.weights !== undefined) {
    if (!obj.weights || typeof obj.weights !== "object" || Array.isArray(obj.weights)) throw new UsageError(`${label}: "weights" must be an object of tag to a whole number.`);
    for (const [tag, weight] of Object.entries(obj.weights)) {
      if (!CONTEXT_TAGS.includes(tag as ContextTag)) throw new UsageError(`${label}: "${tag.slice(0, 40)}" is not a tag. Use ${CONTEXT_TAGS.join(", ")}.`);
      if (!Number.isInteger(weight) || Math.abs(weight as number) > MAX_SHIFT) throw new UsageError(`${label}: the weight of ${tag} must be a whole number from -${MAX_SHIFT} to ${MAX_SHIFT}.`);
      weights[tag as ContextTag] = weight as number;
    }
  }
  const entries = obj.entries.map((raw, index): ContextEntry => {
    const where = `${label}: entries[${index}]`;
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new UsageError(`${where} must be an object.`);
    const entry = raw as Record<string, unknown>;
    for (const key of Object.keys(entry)) if (key !== "match" && key !== "tags" && key !== "note") throw new UsageError(`${where}: "${key.slice(0, 40)}" is not a setting. Use match, tags and note.`);
    if (entry.match !== undefined && (typeof entry.match !== "string" || !entry.match.trim() || entry.match.length > 200)) throw new UsageError(`${where}: match must be a path or glob of at most 200 characters.`);
    if (!Array.isArray(entry.tags) || !entry.tags.length) throw new UsageError(`${where}: tags must be a non-empty list from ${CONTEXT_TAGS.join(", ")}.`);
    const tags = entry.tags.map(tag => {
      if (typeof tag !== "string" || !CONTEXT_TAGS.includes(tag as ContextTag)) throw new UsageError(`${where}: "${String(tag).slice(0, 40)}" is not a tag. Use ${CONTEXT_TAGS.join(", ")}.`);
      return tag as ContextTag;
    });
    if (entry.note !== undefined && (typeof entry.note !== "string" || entry.note.length > 200)) throw new UsageError(`${where}: note must be text of at most 200 characters.`);
    return { ...(entry.match !== undefined ? { match: (entry.match as string).trim() } : {}), tags: [...new Set(tags)], ...(entry.note ? { note: line(entry.note as string) } : {}) };
  });
  return { entries, weights };
}

/** Reads the file you named. It must be a regular file of at most 64 KB. */
export function loadBusinessContext(path: string): BusinessContext {
  let stat;
  try { stat = statSync(path); } catch { throw new UsageError(`--context ${path} does not exist.`); }
  if (!stat.isFile() || stat.size > MAX_FILE_BYTES) throw new UsageError(`--context must name a file of at most ${MAX_FILE_BYTES / 1024} KB.`);
  return parseBusinessContext(readFileSync(path, "utf8"), path);
}

/** A glob over a repository-relative path: ** crosses folders, * and ? stay inside one. A name with no wildcard also covers what is under it. */
function globTest(pattern: string): (path: string) => boolean {
  const clean = pattern.replace(/^\.?\//, "").replace(/\/+$/, "");
  if (!/[*?]/.test(clean)) return path => path === clean || path.startsWith(`${clean}/`);
  let source = "";
  for (let i = 0; i < clean.length; i++) {
    const c = clean[i]!;
    if (c === "*" && clean[i + 1] === "*") {
      if (clean[i + 2] === "/") { source += "(?:.*/)?"; i += 2; } else { source += ".*"; i += 1; }
    } else if (c === "*") source += "[^/]*";
    else if (c === "?") source += "[^/]";
    else source += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  const expression = new RegExp(`^${source}$`);
  return path => expression.test(path);
}

/** The file a finding points at, from its stored review annotation. */
export function findingPath(reviewAnnotation: unknown): string | undefined {
  let value = reviewAnnotation;
  if (typeof value === "string") { try { value = JSON.parse(value); } catch { return undefined; } }
  const path = value && typeof value === "object" ? (value as { path?: unknown }).path : undefined;
  return typeof path === "string" && path ? path.replace(/\\/g, "/").replace(/^\.?\//, "") : undefined;
}

/** What the context says about a finding in `path`. An entry with no `match` applies to every finding; one with `match` needs a path. */
export function adjustmentFor(context: BusinessContext, path: string | undefined): ContextAdjustment {
  const tags = new Set<ContextTag>();
  const notes: string[] = [];
  for (const entry of context.entries) {
    if (entry.match !== undefined && (path === undefined || !globTest(entry.match)(path))) continue;
    for (const tag of entry.tags) tags.add(tag);
    if (entry.note) notes.push(entry.note);
  }
  const total = [...tags].reduce((sum, tag) => sum + context.weights[tag], 0);
  return { shift: Math.max(-MAX_SHIFT, Math.min(MAX_SHIFT, total)), tags: [...tags], notes: [...new Set(notes)] };
}

/** Severity steps plus the shift. Larger sorts first. Unknown severities stay below every known one. */
export function contextScore(severity: string, adjustment: ContextAdjustment): number {
  const base = SEVERITY_STEPS[severity.toLowerCase()];
  return base === undefined ? -10 : base + adjustment.shift;
}

/** One line for the list: what moved the finding and why. Empty when the context says nothing about it. */
export function describeAdjustment(adjustment: ContextAdjustment): string {
  if (!adjustment.tags.length) return "";
  const direction = adjustment.shift > 0 ? `ranked higher (+${adjustment.shift})` : adjustment.shift < 0 ? `ranked lower (${adjustment.shift})` : "rank unchanged";
  return `${direction}: ${adjustment.tags.join(", ")}${adjustment.notes.length ? `. ${adjustment.notes.join(" ")}` : ""}`;
}
