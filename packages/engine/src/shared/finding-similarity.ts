/**
 * When two findings are the same flaw reported twice (by two passes, two batches or two runs).
 *
 * Deliberately conservative: two findings are one flaw only when they cite the same file, their categories agree
 * (or they share a CWE), and their cited lines overlap. Lines that are close but do not overlap merge only when the
 * titles also read alike (`nearWithoutTitle` drops that condition, for two passes citing neighbouring lines of one file).
 * Findings in different files or different categories are never merged. A merge hides no finding: the merged one keeps
 * the highest severity and lists the ids it absorbed.
 */
import { classifyFinding } from "./finding-category.js";

export interface SimilarityInput {
  title: string;
  category: string;
  description?: string;
  /** CWE ids the finding carries, if any ("CWE-89"). Also read from a "CWE: ..." tag in `evidenceAnalysis`. */
  cwe?: readonly string[];
  evidenceAnalysis?: string;
  location?: { path: string; startLine: number; endLine?: number };
}

/** A cited range longer than this many lines is too broad to prove two findings are the same flaw by itself. */
export const WIDE_RANGE = 40;
const WIDE_RANGE_TITLE_SIMILARITY = 0.25;
const span = (l: NonNullable<SimilarityInput["location"]>): number => (l.endLine !== undefined && l.endLine >= l.startLine ? l.endLine : l.startLine) - l.startLine + 1;

/** Lines apart that still count as one place when the titles read alike. */
export const NEAR_LINE_GAP = 3;
/** Title similarity (0 to 1) two findings need to merge when their lines are near but do not overlap. */
export const NEAR_TITLE_SIMILARITY = 0.4;

const STOP = new Set(["a", "an", "the", "in", "on", "of", "to", "via", "by", "for", "and", "or", "is", "are", "can", "may", "that", "with", "from", "into", "at", "as", "be", "any", "all", "allows", "allow", "permits", "permit", "enables", "enable", "leads", "lead", "lets", "let", "unauthenticated", "authenticated", "public", "user", "users"]);

const stem = (word: string): string => word.replace(/(ing|ed|es|s)$/, "");

/** The words of a title that carry meaning, lowercased and lightly stemmed. */
export function titleTokens(title: string): Set<string> {
  const out = new Set<string>();
  for (const word of title.toLowerCase().split(/[^a-z0-9$]+/)) if (word.length > 1 && !STOP.has(word)) out.add(stem(word));
  return out;
}

/** Share of meaningful title words two titles have in common (Jaccard), 0 to 1. */
export function titleSimilarity(a: string, b: string): number {
  const x = titleTokens(a), y = titleTokens(b);
  if (!x.size || !y.size) return 0;
  let shared = 0;
  for (const word of x) if (y.has(word)) shared++;
  return shared / (x.size + y.size - shared);
}

function cwesOf(input: SimilarityInput): Set<number> {
  const out = new Set<number>();
  const take = (text: string): void => { for (const m of text.matchAll(/cwe[-_/ :]*0*(\d{1,5})\b/gi)) out.add(Number(m[1])); };
  for (const value of input.cwe ?? []) take(value);
  if (input.evidenceAnalysis) take(input.evidenceAnalysis.slice(0, 400));
  return out;
}

/** The category a finding is compared under: the same normalizer a new finding goes through. */
export function comparableCategory(input: SimilarityInput): string {
  return classifyFinding({ category: input.category, title: input.title, description: input.description, cwe: [...cwesOf(input)].map(n => `CWE-${n}`) }).category;
}

/** True when the cited lines overlap (gap 0) or lie within `gap` lines of each other. Same file only. */
export function linesWithin(a: NonNullable<SimilarityInput["location"]>, b: NonNullable<SimilarityInput["location"]>, gap: number): boolean {
  if (a.path !== b.path) return false;
  const aEnd = a.endLine !== undefined && a.endLine >= a.startLine ? a.endLine : a.startLine;
  const bEnd = b.endLine !== undefined && b.endLine >= b.startLine ? b.endLine : b.startLine;
  return a.startLine <= bEnd + gap && b.startLine <= aEnd + gap;
}

/** Same flaw: same file, same category (or a shared CWE), overlapping lines, or near lines with alike titles. */
export function sameFlaw(a: SimilarityInput, b: SimilarityInput, options: { minOverlapTitle?: number; nearWithoutTitle?: boolean } = {}): boolean {
  if (!a.location || !b.location || a.location.path !== b.location.path) return false;
  const sameCategory = comparableCategory(a) === comparableCategory(b);
  if (!sameCategory) {
    const cb = cwesOf(b);
    if (![...cwesOf(a)].some(n => cb.has(n))) return false;
  }
  const similarity = titleSimilarity(a.title, b.title);
  if (linesWithin(a.location, b.location, 0)) {
    // Overlapping lines in one category are one flaw, however the two reports word it. A cited range wider than a
    // handler (a whole file, a long block) overlaps many flaws, so then the titles must agree too.
    const wide = span(a.location) > WIDE_RANGE || span(b.location) > WIDE_RANGE;
    return similarity >= Math.max(options.minOverlapTitle ?? 0, wide ? WIDE_RANGE_TITLE_SIMILARITY : 0);
  }
  return linesWithin(a.location, b.location, NEAR_LINE_GAP) && (options.nearWithoutTitle === true || similarity >= NEAR_TITLE_SIMILARITY);
}
