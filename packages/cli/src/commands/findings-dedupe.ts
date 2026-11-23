/**
 * The grouped findings list shows one line per flaw. A group is a fingerprint, and a fingerprint hashes the title and
 * the evidence text, which a model words differently on every run. So the same flaw found by two runs is two groups.
 * This folds such groups into the first (most severe) one when they cite the same file and category at overlapping
 * lines. Groups with different triage state never fold, so a suppressed finding cannot hide a new one.
 */
import { sameFlaw, type SimilarityInput } from "@0/engine/shared";

export interface GroupRow {
  title: string;
  category: string;
  description?: string | null;
  evidenceAnalysis?: string | null;
  reviewAnnotation?: unknown;
  triageStatus?: string | null;
}

export interface FoldableGroup<R extends GroupRow> { latest: R; count: number; scans: number; fingerprint: string; similar?: number }

function locationOf(value: unknown): SimilarityInput["location"] | undefined {
  let annotation = value;
  if (typeof annotation === "string") { try { annotation = JSON.parse(annotation); } catch { return undefined; } }
  if (!annotation || typeof annotation !== "object") return undefined;
  const { path, startLine, endLine } = annotation as { path?: unknown; startLine?: unknown; endLine?: unknown };
  if (typeof path !== "string" || !path || typeof startLine !== "number") return undefined;
  return { path, startLine, ...(typeof endLine === "number" ? { endLine } : {}) };
}

const asInput = (row: GroupRow): SimilarityInput => {
  const location = locationOf(row.reviewAnnotation);
  return { title: row.title, category: row.category, description: row.description ?? undefined, evidenceAnalysis: row.evidenceAnalysis ?? undefined, ...(location ? { location } : {}) };
};

/** Folds near-duplicate groups into the first of them. The input order (most severe first) decides which one stays. */
export function foldSimilarGroups<R extends GroupRow, G extends FoldableGroup<R>>(groups: readonly G[]): G[] {
  const kept: G[] = [];
  for (const group of groups) {
    const input = asInput(group.latest);
    const into = input.location ? kept.find(other => (other.latest.triageStatus ?? "new") === (group.latest.triageStatus ?? "new") && sameFlaw(asInput(other.latest), input)) : undefined;
    if (into) {
      into.count += group.count;
      into.scans += group.scans;
      into.similar = (into.similar ?? 0) + 1;
    } else kept.push({ ...group });
  }
  return kept;
}
