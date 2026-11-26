import { parseStoredRootCause, type RootCause } from "@0/engine/shared";
import { osecDB } from "@0/engine/storage";
import { existsSync } from "node:fs";
import { shortFindingId } from "./finding-id.js";
import type { Host } from "./host/index.js";

export interface VariantLink { id: string; variantOf: string; status: string }

/** Fixed in a fix branch whose pull request has not been seen merged. Becomes `fixed` only after the merge is observed. */
export const VARIANT_FIXED_PENDING_MERGE = "fixed-pending-merge";

/**
 * Ask the code host whether the fix pull request of a finding was merged (the same `pullRequestState` read that
 * `findings export-fixes --check-merged` uses) and, only if one was, settle its pending variants.
 * `records` are the fix records for the finding from the fix state file.
 */
export async function settleFromFixPullRequests(
  findingId: string,
  records: ReadonlyArray<{ finding: string; pullRequestUrl?: string }>,
  host: Pick<Host, "pullRequestState">,
  dbPaths: readonly string[],
): Promise<{ settled: number; merged: boolean }> {
  for (const record of records) {
    if (record.finding !== findingId || !record.pullRequestUrl) continue;
    try {
      if ((await host.pullRequestState(record.pullRequestUrl)).state === "merged") return { settled: settleVariantsOfMergedFix(findingId, dbPaths), merged: true };
    } catch { /* an unreadable pull request is not a merge */ }
  }
  return { settled: 0, merged: false };
}

/**
 * Flip the variants of a finding from `fixed-pending-merge` to `fixed`. Call it only after the finding's fix pull
 * request was observed merged. Returns how many variants changed.
 */
export function settleVariantsOfMergedFix(findingId: string, dbPaths: readonly string[]): number {
  let settled = 0;
  for (const path of dbPaths) {
    if (typeof path !== "string" || !existsSync(path)) continue;
    let db: osecDB | undefined;
    try {
      db = new osecDB(path);
      for (const link of db.listVariantLinks()) {
        if (link.variantOf === findingId && link.status === VARIANT_FIXED_PENDING_MERGE) { db.updateFindingStatus(link.id, "fixed"); settled++; }
      }
    } catch { /* an unreadable database has nothing to settle */ } finally { db?.close(); }
  }
  return settled;
}

/** Every variant link in the given databases: a variant's id, the finding it is a variant of, and its status. */
export function readVariantLinks(dbPaths: readonly string[]): VariantLink[] {
  const out: VariantLink[] = [];
  for (const path of dbPaths) {
    if (typeof path !== "string" || !existsSync(path)) continue;
    const db = new osecDB(path);
    try { out.push(...db.listVariantLinks()); } finally { db.close(); }
  }
  return out;
}

/** The stored root cause of a finding row, or undefined for a row without a complete one. */
export const rowRootCause = (row: { rootCause?: unknown }): RootCause | undefined => parseStoredRootCause(row.rootCause);

export const rowVariantOf = (row: { variantOf?: unknown }): string | undefined => typeof row.variantOf === "string" && row.variantOf ? row.variantOf : undefined;

/** Lines for `findings list` and `findings show`: what a finding is a variant of, and the variants it has. */
export function variantLines(id: string, variantOf: string | undefined, links: readonly VariantLink[]): string[] {
  const lines: string[] = [];
  if (variantOf) lines.push(`variant of ${shortFindingId(variantOf)}`);
  const mine = links.filter(link => link.variantOf === id);
  if (mine.length) {
    const fixed = mine.filter(link => link.status === "fixed").length;
    const pending = mine.filter(link => link.status === VARIANT_FIXED_PENDING_MERGE).length;
    lines.push(`${mine.length} variant${mine.length === 1 ? "" : "s"}: ${mine.length - fixed - pending} open, ${pending ? `${pending} fixed pending merge, ` : ""}${fixed} fixed (${mine.slice(0, 5).map(link => shortFindingId(link.id)).join(", ")}${mine.length > 5 ? ", ..." : ""})`);
  }
  return lines;
}


