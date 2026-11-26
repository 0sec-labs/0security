import { parseStoredRootCause, type RootCause } from "@0/engine/shared";
import { osecDB } from "@0/engine/storage";
import { existsSync } from "node:fs";
import { shortFindingId } from "./finding-id.js";

export interface VariantLink { id: string; variantOf: string; status: string }

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
    lines.push(`${mine.length} variant${mine.length === 1 ? "" : "s"}: ${mine.length - fixed} open, ${fixed} fixed (${mine.slice(0, 5).map(link => shortFindingId(link.id)).join(", ")}${mine.length > 5 ? ", ..." : ""})`);
  }
  return lines;
}


