import type { FindingModelVerification } from "@0/engine/storage";
import { shortFindingId } from "./finding-id.js";

const VERDICTS = new Set(["true-positive", "false-positive", "fixed", "uncertain", "duplicate"]);

/** A short phrase for `findings list` and `findings show`. Advice from a second look, not a status. */
export function verificationPhrase(record: Pick<FindingModelVerification, "verdict" | "duplicateOf"> | undefined): string | undefined {
  if (!record) return undefined;
  switch (record.verdict) {
    case "true-positive": return "verified: likely real";
    case "false-positive": return "verified: likely false positive";
    case "fixed": return "verified: already fixed";
    case "duplicate": return `verified: duplicate${record.duplicateOf ? ` of ${shortFindingId(record.duplicateOf)}` : ""}`;
    default: return "verified: uncertain";
  }
}

/** The record stored in a finding row's `modelVerification` column, when it holds a usable one. Absent for anything else. */
export function rowVerification(row: { modelVerification?: unknown }): FindingModelVerification | undefined {
  const raw = row.modelVerification;
  let value: unknown = raw;
  if (typeof raw === "string") { try { value = JSON.parse(raw); } catch { return undefined; } }
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  if (!VERDICTS.has(String(record.verdict)) || typeof record.reasoning !== "string" || typeof record.verifiedAt !== "string") return undefined;
  return record as unknown as FindingModelVerification;
}
