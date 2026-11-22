import { randomBytes } from "node:crypto";
import { ensureDatabaseDirectory } from "./db-directory.js";
import { resolveOsecDbPath } from "./database.js";
import { COVERAGE_INDEXES_SQL, SCHEMA_TABLES_SQL } from "./schema-migrations.js";
import { createShimmedDatabase, type ShimmedDatabase } from "./wasm-shim.js";

export type CoverageStatus = "pending" | "reviewed" | "skipped";

export interface LedgerScan {
  id: string;
  folder: string;
  label: string;
  gitHead?: string;
  batchSize: number;
  budgetUsd: number;
  spentUsd: number;
  /** Every thread the scan started, in order (partial batches included). */
  threadIds: string[];
  createdAt: string;
  updatedAt: string;
}

export interface LedgerUnit {
  unitId: string;
  kind: string;
  path: string;
  startLine?: number;
  name?: string;
  files?: string[];
  batch: number;
  status: CoverageStatus;
  reason?: string;
  threadId?: string;
  updatedAt: string;
}

export interface NewLedgerUnit { id: string; kind: string; path: string; startLine?: number; name?: string; files?: string[]; batch: number }

interface Tally { total: number; reviewed: number; pending: number; skipped: number }
export interface CoverageSummary {
  scanId: string;
  entryPoints: Tally;
  otherGroups: Tally;
  byKind: Record<string, Tally>;
  /** Why entry points were not reached: reason to count. */
  notReached: Record<string, number>;
  /** True only when no unit is pending. */
  complete: boolean;
}

const emptyTally = (): Tally => ({ total: 0, reviewed: 0, pending: 0, skipped: 0 });

/** The counts of a ledger. `skipped` units are neither reviewed nor pending: they were set aside on purpose. */
export function summarizeCoverage(scanId: string, units: readonly LedgerUnit[]): CoverageSummary {
  const entryPoints = emptyTally();
  const otherGroups = emptyTally();
  const byKind: Record<string, Tally> = {};
  const notReached: Record<string, number> = {};
  for (const unit of units) {
    const tally = (byKind[unit.kind] ??= emptyTally());
    const group = unit.kind === "other" ? otherGroups : entryPoints;
    for (const target of [tally, group]) { target.total++; target[unit.status]++; }
    if (unit.status === "pending" && unit.kind !== "other") notReached[unit.reason ?? "not started"] = (notReached[unit.reason ?? "not started"] ?? 0) + 1;
  }
  return { scanId, entryPoints, otherGroups, byKind, notReached, complete: entryPoints.pending + otherGroups.pending === 0 };
}

const reasonList = (reasons: Record<string, number>): string => {
  const entries = Object.entries(reasons);
  return entries.length === 1 ? entries[0]![0] : entries.map(([reason, count]) => `${reason}: ${count}`).join(", ");
};

/**
 * What a report says about coverage, in plain words: "reviewed 41 of 57 entry points; 16 not reached (budget)". It never
 * says everything was reviewed while a unit is pending.
 */
export function coverageSentence(summary: CoverageSummary): string {
  const { entryPoints, otherGroups } = summary;
  const parts: string[] = [];
  if (entryPoints.total) {
    parts.push(`reviewed ${entryPoints.reviewed} of ${entryPoints.total} entry point${entryPoints.total === 1 ? "" : "s"}`);
    if (entryPoints.pending) parts.push(`${entryPoints.pending} not reached (${reasonList(summary.notReached)})`);
    if (entryPoints.skipped) parts.push(`${entryPoints.skipped} skipped`);
  }
  if (otherGroups.total) {
    const others = `${otherGroups.reviewed} of ${otherGroups.total} groups of other files reviewed`;
    parts.push(entryPoints.total ? others : `reviewed ${others.replace(" reviewed", "")}`);
    if (otherGroups.pending) parts.push(`${otherGroups.pending} not reached`);
  }
  if (!parts.length) return "no entry points found";
  return parts.join("; ");
}

type Row = Record<string, unknown>;
const optionalString = (value: unknown): string | undefined => (typeof value === "string" ? value : undefined);
const optionalNumber = (value: unknown): number | undefined => (typeof value === "number" ? value : undefined);

function parseList(value: unknown): string[] {
  try { const parsed: unknown = typeof value === "string" ? JSON.parse(value) : []; return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : []; } catch { return []; }
}

function scanFromRow(row: Row): LedgerScan {
  const head = optionalString(row["gitHead"]);
  return { id: String(row["id"]), folder: String(row["folder"]), label: String(row["label"]), ...(head ? { gitHead: head } : {}), batchSize: Number(row["batchSize"]), budgetUsd: Number(row["budgetUsd"]), spentUsd: Number(row["spentUsd"]), threadIds: parseList(row["threadIds"]), createdAt: String(row["createdAt"]), updatedAt: String(row["updatedAt"]) };
}

function unitFromRow(row: Row): LedgerUnit {
  const files = optionalString(row["files"]);
  const startLine = optionalNumber(row["startLine"]);
  const name = optionalString(row["name"]);
  const reason = optionalString(row["reason"]);
  const threadId = optionalString(row["threadId"]);
  let parsed: string[] | undefined;
  try { parsed = files ? (JSON.parse(files) as string[]) : undefined; } catch { parsed = undefined; }
  return { unitId: String(row["unitId"]), kind: String(row["kind"]), path: String(row["path"]), ...(startLine !== undefined ? { startLine } : {}), ...(name ? { name } : {}), ...(parsed ? { files: parsed } : {}), batch: Number(row["batch"]), status: String(row["status"]) as CoverageStatus, ...(reason ? { reason } : {}), ...(threadId ? { threadId } : {}), updatedAt: String(row["updatedAt"]) };
}

/** The coverage ledger of batched scans, in the findings database next to the scans it describes. */
export class CoverageLedger {
  readonly #db: ShimmedDatabase;
  constructor(dbPath?: string) {
    const path = resolveOsecDbPath(dbPath);
    ensureDatabaseDirectory(path);
    this.#db = createShimmedDatabase(path);
    this.#db.pragma("busy_timeout = 5000");
    this.#db.exec(SCHEMA_TABLES_SQL);
    this.#db.exec(COVERAGE_INDEXES_SQL);
  }

  createScan(input: { folder: string; label: string; gitHead?: string; batchSize: number; budgetUsd: number }, units: readonly NewLedgerUnit[], now = new Date()): LedgerScan {
    const id = `scan-${randomBytes(4).toString("hex")}`;
    const stamp = now.toISOString();
    this.#db.transaction(() => {
      this.#db.prepare("INSERT INTO coverage_scans(id,folder,label,gitHead,batchSize,budgetUsd,spentUsd,createdAt,updatedAt) VALUES(?,?,?,?,?,?,0,?,?)").run(id, input.folder, input.label, input.gitHead ?? null, input.batchSize, input.budgetUsd, stamp, stamp);
      const insert = this.#db.prepare("INSERT OR IGNORE INTO coverage_units(scanId,unitId,kind,path,startLine,name,files,batch,status,updatedAt) VALUES(?,?,?,?,?,?,?,?,'pending',?)");
      for (const unit of units) insert.run(id, unit.id, unit.kind, unit.path, unit.startLine ?? null, unit.name ?? null, unit.files ? JSON.stringify(unit.files) : null, unit.batch, stamp);
    })();
    return this.getScan(id)!;
  }

  getScan(id: string): LedgerScan | undefined {
    const row = this.#db.prepare("SELECT * FROM coverage_scans WHERE id = ?").all(id)[0] as Row | undefined;
    return row ? scanFromRow(row) : undefined;
  }

  /** The newest scan of this folder, or of any folder when none is named. */
  latestScan(folder?: string): LedgerScan | undefined {
    const row = (folder === undefined
      ? this.#db.prepare("SELECT * FROM coverage_scans ORDER BY createdAt DESC, rowid DESC LIMIT 1").all()
      : this.#db.prepare("SELECT * FROM coverage_scans WHERE folder = ? ORDER BY createdAt DESC, rowid DESC LIMIT 1").all(folder))[0] as Row | undefined;
    return row ? scanFromRow(row) : undefined;
  }

  units(scanId: string, status?: CoverageStatus): LedgerUnit[] {
    const rows = status
      ? this.#db.prepare("SELECT * FROM coverage_units WHERE scanId = ? AND status = ? ORDER BY batch, path, COALESCE(startLine,0), unitId").all(scanId, status)
      : this.#db.prepare("SELECT * FROM coverage_units WHERE scanId = ? ORDER BY batch, path, COALESCE(startLine,0), unitId").all(scanId);
    return (rows as Row[]).map(unitFromRow);
  }

  mark(scanId: string, unitIds: readonly string[], update: { status: CoverageStatus; reason?: string; threadId?: string }, now = new Date()): void {
    const stamp = now.toISOString();
    this.#db.transaction(() => {
      const statement = this.#db.prepare("UPDATE coverage_units SET status = ?, reason = ?, threadId = COALESCE(?, threadId), updatedAt = ? WHERE scanId = ? AND unitId = ?");
      for (const id of unitIds) statement.run(update.status, update.reason ?? null, update.threadId ?? null, stamp, scanId, id);
      this.#db.prepare("UPDATE coverage_scans SET updatedAt = ? WHERE id = ?").run(stamp, scanId);
    })();
  }

  /** Why the still-pending units of a scan have not been reviewed (only those with no reason yet). */
  setPendingReason(scanId: string, reason: string, now = new Date()): void {
    this.#db.prepare("UPDATE coverage_units SET reason = ?, updatedAt = ? WHERE scanId = ? AND status = 'pending' AND reason IS NULL").run(reason, now.toISOString(), scanId);
  }

  /** Remember a thread the scan started, so a later report reads its findings even when a unit moved on to another thread. */
  addThread(scanId: string, threadId: string, now = new Date()): void {
    this.#db.transaction(() => {
      const current = this.getScan(scanId)?.threadIds ?? [];
      if (current.includes(threadId)) return;
      this.#db.prepare("UPDATE coverage_scans SET threadIds = ?, updatedAt = ? WHERE id = ?").run(JSON.stringify([...current, threadId]), now.toISOString(), scanId);
    })();
  }

  addSpend(scanId: string, usd: number, now = new Date()): void {
    this.#db.prepare("UPDATE coverage_scans SET spentUsd = spentUsd + ?, updatedAt = ? WHERE id = ?").run(usd, now.toISOString(), scanId);
  }

  summary(scanId: string): CoverageSummary { return summarizeCoverage(scanId, this.units(scanId)); }

  close(): void { this.#db.close(); }
}
