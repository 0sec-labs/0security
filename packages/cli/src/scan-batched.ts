/**
 * The planning side of a batched scan: decide whether a folder is split, make or find its coverage ledger, and print a ledger.
 * The thread running stays in `commands/scan.ts`; the orchestration is in `scan-batches.ts`.
 */
import { buildInventory, inventorySummaryText, planBatches, type Batch, type Inventory } from "@0/engine";
import { coverageSentence, summarizeCoverage, type CoverageLedger, type LedgerScan, type LedgerUnit } from "@0/engine/storage";
import { UsageError } from "./commands/output.js";
import { unitFromLedger } from "./scan-batches.js";

export const DEFAULT_BATCH_SIZE = 8;
/** `--batches auto` splits a folder with more source files than this even when few entry points are found. */
export const AUTO_BATCH_FILES = 150;

export interface BatchedSetup {
  ledger: CoverageLedger;
  scan: LedgerScan;
  /** What this run reviews: all units of a new scan, the pending units of a resumed one. */
  batches: Batch[];
  inventory: Inventory;
  summaryText: string;
  resumed: boolean;
}

export interface PlanInput {
  folder: string;
  label: string;
  mode: string;
  batchSize: number;
  resume?: string;
  force?: boolean;
  budgetUsd: number;
  passes: number;
  /** The scan has a reason to stay one thread (another skill, policies). */
  singleThread: boolean;
  scope?: readonly string[];
  dbPath?: string;
  openLedger: (dbPath?: string) => CoverageLedger;
  gitHead: (folder: string) => Promise<string | undefined>;
  err: (text: string) => void;
}

const short = (head: string | undefined): string => (head ? head.slice(0, 7) : "no git commit");

/** Whether `auto` splits this folder: more entry points than one thread takes, or a large tree. */
export function shouldBatch(inventory: Inventory, batchSize: number): boolean {
  return inventory.summary.entryPoints > batchSize || inventory.summary.sourceFiles > AUTO_BATCH_FILES;
}

/** The plan for a batched scan, or undefined when the scan runs as one thread as before. Throws UsageError on a bad resume. */
export async function planBatchedScan(input: PlanInput): Promise<BatchedSetup | undefined> {
  const resuming = input.resume !== undefined;
  if (!resuming && (input.mode === "off" || (input.mode === "auto" && (input.passes > 1 || input.singleThread)))) return undefined;
  const inventory = buildInventory(input.folder, input.scope ? { only: new Set(input.scope) } : {});
  const summaryText = inventorySummaryText(inventory.summary);
  const head = await input.gitHead(input.folder);

  if (resuming) {
    const ledger = input.openLedger(input.dbPath);
    try {
      const wanted = input.resume!.trim();
      const scan = wanted === "latest" || wanted === "" ? ledger.latestScan(input.folder) : ledger.getScan(wanted);
      if (!scan) throw new UsageError(wanted === "latest" || wanted === "" ? `No batched scan of ${input.folder} to resume. Run \`0security scan\` on it first.` : `No scan ${wanted} in the findings database. List what a folder has with \`0security scan <folder> --coverage\`.`);
      if (scan.folder !== input.folder) throw new UsageError(`Scan ${scan.id} was of ${scan.folder}, not ${input.folder}.`);
      if ((scan.gitHead ?? undefined) !== head) {
        if (!input.force) throw new UsageError(`The git HEAD of ${input.folder} changed since scan ${scan.id} began (${short(scan.gitHead)}, now ${short(head)}), so its unit ids may not match the code. Run a new scan, or pass --force to continue anyway.`);
        input.err(`warning: continuing scan ${scan.id} although the git HEAD changed (${short(scan.gitHead)}, now ${short(head)}); some units may no longer match the code`);
      }
      const pending = ledger.units(scan.id, "pending");
      return { ledger, scan, inventory, summaryText, resumed: true, batches: planBatches(pending.map(unitFromLedger), scan.batchSize) };
    } catch (error) { ledger.close(); throw error; }
  }

  if (input.mode === "auto" && !shouldBatch(inventory, input.batchSize)) return undefined;
  if (!inventory.units.length) return undefined;
  const batches = planBatches(inventory.units, input.batchSize);
  const batchOf = new Map<string, number>();
  for (const batch of batches) for (const unit of batch.units) batchOf.set(unit.id, batch.index);
  const ledger = input.openLedger(input.dbPath);
  try {
    const scan = ledger.createScan({ folder: input.folder, label: input.label, ...(head ? { gitHead: head } : {}), batchSize: input.batchSize, budgetUsd: input.budgetUsd }, inventory.units.map(unit => ({ ...unit, batch: batchOf.get(unit.id) ?? 0 })));
    return { ledger, scan, inventory, summaryText, resumed: false, batches };
  } catch (error) { ledger.close(); throw error; }
}

const where = (unit: LedgerUnit): string => (unit.startLine ? `${unit.path}:${unit.startLine}` : unit.path);

/** The ledger of one scan as text, one line per unit that is not reviewed first. */
export function coverageText(scan: LedgerScan, units: readonly LedgerUnit[]): string {
  const summary = summarizeCoverage(scan.id, units);
  const order = { pending: 0, skipped: 1, reviewed: 2 } as const;
  const rows = [...units].sort((a, b) => order[a.status] - order[b.status] || a.batch - b.batch || (a.path < b.path ? -1 : a.path > b.path ? 1 : (a.startLine ?? 0) - (b.startLine ?? 0)));
  return [
    `Scan ${scan.id} of ${scan.folder} (${scan.gitHead ? `git ${short(scan.gitHead)}` : "not a git work tree"}), started ${scan.createdAt}, spent $${scan.spentUsd.toFixed(4)} of $${scan.budgetUsd}`,
    `${coverageSentence(summary)}${summary.complete ? "" : " (resume with `0security scan <folder> --resume " + scan.id + "`)"}`,
    "",
    ...rows.map(unit => `${unit.status.padEnd(8)} ${unit.kind.padEnd(15)} ${where(unit)}${unit.name ? ` ${unit.name}` : ""}${unit.files ? ` [${unit.files.length} files]` : ""}${unit.reason ? `  (${unit.reason})` : ""}`),
  ].join("\n");
}

/** The ledger of one scan as JSON. */
export function coverageJson(scan: LedgerScan, units: readonly LedgerUnit[]): Record<string, unknown> {
  const summary = summarizeCoverage(scan.id, units);
  return { schemaVersion: 1, scan, statement: coverageSentence(summary), complete: summary.complete, entryPoints: summary.entryPoints, otherGroups: summary.otherGroups, byKind: summary.byKind, notReached: summary.notReached, units };
}
