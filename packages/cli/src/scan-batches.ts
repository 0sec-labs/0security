/**
 * Run a large scan as several threads, one per batch of units, and keep the coverage ledger honest.
 *
 * The orchestration is separate from the console so it can be tested without one: `run` starts one thread and says how it
 * ended. A batch counts as reviewed only when its thread finished normally. A batch that stopped at its budget, hit the time
 * limit or failed stays pending, with the reason, and so does every batch that was never started.
 */
import type { Batch, InventoryUnit } from "@0/engine";
import type { CoverageStatus, CoverageSummary, LedgerUnit } from "@0/engine/storage";
import type { ScanCoverage } from "@0/engine/shared";

/** The least a batch gets. Below this the scan stops and leaves the rest pending instead of starting threads that cannot finish. */
export const MIN_BATCH_BUDGET_USD = 0.05;
/** Failed batches in a row after which the scan stops starting new ones. */
const MAX_CONSECUTIVE_FAILURES = 3;

export type StopReason = "budget" | "time limit" | "thread failed";

export interface BatchOutcome {
  threadId?: string;
  /** The thread finished normally: not failed, not cancelled at the time limit, not stopped at its budget. */
  reviewed: boolean;
  costUsd?: number;
  budgetExhausted: boolean;
  timedOut: boolean;
  failed: boolean;
  error?: string;
}

export interface LedgerPort {
  mark(scanId: string, unitIds: readonly string[], update: { status: CoverageStatus; reason?: string; threadId?: string }): void;
  addSpend(scanId: string, usd: number): void;
  addThread(scanId: string, threadId: string): void;
  setPendingReason(scanId: string, reason: string): void;
}

export interface RunBatchesInput {
  batches: readonly Batch[];
  ledger: LedgerPort;
  scanId: string;
  /** What this run may still spend in total. */
  budgetUsd: number;
  /** Epoch milliseconds after which no batch is started. */
  deadline: number;
  concurrency: number;
  run(batch: Batch, budgetUsd: number): Promise<BatchOutcome>;
  now?: () => number;
  log?: (text: string) => void;
}

export interface RunBatchesResult {
  outcomes: Array<{ batch: Batch; outcome: BatchOutcome }>;
  spentUsd: number;
  stopped?: StopReason;
  budgetHit: boolean;
  timedOut: boolean;
}

/**
 * The budget of the next batch: what is left (minus what running batches may still use) shared between the batches not yet
 * started, with a floor, never more than what is left.
 */
export function batchBudget(available: number, batchesLeft: number): number {
  return Math.min(available, Math.max(MIN_BATCH_BUDGET_USD, available / Math.max(1, batchesLeft)));
}

export async function runBatches(input: RunBatchesInput): Promise<RunBatchesResult> {
  const now = input.now ?? Date.now;
  const queue = [...input.batches];
  const outcomes: RunBatchesResult["outcomes"] = [];
  let spent = 0;
  let reserved = 0;
  let stopped: StopReason | undefined;
  let consecutiveFailures = 0;
  let budgetHit = false;
  let timedOut = false;

  const worker = async (): Promise<void> => {
    while (queue.length && !stopped) {
      if (now() > input.deadline) { stopped = "time limit"; timedOut = true; return; }
      const available = input.budgetUsd - spent - reserved;
      if (available < MIN_BATCH_BUDGET_USD) {
        // Another batch may still be running and could free some budget; only stop when nothing else holds any.
        if (reserved > 0) { await new Promise(resolve => setTimeout(resolve, 50)); continue; }
        stopped = "budget";
        budgetHit = true;
        return;
      }
      const batch = queue.shift()!;
      const share = batchBudget(available, queue.length + 1);
      reserved += share;
      let outcome: BatchOutcome;
      try { outcome = await input.run(batch, share); }
      catch (error) { outcome = { reviewed: false, budgetExhausted: false, timedOut: false, failed: true, error: error instanceof Error ? error.message : String(error) }; }
      reserved -= share;
      // A thread that ran but reported no cost is assumed to have used its share; one that never started used nothing.
      spent += outcome.costUsd ?? (outcome.threadId ? share : 0);
      outcomes.push({ batch, outcome });
      const ids = batch.units.map(unit => unit.id);
      const threadId = outcome.threadId;
      if (threadId) input.ledger.addThread(input.scanId, threadId);
      if (outcome.reviewed) {
        input.ledger.mark(input.scanId, ids, { status: "reviewed", ...(threadId ? { threadId } : {}) });
        consecutiveFailures = 0;
      } else {
        const reason: StopReason | "budget" = outcome.budgetExhausted ? "budget" : outcome.timedOut ? "time limit" : "thread failed";
        input.ledger.mark(input.scanId, ids, { status: "pending", reason, ...(threadId ? { threadId } : {}) });
        if (outcome.budgetExhausted) budgetHit = true;
        if (outcome.timedOut) { timedOut = true; stopped = "time limit"; }
        else if (outcome.failed && !outcome.budgetExhausted) {
          if (++consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) stopped = "thread failed";
        } else consecutiveFailures = 0;
      }
      if (outcome.costUsd !== undefined) input.ledger.addSpend(input.scanId, outcome.costUsd);
      input.log?.(`batch ${batch.index + 1} of ${input.batches.length}: ${outcome.reviewed ? "reviewed" : `not reviewed (${outcome.budgetExhausted ? "budget" : outcome.timedOut ? "time limit" : "failed"}${outcome.failed && outcome.error ? `: ${outcome.error.slice(0, 200)}` : ""})`}`);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(input.concurrency, input.batches.length)) }, worker));
  if (queue.length && stopped) input.ledger.setPendingReason(input.scanId, stopped);
  return { outcomes, spentUsd: spent, ...(stopped ? { stopped } : {}), budgetHit, timedOut };
}

/** A ledger row as an inventory unit, to batch what is still pending. */
export function unitFromLedger(row: LedgerUnit): InventoryUnit {
  return { id: row.unitId, kind: row.kind as InventoryUnit["kind"], path: row.path, ...(row.startLine !== undefined ? { startLine: row.startLine } : {}), ...(row.name ? { name: row.name } : {}), ...(row.files ? { files: row.files } : {}) };
}

/** The `coverage` object of a report: counts, the sentence, and the first units not reached. */
export function coverageReport(summary: CoverageSummary, statement: string, units: readonly LedgerUnit[]): ScanCoverage {
  const pending = units.filter(unit => unit.status === "pending");
  const batchIds = new Set(units.map(unit => unit.batch));
  const open = new Set(pending.map(unit => unit.batch));
  const batches = { total: batchIds.size, reviewed: batchIds.size - open.size };
  return {
    scanId: summary.scanId,
    complete: summary.complete,
    statement,
    entryPoints: summary.entryPoints,
    otherGroups: summary.otherGroups,
    byKind: summary.byKind,
    notReached: summary.notReached,
    batches: { total: batches.total, reviewed: batches.reviewed, pending: batches.total - batches.reviewed },
    pendingUnits: pending.slice(0, 100).map(unit => ({ kind: unit.kind, path: unit.path, ...(unit.startLine !== undefined ? { startLine: unit.startLine } : {}), ...(unit.name ? { name: unit.name } : {}), ...(unit.reason ? { reason: unit.reason } : {}) })),
  };
}
