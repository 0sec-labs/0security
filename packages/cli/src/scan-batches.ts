/**
 * Run a large scan as several threads, one per batch of units, and keep the coverage ledger honest.
 *
 * The orchestration is separate from the console so it can be tested without one: `run` starts one thread and says how it
 * ended. A batch counts as reviewed only when its thread finished normally. A batch that stopped at its budget, hit the time
 * limit or failed stays pending, with the reason, and so does every batch that was never started. Inside a batch that did
 * finish, a unit whose files the thread never opened stays pending with the reason "not opened".
 */
import type { Batch, InventoryUnit } from "@0/engine";
import type { CoverageStatus, CoverageSummary, LedgerUnit } from "@0/engine/storage";
import type { ScanCoverage, ScanFileCoverage } from "@0/engine/shared";
import type { FailureCause, ScanFailure } from "./scan-failure.js";

/** The least a batch gets. Below this the scan stops and leaves the rest pending instead of starting threads that cannot finish. */
export const MIN_BATCH_BUDGET_USD = 0.05;
/** Failed batches in a row after which the scan stops starting new ones. */
const MAX_CONSECUTIVE_FAILURES = 3;

/** Retries of a failed batch when `--retries` is not given. */
export const DEFAULT_RETRIES = 2;
/** The longest wait between two attempts of a batch. */
const MAX_BACKOFF_MS = 30_000;
const BASE_BACKOFF_MS = 2_000;

/** The most batches `--concurrency` can ever ask for. `ZERO_SCAN_MAX_CONCURRENCY` can lower the limit but never pass this. */
export const BATCH_CONCURRENCY_CEILING = 16;
/** What `--concurrency` allows when `ZERO_SCAN_MAX_CONCURRENCY` is not set. */
export const DEFAULT_MAX_BATCH_CONCURRENCY = 8;

/**
 * The most batches one scan may run at the same time: `ZERO_SCAN_MAX_CONCURRENCY` when it is a whole number from 1 up to
 * the ceiling, else the default. A bad value is ignored, not trusted: the limit protects the model provider, the console
 * and the machine, so a typo must not remove it.
 */
export function maxBatchConcurrency(env: Record<string, string | undefined> = process.env): number {
  const raw = env["ZERO_SCAN_MAX_CONCURRENCY"]?.trim();
  if (!raw || !/^\d+$/.test(raw)) return DEFAULT_MAX_BATCH_CONCURRENCY;
  const value = Number(raw);
  return value >= 1 && value <= BATCH_CONCURRENCY_CEILING ? value : DEFAULT_MAX_BATCH_CONCURRENCY;
}

export type StopReason = "budget" | "time limit" | "thread failed" | "timeout";

export interface BatchOutcome {
  threadId?: string;
  /** The thread finished normally: not failed, not cancelled at the time limit, not stopped at its budget. */
  reviewed: boolean;
  costUsd?: number;
  budgetExhausted: boolean;
  timedOut: boolean;
  failed: boolean;
  error?: string;
  /** The batch hit its own time limit (the scan's limit has not passed). The batch stays pending, the scan goes on. */
  batchTimedOut?: boolean;
  /** Why the thread failed, when it did. Decides whether the batch is tried again. */
  failure?: ScanFailure;
  /** Units of a batch that finished normally whose files the thread never opened, even after the follow-up rounds: they stay pending. */
  notOpenedUnitIds?: readonly string[];
}

/** One batch that was tried more than once. */
export interface BatchRetry { batch: number; attempts: number; causes: FailureCause[]; recovered: boolean }
export interface BatchFailure { batch: number; cause: FailureCause; message: string }

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
  /** How often a batch that failed for a transient reason is run again (default 2, 0 turns retries off). */
  retries?: number;
  /** Waits between attempts; replaced in tests. */
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
  now?: () => number;
  log?: (text: string) => void;
}

export interface RunBatchesResult {
  outcomes: Array<{ batch: Batch; outcome: BatchOutcome }>;
  spentUsd: number;
  stopped?: StopReason;
  budgetHit: boolean;
  timedOut: boolean;
  /** Batches that needed more than one attempt. */
  retried: BatchRetry[];
  /** Batches that still were not reviewed because of a failure or their own time limit, with the cause. */
  failures: BatchFailure[];
}

/** Wait before retry number `attempt` (1 for the first): doubles each time, 50% to 100% of that, at most 30 s. */
export function retryDelayMs(attempt: number, random: () => number = Math.random): number {
  const ceiling = Math.min(MAX_BACKOFF_MS, BASE_BACKOFF_MS * 2 ** Math.max(0, attempt - 1));
  return Math.round(ceiling * (0.5 + random() / 2));
}

/** A failed batch is tried again only when the cause is transient, and never after budget, timeout or cancellation. */
export function isRetryable(outcome: BatchOutcome): boolean {
  return !outcome.reviewed && outcome.failed && !outcome.budgetExhausted && !outcome.timedOut && !outcome.batchTimedOut && outcome.failure?.transient === true;
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
  const sleep = input.sleep ?? ((ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms)));
  const random = input.random ?? Math.random;
  const maxRetries = Math.max(0, Math.floor(input.retries ?? DEFAULT_RETRIES));
  const retried: BatchRetry[] = [];
  const failures: BatchFailure[] = [];
  const queue = [...input.batches];
  const outcomes: RunBatchesResult["outcomes"] = [];
  let spent = 0;
  let reserved = 0;
  let stopped: StopReason | undefined;
  let consecutiveFailures = 0;
  let budgetHit = false;
  let timedOut = false;
  // The provider's limit is shared by every batch: when one batch is turned away, none of them starts new work for a while.
  let pausedUntil = 0;
  let rateLimitStreak = 0;
  const slowDown = (ms: number, label: string): void => {
    const until = now() + ms;
    if (until <= pausedUntil) return;
    pausedUntil = until;
    input.log?.(`${label}: the model provider rate limit was hit; no batch starts for ${Math.max(1, Math.round(ms / 1000))}s`);
  };
  const holdForRateLimit = async (): Promise<void> => {
    const left = pausedUntil - now();
    if (left > 0) await sleep(left);
  };

  const worker = async (): Promise<void> => {
    while (queue.length && !stopped) {
      await holdForRateLimit();
      // Another worker may have taken the last batch, or stopped the scan, while this one waited.
      if (stopped || !queue.length) return;
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
      const label = `batch ${batch.index + 1} of ${input.batches.length}`;
      let outcome: BatchOutcome;
      const causes: FailureCause[] = [];
      let attempts = 0;
      for (;;) {
        await holdForRateLimit();
        const room = input.budgetUsd - spent - reserved;
        const share = batchBudget(room, queue.length + 1);
        reserved += share;
        try { outcome = await input.run(batch, share); }
        catch (error) { outcome = { reviewed: false, budgetExhausted: false, timedOut: false, failed: true, error: error instanceof Error ? error.message : String(error) }; }
        reserved -= share;
        attempts++;
        // A thread that ran but reported no cost is assumed to have used its share; one that never started used nothing.
        // A failed attempt costs the same as any other: it counts against the total budget.
        spent += outcome.costUsd ?? (outcome.threadId ? share : 0);
        if (outcome.threadId) input.ledger.addThread(input.scanId, outcome.threadId);
        if (outcome.costUsd !== undefined) input.ledger.addSpend(input.scanId, outcome.costUsd);
        if (outcome.failure && !outcome.reviewed) causes.push(outcome.failure.cause);
        const rateLimited = !outcome.reviewed && outcome.failure?.cause === "provider_rate_limit";
        rateLimitStreak = rateLimited ? rateLimitStreak + 1 : outcome.reviewed ? 0 : rateLimitStreak;
        if (!isRetryable(outcome) || attempts > maxRetries) {
          if (rateLimited) slowDown(retryDelayMs(rateLimitStreak, random), label);
          break;
        }
        const delay = retryDelayMs(rateLimited ? rateLimitStreak : attempts, random);
        if (rateLimited) slowDown(delay, label);
        if (now() + delay > input.deadline || input.budgetUsd - spent - reserved < MIN_BATCH_BUDGET_USD) break;
        input.log?.(`${label}: ${outcome.failure?.message ?? outcome.error ?? "failed"}; trying again in ${Math.max(1, Math.round(delay / 1000))}s (retry ${attempts} of ${maxRetries}, $${spent.toFixed(4)} spent so far)`);
        await sleep(delay);
      }
      outcomes.push({ batch, outcome });
      if (attempts > 1) retried.push({ batch: batch.index + 1, attempts, causes, recovered: outcome.reviewed });
      const ids = batch.units.map(unit => unit.id);
      const threadId = outcome.threadId;
      if (outcome.reviewed) {
        // A thread that ended normally has reviewed the units whose files it opened; the others wait for a resume.
        const skipped = new Set(outcome.notOpenedUnitIds ?? []);
        const opened = ids.filter(id => !skipped.has(id));
        if (opened.length) input.ledger.mark(input.scanId, opened, { status: "reviewed", ...(threadId ? { threadId } : {}) });
        if (skipped.size) input.ledger.mark(input.scanId, ids.filter(id => skipped.has(id)), { status: "pending", reason: "not opened", ...(threadId ? { threadId } : {}) });
        consecutiveFailures = 0;
      } else {
        const reason: StopReason = outcome.budgetExhausted ? "budget" : outcome.timedOut ? "time limit" : outcome.batchTimedOut ? "timeout" : "thread failed";
        input.ledger.mark(input.scanId, ids, { status: "pending", reason, ...(threadId ? { threadId } : {}) });
        if (outcome.budgetExhausted) budgetHit = true;
        if (outcome.timedOut) { timedOut = true; stopped = "time limit"; }
        else if ((outcome.failed || outcome.batchTimedOut) && !outcome.budgetExhausted) {
          if (outcome.failure || outcome.error || outcome.batchTimedOut) failures.push({ batch: batch.index + 1, cause: outcome.failure?.cause ?? (outcome.batchTimedOut ? "batch_timeout" : "unknown"), message: outcome.failure?.message ?? (outcome.error ?? (outcome.batchTimedOut ? "A batch reached its time limit" : "")).slice(0, 240) });
          if (++consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) stopped = outcome.batchTimedOut ? "timeout" : "thread failed";
        } else consecutiveFailures = 0;
      }
      const why = outcome.budgetExhausted ? "budget" : outcome.timedOut ? "time limit" : outcome.batchTimedOut ? "timeout" : "failed";
      const detail = outcome.failure?.message ?? (outcome.failed && outcome.error ? outcome.error.slice(0, 200) : "");
      input.log?.(`${label}: ${outcome.reviewed ? `reviewed${attempts > 1 ? ` (after ${attempts - 1} ${attempts === 2 ? "retry" : "retries"})` : ""}` : `not reviewed (${why}${detail ? `: ${detail}` : ""}${attempts > 1 ? `; ${attempts - 1} ${attempts === 2 ? "retry" : "retries"} used` : ""})`}`);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(input.concurrency, input.batches.length)) }, worker));
  if (queue.length && stopped) input.ledger.setPendingReason(input.scanId, stopped);
  return { outcomes, spentUsd: spent, ...(stopped ? { stopped } : {}), budgetHit, timedOut, retried, failures };
}

/** A ledger row as an inventory unit, to batch what is still pending. */
export function unitFromLedger(row: LedgerUnit): InventoryUnit {
  return { id: row.unitId, kind: row.kind as InventoryUnit["kind"], path: row.path, ...(row.startLine !== undefined ? { startLine: row.startLine } : {}), ...(row.name ? { name: row.name } : {}), ...(row.files ? { files: row.files } : {}) };
}

/** The `coverage` object of a report: counts, the sentence, and the first units not reached. */
export function coverageReport(summary: CoverageSummary, statement: string, units: readonly LedgerUnit[], run?: { retried: readonly BatchRetry[]; failures: readonly BatchFailure[]; retriesAllowed: number; files?: ScanFileCoverage }): ScanCoverage {
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
    ...(run ? { retries: { allowed: run.retriesAllowed, total: run.retried.reduce((sum, item) => sum + item.attempts - 1, 0), batches: run.retried.map(item => ({ batch: item.batch, attempts: item.attempts, causes: [...item.causes], recovered: item.recovered })) } } : {}),
    ...(run?.files ? run.files : {}),
    ...(run?.failures.length ? { failures: run.failures.map(item => ({ batch: item.batch, cause: item.cause, message: item.message })) } : {}),
    pendingUnits: pending.slice(0, 100).map(unit => ({ kind: unit.kind, path: unit.path, ...(unit.startLine !== undefined ? { startLine: unit.startLine } : {}), ...(unit.name ? { name: unit.name } : {}), ...(unit.reason ? { reason: unit.reason } : {}) })),
  };
}
