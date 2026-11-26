/**
 * Executed PoC harness. After a high or critical finding is saved, build a PoC
 * from its steps and run it through the existing verifier (`runVerifier`) on a
 * snapshot of the scanned folder, in a container with the network off.
 *
 * The model never calls this and cannot set its result. Only a passing run in a
 * container earns `executed-proven`; everything that did not execute to a
 * verdict is `static-only`. A host runner is refused: it cannot isolate.
 */
import type { ContainerRunner, StepRequest } from "../verifier/port.js";
import { OciRunner } from "../verifier/docker-runner.js";
import { isGitRepo, snapshotWorktree } from "../verifier/snapshot.js";
import { runVerifier } from "../verifier/runner.js";
import { REPRODUCTION_LIMITS } from "../reproduction/harness.js";
import { EXECUTED_POC_HARNESS, isPocEligibleSeverity, parseExecutedPoc, type ExecutedPoc, type ExecutedPocRun } from "../shared/executed-poc.js";
import type { Finding } from "../shared/types.js";
import { planPocSpec, POC_DEFAULT_TIMEOUT_SEC } from "./plan.js";

export interface ExecutedPocConfig {
  /** Digest-pinned image the PoC runs in. Without it every attempt is static-only. */
  image?: string;
  /** Most PoC runs for one scan. Default 3. */
  maxRuns?: number;
  /** Wall-clock limit for one run, seconds. Default 60, at most 300. */
  timeoutSec?: number;
  /** Total wall-clock time all runs of a scan may use, seconds. Default 300. */
  maxTotalSec?: number;
  /** Run even when the runtime cannot cap writable storage. Off by default: the run is refused instead. */
  allowUnboundedStorage?: boolean;
}

export const POC_DEFAULT_MAX_RUNS = 3;
export const POC_DEFAULT_MAX_TOTAL_SEC = 300;

/** Run and time budget shared by every attempt in one scan. */
export class ExecutedPocBudget {
  #runs = 0;
  #ms = 0;
  constructor(private readonly maxRuns: number, private readonly maxMs: number) {}
  /** Takes one run from the budget, or says it is spent. */
  reserve(): boolean {
    if (this.#runs >= this.maxRuns || this.#ms >= this.maxMs) return false;
    this.#runs += 1;
    return true;
  }
  spend(ms: number): void { this.#ms += Math.max(0, ms); }
  get runs(): number { return this.#runs; }
  get remainingMs(): number { return Math.max(0, this.maxMs - this.#ms); }
}

export interface ExecutedPocRuntime {
  config: ExecutedPocConfig;
  budget: ExecutedPocBudget;
  /** Test seam at the container port. Defaults to Docker or podman. */
  runner?: ContainerRunner;
}

const positive = (value: number | undefined, fallback: number): number => (value !== undefined && Number.isFinite(value) && value > 0 ? value : fallback);

export function createExecutedPoc(config: ExecutedPocConfig, runner?: ContainerRunner): ExecutedPocRuntime {
  return {
    config,
    budget: new ExecutedPocBudget(Math.floor(positive(config.maxRuns, POC_DEFAULT_MAX_RUNS)), positive(config.maxTotalSec, POC_DEFAULT_MAX_TOTAL_SEC) * 1000),
    ...(runner ? { runner } : {}),
  };
}

const scanRuntimes = new Map<string, ExecutedPocRuntime>();

/** One runtime per scan, so a scan's delegated agents share one budget. Undefined when the feature is not configured. */
export function executedPocForScan(scanId: string, explicit?: ExecutedPocRuntime, env: NodeJS.ProcessEnv = process.env): ExecutedPocRuntime | undefined {
  if (explicit) return explicit;
  const known = scanRuntimes.get(scanId);
  if (known) return known;
  const config = executedPocConfigFromEnv(env);
  if (!config) return undefined;
  const runtime = createExecutedPoc(config);
  if (scanRuntimes.size >= 64) scanRuntimes.delete(scanRuntimes.keys().next().value as string);
  scanRuntimes.set(scanId, runtime);
  return runtime;
}

/** Opt-in through the environment: `ZERO_POC_IMAGE` (digest-pinned) enables it. Undefined when unset. */
export function executedPocConfigFromEnv(env: NodeJS.ProcessEnv = process.env): ExecutedPocConfig | undefined {
  const image = env.ZERO_POC_IMAGE?.trim();
  if (!image) return undefined;
  const num = (name: string): number | undefined => { const n = Number(env[name]); return env[name] && Number.isFinite(n) && n > 0 ? n : undefined; };
  const maxRuns = num("ZERO_POC_MAX_RUNS");
  const timeoutSec = num("ZERO_POC_TIMEOUT_SEC");
  const maxTotalSec = num("ZERO_POC_MAX_TOTAL_SEC");
  return { image, ...(maxRuns ? { maxRuns } : {}), ...(timeoutSec ? { timeoutSec } : {}), ...(maxTotalSec ? { maxTotalSec } : {}), ...(env.ZERO_POC_ALLOW_UNBOUNDED_STORAGE === "1" ? { allowUnboundedStorage: true } : {}) };
}

/** Adds the sandbox limits to every step the verifier runs. */
function limited(runner: ContainerRunner, allowUnboundedStorage: boolean | undefined): ContainerRunner {
  return {
    get isolation() { return runner.isolation; },
    probe: () => runner.probe(),
    run: (request: StepRequest) => runner.run({ ...request, limits: { ...REPRODUCTION_LIMITS, ...(allowUnboundedStorage ? { allowUnboundedStorage: true } : {}), ...request.limits } }),
  };
}

export interface ExecutePocInput {
  finding: Pick<Finding, "severity" | "pocSteps">;
  /** The scanned folder. The only thing that is copied into the sandbox. */
  folder: string | undefined;
  runtime: ExecutedPocRuntime;
  signal?: AbortSignal;
  now?: () => Date;
}

/**
 * Returns the record to store, or undefined when the finding is not eligible
 * (below high). Never throws and never runs outside the sandbox.
 */
export async function executePocForFinding(input: ExecutePocInput): Promise<ExecutedPoc | undefined> {
  if (!isPocEligibleSeverity(input.finding.severity)) return undefined;
  const now = input.now ?? (() => new Date());
  const startedAt = now().toISOString();
  const { config, budget } = input.runtime;
  const record = (outcome: ExecutedPoc["outcome"], reason: string, stepIds: string[] = [], run?: ExecutedPocRun): ExecutedPoc => {
    const built = { schemaVersion: 1, harness: EXECUTED_POC_HARNESS, outcome, reason, stepIds, ...(run ? { run } : {}), startedAt, finishedAt: now().toISOString() };
    // Built through the parser that guards storage: an incomplete record cannot claim a result.
    return parseExecutedPoc(built) ?? { schemaVersion: 1, harness: EXECUTED_POC_HARNESS, outcome: "static-only", reason: "incomplete-record", stepIds: [], startedAt, finishedAt: built.finishedAt };
  };
  const staticOnly = (reason: string, stepIds: string[] = [], run?: ExecutedPocRun) => record("static-only", reason, stepIds, run);

  const plan = planPocSpec(input.finding.pocSteps, { image: config.image, timeoutSec: config.timeoutSec ?? POC_DEFAULT_TIMEOUT_SEC });
  if (!plan.ok) return staticOnly(plan.reason);
  if (!input.folder) return staticOnly("no-scanned-folder");
  const runner = input.runtime.runner ?? new OciRunner();
  if (runner.isolation !== "container") return staticOnly("no-container-isolation", plan.stepIds);
  if (!budget.reserve()) return staticOnly("budget-exhausted", plan.stepIds);

  const snapshot = await (async () => {
    try { return (await isGitRepo(input.folder!)) ? await snapshotWorktree(input.folder!) : undefined; } catch { return undefined; }
  })();
  if (!snapshot) return staticOnly("no-snapshot-of-the-folder", plan.stepIds);
  try {
    // A run may not outlast what is left of the scan's time budget.
    const spec = { ...plan.spec, timeoutSec: Math.max(1, Math.min(plan.spec.timeoutSec, Math.floor(budget.remainingMs / 1000))) };
    const result = await runVerifier({ spec, afterDir: snapshot.dir, runner: limited(runner, config.allowUnboundedStorage), skillId: "executed-poc", ...(input.signal ? { signal: input.signal } : {}) });
    budget.spend(result.durationMs);
    const run: ExecutedPocRun = {
      status: result.status, reason: result.reason, command: result.command, isolation: result.isolation, durationMs: result.durationMs, logTail: result.logTail,
      ...(result.imageDigest ? { imageDigest: result.imageDigest } : {}), ...(result.exitCode !== undefined ? { exitCode: result.exitCode } : {}),
    };
    if (result.isolation !== "container") return staticOnly("no-container-isolation", plan.stepIds, run);
    if (result.status === "pass") return record("executed-proven", "expectation-met", plan.stepIds, run);
    if (result.status === "fail") return record("executed-failed", result.reason === "output-did-not-match" ? "expectation-not-met" : result.reason, plan.stepIds, run);
    return staticOnly(`run-${result.reason}`, plan.stepIds, run);
  } catch {
    return staticOnly("run-infra-error", plan.stepIds);
  } finally { snapshot.cleanup(); }
}
