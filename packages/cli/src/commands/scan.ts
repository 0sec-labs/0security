/**
 * `0 scan <target>`: a thread that follows the `scan` skill, then its findings as a report.
 *
 * No scan logic lives here. The command resolves the target to a folder, starts a thread with
 * the skill and a budget, waits, and prints what the thread recorded
 * (docs/design/scan-as-a-thread.md). The thread shows up in `0 threads` like any other.
 */
import { execFile, spawn } from "node:child_process";
import { closeSync, existsSync, mkdtempSync, openSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { promisify } from "node:util";
import type { Command } from "commander";
import { buildInventory, discoverAgentSkills, exportReport, getSkillById, isReportExportFormat, resolveAgentSkillName, type Batch } from "@0/engine";
import { CoverageLedger, coverageSentence, listOsecRunDatabasePaths, osecDB, resolveOsecDbPath, summarizeCoverage } from "@0/engine/storage";
import { consoleTransportOptions, openConsole, type ConsoleClient, type ConsoleTransportOptions } from "../console-client.js";
import { homeStateDir, parseSarif, parseScannerList, scanPrompt, scannerArguments, scannerById, scannerTakesRules, SCANNERS, type KnownItem, type PrePassLeads, type BatchPromptInfo, type ScanFileCoverage, type ScanReport } from "@0/engine/shared";
import { runPrePass } from "../prepass.js";
import { checkRulesScanners, resolveRulePaths } from "../scan-rules.js";
import { applyScope, markKnown, mergePasses, scanExitCode, scanJson, toScanReport, type ScanOutcome } from "../scan-report.js";
import { followUpText, reviewDepth, reviewScopeFiles, shallowReviewWarning, toolCallText, unopenedFiles } from "../scan-review.js";
import { coverageReport, DEFAULT_RETRIES, runBatches, type BatchOutcome, type RunBatchesResult } from "../scan-batches.js";
import { classifyFailure, type FailureCause, type ScanFailure } from "../scan-failure.js";
import { coverageJson, coverageText, DEFAULT_BATCH_SIZE, planBatchedScan, type BatchedSetup } from "../scan-batched.js";
import { planScan, planText } from "../scan-plan.js";
import { interactiveScopeHint } from "../threat-interview-findings.js";
import { resumeHint, type ResumeHint } from "../scan-resume.js";
import { loadScope, loadSteering, type Steering } from "../scan-steering.js";
import { applyTierSettings, loadTierMap, repoIdentifier, resolveTier, settingsSentence, tierSentence, type ResolvedTier } from "../scan-tiers.js";
import { knownIn, leadsToFindings, loadKnown, type KnownSet } from "../scan-known.js";
import { finishWithError, UsageError } from "./output.js";
import { appendRunMetric, type RunMetric } from "../run-metrics.js";
import { applyWorkflowDefaults } from "../workflow-defaults.js";
import { asJson, finishedThread, lastAssistantText, usageLine, type FinishedThread, type Json } from "./thread-output.js";

const exec = promisify(execFile);
const FORMATS = ["json", "md", "sarif", "html", "pdf"] as const;
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const DEFAULT_BUDGET_USD = 5;
/** Chosen by measurement: on the same one-file scan it finished in 26s and $0.0014 and recorded its finding first try; glm-5.3-flash took minutes and rejected a dozen `finding` calls. */
export const DEFAULT_SCAN_MODEL = "gpt-6-luna";
const DEFAULT_TIMEOUT_SECONDS = 3600;
/** The longest one batch may run. A batch that passes it is cancelled and stays pending; the scan goes on with the next one. */
export const DEFAULT_BATCH_TIMEOUT_SECONDS = 900;
const MAX_RETRIES = 5;
/** Follow-up rounds that ask a thread to open the source files it skipped (`--coverage-rounds`). */
export const DEFAULT_COVERAGE_ROUNDS = 1;
const MAX_COVERAGE_ROUNDS = 5;
/** A follow-up round starts only with this much of the thread's budget left (a share of it, and never less than the floor). */
const ROUND_BUDGET_SHARE = 0.15;
const ROUND_BUDGET_FLOOR_USD = 0.03;
/** ...and with this much time left before the thread's limit. */
const ROUND_MIN_SECONDS = 20;
/** Messages and events a status poll asks for. A long thread's full snapshot can pass the transport limit; the status needs only the end. */
const POLL_WINDOW = 20;
/** Consecutive failed status requests before the scan gives up on the console (about a minute with the backoff). */
const MAX_FAILED_POLLS = 12;
/** Passes that run at the same time: more only crowds the model provider and the console. */
const MAX_PARALLEL_PASSES = 3;
const MAX_PASSES = 5;
/** What `--policy` and `--org-policy` run. */
const POLICY_SKILL = "policy-check";
const BATCH_MODES = ["auto", "on", "off"];
const MAX_BATCH_SIZE = 50;
const GIT_TARGET =/^(git@|git:\/\/|ssh:\/\/git@)|\.git$|^https:\/\/(github|gitlab)\.com\//;

/**
 * The arguments that run this same program as a headless console for one scan. `--port 0` takes any free port, so another
 * console on the default port (a second user, another job on a shared runner, one started from a different home) cannot make
 * this one exit with "already running" and leave the scan without a console.
 */
export function headlessConsoleArgs(entry: string | undefined, dbPath?: string): string[] {
  return [...(entry && /\.[cm]?js$/.test(entry) ? [entry] : []), "--headless", "--port", "0", ...(dbPath ? ["--db-path", dbPath] : [])];
}

export interface ScanDeps {
  open(options: ConsoleTransportOptions): Promise<ConsoleClient>;
  out(bytes: Uint8Array | string): void;
  err(text: string): void;
  sleep(ms: number): Promise<void>;
  now(): Date;
  writeBytes(path: string, bytes: Uint8Array): void;
  /** The findings stored under a thread id, as the shared report type, from the engine the thread ran on. */
  loadReport(client: ConsoleClient, threadId: string): Promise<ScanReport>;
  /** Start a headless console for this scan; returns how to stop it. Used only when none is running. */
  startConsole(dbPath?: string): Promise<(() => void) & { failure?: () => string | undefined }>;
  /** What `git status` lists in the folder, or undefined when it is not a git work tree. A scan must leave it as it found it. */
  changedFiles(folder: string): Promise<Set<string> | undefined>;
  /** Run the chosen pattern scanners on the folder for leads, or undefined when none is installed or all fail. With `rules` (absolute paths, passed to scanners that take them) it throws when such a scanner is missing or cannot run them. */
  prePass(folder: string, scanners: string[], rules?: string[], options?: { repoIgnores?: boolean }): Promise<PrePassLeads | undefined>;
  /** The files that differ from a git ref (added, copied, modified, renamed), relative to the folder. Throws when the ref is not valid there. */
  diffFiles(folder: string, ref: string): Promise<string[]>;
  /** The full id a `--skill` name stands for, or the name itself when no installed skill has it. Throws a UsageError when several do. Optional: without it the name is used as given. */
  resolveSkill?(skill: string): string;
  /** Make a folder out of a git URL. Returns the folder and how to remove it. */
  clone(url: string): Promise<{ dir: string; dispose(): void }>;
  /** The coverage ledger in the findings database (default: the local control database, or --db-path). Used by batched scans. */
  openLedger?(dbPath?: string): CoverageLedger;
  /** The commit a folder is on, or undefined when it is not a git work tree. A resumed scan refuses a different one. */
  gitHead?(folder: string): Promise<string | undefined>;
  /** Record one run in the metrics file (counts and ids only). Absent in tests, so they write nothing. */
  metrics?(record: Omit<RunMetric, "version" | "ci">): void;
  /** Store the declared-scope labels on the findings in the local findings databases. Absent in tests, so they write nothing. */
  saveScope?(labels: ScopeLabelRow[], dbPath?: string): void;
  /** The hint line for the end of a scan (findings in classes with no declared scope), or undefined. Prints only on a terminal. */
  scopeHint?(findings: ReadonlyArray<{ category: string }>, entries: ReadonlyArray<{ category?: string | undefined }>, folder: string | undefined, jsonToStdout: boolean): string | undefined;
  /** The URL of the folder's `origin` remote, or undefined. Used to find the folder's tier. */
  gitRemote?(folder: string): Promise<string | undefined>;
}
/** One finding's declared-scope label, as stored. */
export interface ScopeLabelRow { id: string; scope: "in-scope" | "out-of-scope"; reason: string; source: string }

/** Write the labels into the findings databases that hold those findings (the one named, else the shared one and the per-run ones). A database that does not hold a finding is left alone. */
function saveScopeLabels(labels: ScopeLabelRow[], dbPath?: string): void {
  if (!labels.length) return;
  const paths = dbPath ? [dbPath] : [...new Set([resolveOsecDbPath(), ...listOsecRunDatabasePaths()])].slice(0, 200);
  for (const path of paths) {
    if (!existsSync(path)) continue;
    let db: osecDB | undefined;
    try {
      db = new osecDB(path);
      for (const label of labels) if (db.getFinding(label.id)) db.setFindingScope(label.id, { scope: label.scope, reason: label.reason, source: label.source });
    } catch { /* a database that cannot be opened keeps no label; the report still carries it */ }
    finally { db?.close(); }
  }
}

export const defaultScanDeps: ScanDeps = {
  saveScope: saveScopeLabels,
  scopeHint: interactiveScopeHint,
  open: options => openConsole(options),
  out: bytes => { process.stdout.write(bytes); },
  err: text => process.stderr.write(`${text}\n`),
  sleep: ms => new Promise(resolve => setTimeout(resolve, ms)),
  now: () => new Date(),
  writeBytes: (path, bytes) => writeFileSync(path, bytes, { mode: 0o600 }),
  metrics: record => appendRunMetric(record),
  async loadReport(client, threadId) {
    const report = asJson(await client.request("GET", `/api/scans/${encodeURIComponent(threadId)}/export?format=json`));
    if (!Array.isArray(report.findings)) throw new Error("The engine returned no report for this scan.");
    return report as unknown as ScanReport;
  },
  async changedFiles(folder) {
    try {
      const { stdout } = await exec("git", ["-C", folder, "status", "--porcelain", "--untracked-files=all"], { maxBuffer: 16 * 1024 * 1024 });
      return new Set(stdout.split("\n").filter(Boolean));
    } catch { return undefined; }
  },
  async startConsole(dbPath) {
    // Run the same program again as `--headless`: the script when node runs a .js file, else the compiled binary itself.
    // Its output goes to a file, so when it dies the scan can say why instead of waiting for a console that is not coming.
    const dir = mkdtempSync(join(tmpdir(), "0-console-"));
    const logPath = join(dir, "console.log");
    const log = openSync(logPath, "a");
    const child = spawn(process.execPath, headlessConsoleArgs(process.argv[1], dbPath), { stdio: ["ignore", log, log] });
    let failure: string | undefined;
    const tail = () => { try { return readFileSync(logPath, "utf8").trim().split("\n").slice(-6).join(" | ").slice(0, 600); } catch { return ""; } };
    child.on("error", error => { failure = `it could not be started (${error.message})`; });
    child.on("exit", (code, signal) => { failure = `it exited with ${signal ?? `code ${code}`}${tail() ? `: ${tail()}` : ""}`; });
    const stop = () => { child.kill("SIGTERM"); try { closeSync(log); } catch { /* already closed */ } };
    return Object.assign(stop, { failure: () => failure });
  },
  prePass: (folder, scanners, rules = [], options) => runPrePass(folder, scanners, rules, { note: text => process.stderr.write(`${text}\n`), repoIgnores: options?.repoIgnores }),
  resolveSkill: resolveSkillId,
  async diffFiles(folder, ref) {
    const { stdout } = await exec("git", ["-C", folder, "diff", "--name-only", "--relative", "--diff-filter=ACMR", ref, "--"], { maxBuffer: 16 * 1024 * 1024 });
    return stdout.split("\n").map(line => line.trim()).filter(Boolean);
  },
  async clone(url) {
    const dir = mkdtempSync(join(tmpdir(), "0-scan-"));
    // An untrusted repository: no hooks, no external transports, shallow, and `--` before the URL.
    await exec("git", ["-c", "core.hooksPath=/dev/null", "-c", "protocol.ext.allow=never", "clone", "--depth", "1", "--quiet", "--", url, dir]);
    return { dir, dispose: () => rmSync(dir, { recursive: true, force: true }) };
  },
  openLedger: dbPath => new CoverageLedger(dbPath),
  async gitHead(folder) {
    try { return (await exec("git", ["-C", folder, "rev-parse", "HEAD"])).stdout.trim() || undefined; } catch { return undefined; }
  },
  async gitRemote(folder) {
    try { return (await exec("git", ["-C", folder, "remote", "get-url", "origin"])).stdout.trim() || undefined; } catch { return undefined; }
  },
};

interface ScanOptions extends ConsoleTransportOptions {
  budget: string; diff?: string; prepass?: string; scanner?: string[]; rules?: string[]; format: string; output?: string; timeout: string; failOn?: string; model?: string; skill: string; passes: string;
  context?: string[]; policy?: string[]; orgPolicy?: string[]; repoContext?: boolean; repoIgnores?: boolean;
  scope?: string; repoScope?: boolean; scopeSarif?: string;
  batches?: string; batchSize?: string; concurrency?: string; resume?: string; force?: boolean; coverage?: string | boolean; allowPartial?: boolean; plan?: boolean;
  tiers?: string; failOnSkip?: boolean; known?: string[]; onlyNew?: boolean;
  retries?: string; batchTimeout?: string; coverageRounds?: string;
  /** The option names the person typed (budget, batches, skill). Tier settings never override these. When unset, an option that differs from its default counts as typed. */
  explicit?: string[];
}
const FLAG_DEFAULTS: Record<string, string> = { budget: String(DEFAULT_BUDGET_USD), batches: "auto", skill: "scan" };
const explicitFlags = (options: ScanOptions): Set<string> =>
  new Set(options.explicit ?? Object.keys(FLAG_DEFAULTS).filter(name => (options as unknown as Record<string, string | undefined>)[name] !== FLAG_DEFAULTS[name]));

export interface ResolvedTarget {
  /** Where the code is on this machine. */
  folder: string;
  /** What the thread, the title and the messages call the target: the folder's path, or a git URL without credentials. */
  label: string;
  /** What the report calls it: the same on every machine (the folder's name, or the git URL without credentials). */
  reportTarget: string;
  /** Finding paths are made relative to these. */
  roots: string[];
  dispose?: () => void;
}

/** A git URL without the user name and password a CI job puts in it, which must not reach a thread, a model or a report. */
export function withoutCredentials(url: string): string {
  try {
    const parsed = new URL(url);
    if (!parsed.username && !parsed.password) return url;
    parsed.username = "";
    parsed.password = "";
    return parsed.href;
  } catch { return url; }
}

const realPath = (path: string): string => { try { return realpathSync(path); } catch { return path; } };

/** A folder or a git URL. */
export async function resolveScanTarget(raw: string, deps: Pick<ScanDeps, "clone">): Promise<ResolvedTarget> {
  const target = raw.trim();
  if (!target) throw new UsageError("Supply a folder or a git URL to scan.");
  if (GIT_TARGET.test(target)) {
    const shown = withoutCredentials(target);
    const cloned = await deps.clone(target);
    return { folder: cloned.dir, label: shown, reportTarget: shown, roots: [...new Set([cloned.dir, realPath(cloned.dir)])], dispose: cloned.dispose };
  }
  const folder = resolve(target);
  if (!existsSync(folder) || !statSync(folder).isDirectory()) {
    throw new UsageError(`${target} is not a folder. Pass a folder or a git URL.`);
  }
  return { folder, label: folder, reportTarget: basename(folder) || folder, roots: [...new Set([folder, realPath(folder)])] };
}

/**
 * `--skill review` is a built-in skill and `--skill extension/pack/review` a full id: both pass through. Any other bare
 * name is looked up once, here, among the skills you installed (extensions, personal folders), never among folders of
 * the scanned code. The scan thread then loads that full id, so a later name collision cannot change which skill runs.
 */
export function resolveSkillId(skill: string): string {
  if (skill.includes("/") || getSkillById(skill)) return skill;
  const found = resolveAgentSkillName(discoverAgentSkills({}).skills, skill);
  if (!found) return skill;
  if ("ambiguous" in found) throw new UsageError(`Several skills are named ${skill}: ${found.ambiguous.join(", ")}. Pass one of these ids to --skill.`);
  return found.id;
}

function validate(target: string | undefined, options: ScanOptions): void {
  if (options.plan) {
    if (options.resume !== undefined || options.coverage !== undefined) throw new UsageError("--plan lists what a scan would do; drop --resume and --coverage.");
    if (options.format !== "md" && options.format !== "json") throw new UsageError("--plan prints text, or JSON with --format json.");
    if (options.output) throw new UsageError("--plan prints to the terminal; drop -o.");
  }
  if (!target?.trim() && !options.plan) throw new UsageError("Supply a folder or a git URL to scan.");
  if (!/^[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*)*$/.test(options.skill) || options.skill.length > 128) throw new UsageError("--skill must be a skill id such as scan.");
  if (!(FORMATS as readonly string[]).includes(options.format)) throw new UsageError(`--format must be one of: ${FORMATS.join(", ")}.`);
  if (options.format === "pdf" && !options.output) throw new UsageError("PDF is binary; supply -o <file>.");
  if (options.prepass !== undefined && options.prepass !== "auto" && options.prepass !== "off") throw new UsageError("--prepass must be auto or off.");
  if (options.diff !== undefined && (!/^[A-Za-z0-9][A-Za-z0-9._\/~^@{}:-]{0,199}$/.test(options.diff) || options.diff.includes("..."))) throw new UsageError("--diff must be a git ref such as origin/main or HEAD~1.");
  if (options.rules?.length) { try { resolveRulePaths(options.rules); checkRulesScanners(options.scanner, options.prepass); } catch (error) { throw new UsageError(error instanceof Error ? error.message : String(error)); } }
  try { parseScannerList(options.scanner); } catch (error) { throw new UsageError(error instanceof Error ? error.message : String(error)); }
  if ((options.policy?.length || options.orgPolicy?.length) && options.skill !== "scan" && options.skill !== POLICY_SKILL) throw new UsageError(`--policy and --org-policy run the ${POLICY_SKILL} skill; drop --skill ${options.skill}.`);
  const budget = Number(options.budget);
  if (!Number.isFinite(budget) || budget <= 0 || budget > 1000) throw new UsageError("--budget must be a positive USD amount up to 1000.");
  const passes = Number(options.passes);
  if (!Number.isInteger(passes) || passes < 1 || passes > MAX_PASSES) throw new UsageError(`--passes must be a whole number from 1 to ${MAX_PASSES}.`);
  if (options.batches !== undefined && !BATCH_MODES.includes(options.batches)) throw new UsageError("--batches must be auto, on or off.");
  const batchSize = Number(options.batchSize ?? DEFAULT_BATCH_SIZE);
  if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > MAX_BATCH_SIZE) throw new UsageError(`--batch-size must be a whole number from 1 to ${MAX_BATCH_SIZE}.`);
  const concurrency = Number(options.concurrency ?? 1);
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > MAX_PARALLEL_PASSES) throw new UsageError(`--concurrency must be a whole number from 1 to ${MAX_PARALLEL_PASSES}.`);
  if ((options.batches === "on" || options.resume !== undefined) && passes > 1) throw new UsageError("--passes cannot be combined with batches or --resume; run the scan again to get another pass.");
  if (options.onlyNew && !options.known?.length) throw new UsageError("--only-new needs --known <sarif>.");
  if (options.known?.length && (options.policy?.length || options.orgPolicy?.length)) throw new UsageError("--known is for scans; it cannot be combined with --policy or --org-policy.");
  if (options.resume !== undefined) {
    if (options.batches === "off") throw new UsageError("--resume continues a batched scan; drop --batches off.");
    if (options.diff) throw new UsageError("--resume continues the units of an earlier scan; drop --diff.");
    if (GIT_TARGET.test((target ?? "").trim())) throw new UsageError("--resume works on a folder on this machine, not a git URL.");
  }
  if (options.coverage !== undefined && GIT_TARGET.test((target ?? "").trim())) throw new UsageError("--coverage reads the ledger of a folder on this machine, not a git URL.");
  if (options.force && options.resume === undefined) throw new UsageError("--force only applies to --resume.");
  const seconds = Number(options.timeout);
  if (!Number.isFinite(seconds) || seconds <= 0) throw new UsageError("--timeout must be a positive number of seconds.");
  const batchSeconds = Number(options.batchTimeout ?? DEFAULT_BATCH_TIMEOUT_SECONDS);
  if (!Number.isFinite(batchSeconds) || batchSeconds <= 0) throw new UsageError("--batch-timeout must be a positive number of seconds.");
  const retries = Number(options.retries ?? DEFAULT_RETRIES);
  if (!Number.isInteger(retries) || retries < 0 || retries > MAX_RETRIES) throw new UsageError(`--retries must be a whole number from 0 to ${MAX_RETRIES}.`);
  const rounds = Number(options.coverageRounds ?? DEFAULT_COVERAGE_ROUNDS);
  if (!Number.isInteger(rounds) || rounds < 0 || rounds > MAX_COVERAGE_ROUNDS) throw new UsageError(`--coverage-rounds must be a whole number from 0 to ${MAX_COVERAGE_ROUNDS}.`);
  if (options.failOn !== undefined && !(SEVERITIES as readonly string[]).includes(options.failOn)) throw new UsageError(`--fail-on must be one of: ${SEVERITIES.join(", ")}.`);
}

const NO_CONSOLE = /No console running/;

/** The engine to run on: the one the options name or that is already running, else a headless one started for this scan. */
export async function connect(options: ConsoleTransportOptions, deps: Pick<ScanDeps, "open" | "err" | "sleep" | "startConsole">): Promise<{ client: ConsoleClient; stop?: () => void }> {
  const message = (error: unknown) => (error instanceof Error ? error.message : String(error));
  try { return { client: await deps.open(options) }; }
  catch (error) { if (!NO_CONSOLE.test(message(error))) throw error; }
  deps.err("no console is running; starting one for this scan");
  const stop = await deps.startConsole(options.dbPath);
  for (let attempt = 0; attempt < 60; attempt++) {
    try { return { client: await deps.open(options), stop }; }
    catch (error) { if (!NO_CONSOLE.test(message(error))) { stop(); throw error; } }
    // A console that already died is not coming; say why now instead of waiting out the clock.
    const failure = stop.failure?.();
    if (failure) { stop(); throw new Error(`The console this scan starts for itself stopped: ${failure}. Start one with \`0security --headless\` and run the scan again.`); }
    await deps.sleep(500);
  }
  stop();
  throw new Error("Could not start a console within 30s. Start one with `0security --headless` and run the scan again.");
}

interface PassContext { /** The source files a thread is expected to open (empty: no check). */ scopeFiles: readonly string[]; prePass?: PrePassLeads; scope?: string[]; known?: KnownItem[]; extras: Partial<ScanOutcome>; steering: Steering; client: ConsoleClient; deps: ScanDeps; resolved: ResolvedTarget; options: ScanOptions; total: number; budget: number; deadline: number }
interface PassResult { threadId: string; done: FinishedThread; stored: ScanReport; budgetExhausted: boolean; timedOut: boolean; /** The batch's own time limit passed before the scan's. */ batchTimedOut: boolean; /** Why the thread failed, when it did and it was not the budget or a time limit. */ failure?: ScanFailure; /** What the thread's tool calls named, across every attempt (a continued thread keeps one transcript). */ toolCalls: string; /** The in-scope files this thread was to open, the ones it did not open, and the follow-up rounds sent. */ files: { expected: readonly string[]; unopened: readonly string[]; rounds: number }; /** The thread was asked to continue once after a transient failure. */ resumed?: boolean; costUsd?: number }

const retryCount = (options: ScanOptions): number => Number(options.retries ?? DEFAULT_RETRIES);
export const coverageRounds = (options: Pick<ScanOptions, "coverageRounds">): number => Number(options.coverageRounds ?? DEFAULT_COVERAGE_ROUNDS);

/** Poll a thread until it finishes, the deadline passes (it is then cancelled) or the console is lost for too long. */
export async function waitForThread(client: ConsoleClient, deps: Pick<ScanDeps, "sleep">, id: string, deadline: number, windowed = false): Promise<{ snapshot: Json; timedOut: boolean }> {
  const path = `/api/console/sessions/${encodeURIComponent(id)}`;
  // A scan's thread can be long: ask for the end of it only (windowed), which holds the status, usage and last reply.
  const poll = windowed ? `${path}?window=${POLL_WINDOW}&workers=summary` : path;
  let snapshot: Json = {};
  let timedOut = false;
  let failedPolls = 0;
  for (;;) {
    await deps.sleep(1000);
    try {
      snapshot = asJson(asJson(await client.request("GET", poll)).snapshot);
      failedPolls = 0;
    } catch (error) {
      // A console busy with several scans, or a provider timing out, can miss a status request while the thread keeps working.
      // Give up only after a run of failures, and say where the thread is.
      if (++failedPolls > MAX_FAILED_POLLS) {
        throw new Error(`Lost contact with the console while scanning: ${error instanceof Error ? error.message : String(error)}. The scan may still be running as thread ${id}; its findings are kept (\`0security findings export --scan ${id}\`).`);
      }
      await deps.sleep(Math.min(5000, 1000 * failedPolls));
      continue;
    }
    const session = asJson(snapshot.session);
    const finished = ["failed", "closed", "waiting"].includes(String(session.status)) || (session.status === "ready" && (lastAssistantText(snapshot) !== undefined || snapshot.lastOutcome != null));
    if (finished) break;
    if (Date.now() > deadline) {
      // Stop the thread and report what it stored so far; a scan that ran out of time still has findings.
      timedOut = true;
      await client.request("POST", `${path}/cancel`, {}).catch(() => undefined);
      await deps.sleep(2000);
      snapshot = await client.request("GET", poll).then(value => asJson(asJson(value).snapshot), () => snapshot);
      break;
    }
  }
  return { snapshot, timedOut };
}

const RESUME_TEXT = "The connection to the model failed part way. Continue the scan from where you stopped. Do not record findings again that you already recorded.";

/** Why a finished thread failed, or undefined when it did not (a budget stop and a time limit are not failures here). */
function threadFailure(done: FinishedThread, budgetExhausted: boolean, timedOut: boolean): ScanFailure | undefined {
  if (!done.failed || budgetExhausted || timedOut) return undefined;
  if (done.claimBlocked && !done.error) return { cause: "unknown", transient: false, message: "The scan's answer was not backed by its checks" };
  return classifyFailure(done.error);
}

/** One scan thread: start it, wait for it, and read what it stored. Throws when the thread cannot run or the console is lost. */
interface PassExtra { /** The files this thread is expected to open (a batch's files); default: every in-scope file. */ files?: readonly string[]; batch?: BatchPromptInfo; budget?: number; prePass?: PrePassLeads | undefined; known?: KnownItem[] }
async function runPass(ctx: PassContext, index: number, extra: PassExtra = {}): Promise<PassResult> {
  const { client, deps, resolved, options, total, deadline } = ctx;
  const budget = extra.budget ?? ctx.budget;
  const prePass = "prePass" in extra ? extra.prePass : ctx.prePass;
  const runtime = { runtime: { model: options.model ?? DEFAULT_SCAN_MODEL } };
  const part = extra.batch ? `batch ${extra.batch.index + 1} of ${extra.batch.total}` : total > 1 ? `pass ${index + 1} of ${total}` : "";
  const title = part ? `Scan ${resolved.label} (${part})` : `Scan ${resolved.label}`;
  const created = asJson(asJson(await client.request("POST", "/api/console/sessions", { ...runtime, title, costCeilingUsd: budget })).session);
  const id = String(created.id);
  const path = `/api/console/sessions/${encodeURIComponent(id)}`;
  try {
    await client.request("PATCH", `${path}/configuration`, { workspacePath: resolved.folder });
    await client.request("POST", `${path}/messages`, { text: scanPrompt(resolved.label, options.skill, prePass, ctx.scope, ctx.steering, extra.batch, "known" in extra ? extra.known : ctx.known) });
  } catch (error) {
    // A thread that never started is no use to anyone; do not leave it in the list.
    const removed = await client.request("POST", `${path}/delete`, {}).then(() => true, () => false);
    const reason = error instanceof Error ? error.message : String(error);
    const hint = /model/i.test(reason) && !/No provider credential found/i.test(reason) ? ` Pick another with --model (default ${DEFAULT_SCAN_MODEL}).` : "";
    throw new Error(`${reason}${hint}${removed ? "" : ` (thread ${id} was created; remove it with \`0security threads delete ${id} --yes\`)`}`);
  }
  deps.err(`scanning ${resolved.label} in thread ${id} (${part ? `${part}, ` : ""}budget $${Number(budget.toFixed(4))})`);

  // A batch has its own limit, so one stuck thread cannot use the time of the whole scan.
  const batchDeadline = extra.batch ? Date.now() + Number(options.batchTimeout ?? DEFAULT_BATCH_TIMEOUT_SECONDS) * 1000 : Infinity;
  const limit = Math.min(deadline, batchDeadline);
  let waited = await waitForThread(client, deps, id, limit, true);
  let resumed = false;
  // A thread that is not a batch has no retry loop around it. When the connection or the provider fails it once, ask it to
  // continue: its context and the findings it recorded stay.
  if (!extra.batch && retryCount(options) > 0 && !waited.timedOut) {
    const first = finishedThread(waited.snapshot);
    const firstFailure = threadFailure(first, false, false);
    if (first.failed && firstFailure?.transient && Date.now() < limit && !asJson(first.session).costCeilingExceeded) {
      deps.err(`${firstFailure.message}; asking thread ${id} to continue (the findings so far are kept)`);
      try {
        await deps.sleep(2000);
        await client.request("POST", `${path}/messages`, { text: RESUME_TEXT });
        waited = await waitForThread(client, deps, id, limit, true);
        resumed = true;
      } catch (error) { deps.err(`could not continue thread ${id}: ${error instanceof Error ? error.message : String(error)}`); }
    }
  }

  // Which source files the thread opened. The status polls see the end of the thread only, so read the whole transcript once.
  const transcript = async (windowed: Json): Promise<string> => {
    try { return toolCallText(asJson(asJson(await client.request("GET", path)).snapshot)); } catch { return toolCallText(windowed); }
  };
  const expected = extra.files ?? ctx.scopeFiles;
  const allowed = coverageRounds(options);
  let calls = expected.length ? await transcript(waited.snapshot) : "";
  let unopened = expected.length ? unopenedFiles(expected, calls, resolved.folder) : [];
  let rounds = 0;
  let stalled = 0;
  let lastRoundCost = 0;
  // Enforcement is not a retry: it runs only after a thread that ended normally, and never after a failure, a time limit or a budget stop.
  while (unopened.length && rounds < allowed && !waited.timedOut) {
    const before = finishedThread(waited.snapshot);
    if (before.failed || before.claimBlocked) break;
    const spent = typeof before.usage.costUsd === "number" ? before.usage.costUsd : undefined;
    const left = spent === undefined ? budget : budget - spent;
    if (left < Math.max(ROUND_BUDGET_FLOOR_USD, budget * ROUND_BUDGET_SHARE, lastRoundCost * 1.5)) { deps.err(`thread ${id}: ${unopened.length} source file${unopened.length === 1 ? "" : "s"} not opened; no follow-up round, too little of the $${Number(budget.toFixed(4))} budget is left`); break; }
    if (Date.now() + ROUND_MIN_SECONDS * 1000 > limit) { deps.err(`thread ${id}: ${unopened.length} source file${unopened.length === 1 ? "" : "s"} not opened; no follow-up round, too little time is left`); break; }
    deps.err(`thread ${id}: opened ${expected.length - unopened.length} of ${expected.length} source files; asking it to open the other ${unopened.length} (follow-up round ${rounds + 1} of ${allowed})`);
    try { await client.request("POST", `${path}/messages`, { text: followUpText(unopened) }); }
    catch (error) { deps.err(`could not send the follow-up to thread ${id}: ${error instanceof Error ? error.message : String(error)}`); break; }
    waited = await waitForThread(client, deps, id, limit, true);
    rounds++;
    const after = finishedThread(waited.snapshot);
    if (typeof after.usage.costUsd === "number" && spent !== undefined) lastRoundCost = Math.max(0, after.usage.costUsd - spent);
    calls = await transcript(waited.snapshot);
    const still = unopenedFiles(expected, calls, resolved.folder);
    const opened = unopened.length - still.length;
    deps.err(`thread ${id}: follow-up round ${rounds} opened ${opened} of ${unopened.length} file${unopened.length === 1 ? "" : "s"}`);
    stalled = opened > 0 ? 0 : stalled + 1;
    unopened = still;
    // A model that opens nothing twice in a row is not going to; stop asking.
    if (stalled >= 2) break;
  }
  const { snapshot, timedOut } = waited;
  const done = finishedThread(snapshot);
  const costUsd = typeof done.usage.costUsd === "number" ? done.usage.costUsd : undefined;
  const budgetExhausted = asJson(done.session).costCeilingExceeded === true;
  const batchTimedOut = timedOut && limit < deadline;
  const failure = threadFailure(done, budgetExhausted, timedOut);
  return { threadId: id, done, stored: await deps.loadReport(client, id), budgetExhausted, timedOut: timedOut && !batchTimedOut, batchTimedOut, toolCalls: calls || toolCallText(snapshot), files: { expected, unopened, rounds }, ...(failure ? { failure } : {}), ...(resumed ? { resumed } : {}), ...(costUsd !== undefined ? { costUsd } : {}) };
}

/** Run `count` tasks, at most `limit` at a time, in order of index. */
async function inPool<T>(count: number, limit: number, task: (index: number) => Promise<T>): Promise<T[]> {
  const results: T[] = new Array(count);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, count) }, async () => {
    while (next < count) { const index = next++; results[index] = await task(index); }
  }));
  return results;
}

/** Format the report and write it to --output or standard output. */
async function writeReport(outcome: ScanOutcome, merged: ReturnType<typeof mergePasses>, stored: ScanReport, name: string, options: ScanOptions, deps: Pick<ScanDeps, "out" | "err" | "writeBytes" | "metrics" | "saveScope" | "scopeHint">): Promise<void> {
  // An empty-diff scan (thread "none") writes no line. A tier skip and a pre-pass-only run do: they are runs the operator chose.
  if (outcome.threadId !== "none" || outcome.tier?.skipped || outcome.tier?.prepassOnly) {
    const status = outcome.failed ? "failed" : outcome.tier?.skipped ? "skipped" : outcome.tier?.prepassOnly ? "prepass_only" : outcome.timedOut ? "timeout" : outcome.budgetExhausted ? "budget" : "ok";
    deps.metrics?.({ at: outcome.startedAt, command: "scan", model: options.model ?? DEFAULT_SCAN_MODEL, budgetUsd: outcome.budgetUsd, costUsd: outcome.costUsd ?? null, durationSeconds: Math.max(0, Math.round((Date.parse(outcome.completedAt) - Date.parse(outcome.startedAt)) / 1000)), findingsAttempted: null, findingsProposed: merged.length, checksPassed: null, tokens: null, status, findingIds: merged.map(finding => finding.id) });
  }
  if (outcome.scope) {
    const labelled = applyScope(outcome, merged).filter(finding => finding.scope);
    const out = labelled.filter(finding => finding.scope === "out-of-scope").length;
    deps.saveScope?.(labelled.flatMap(finding => [finding.id, ...(finding.mergedFindingIds ?? [])].map(id => ({ id, scope: finding.scope!, reason: finding.scopeReason ?? "", source: finding.scopeSource ?? outcome.scope!.source }))), options.dbPath);
    deps.err(`scope (${outcome.scope.source}): ${out} finding${out === 1 ? "" : "s"} outside the declared scope, listed apart and left out of the counts and --fail-on`);
  }
  let body: Uint8Array | string;
  if (options.format === "json") body = `${JSON.stringify(scanJson(outcome, merged), null, 2)}\n`;
  else {
    const format = options.format === "md" ? "markdown" : options.format;
    if (!isReportExportFormat(format)) throw new UsageError(`--format must be one of: ${FORMATS.join(", ")}.`);
    body = (await exportReport(toScanReport(outcome, stored), format, name)).body;
  }
  if (options.output) {
    const bytes = typeof body === "string" ? new TextEncoder().encode(body) : body;
    deps.writeBytes(options.output, bytes);
    deps.err(`Wrote ${options.output} (${bytes.byteLength} bytes)`);
  } else deps.out(body);
  const hint = deps.scopeHint?.(merged, outcome.scope?.entries ?? [], outcome.roots?.[0], options.format === "json" && !options.output);
  if (hint) deps.err(hint);
}

/** The thread has the same tools as any thread, so it could edit the code it reads. The message to show if it did, else undefined. */
async function unexpectedChanges(deps: Pick<ScanDeps, "changedFiles">, folder: string, before: Set<string> | undefined): Promise<string | undefined> {
  const after = before ? await deps.changedFiles(folder) : undefined;
  const changed = before && after ? [...after].filter(line => !before.has(line)) : [];
  return changed.length
    ? `The scan changed ${changed.length} file${changed.length === 1 ? "" : "s"} in the target (${changed.slice(0, 5).map(line => line.slice(3)).join(", ")}${changed.length > 5 ? ", ..." : ""}). A scan must not edit the code it reads; review and revert them.`
    : undefined;
}

/** `--plan`: list the inventory, the batches and a rough cost, and start nothing: no console, no model, no scanner, no database. */
async function printPlan(resolved: ResolvedTarget, options: ScanOptions, deps: ScanDeps, tier?: ResolvedTier): Promise<void> {
  let scope: string[] | undefined;
  if (options.diff) {
    try { scope = await deps.diffFiles(resolved.folder, options.diff); }
    catch { throw new UsageError(`'${options.diff}' is not a git ref in ${resolved.label}, or the folder is not a git work tree.`); }
  }
  const inventory = buildInventory(resolved.folder, scope ? { only: new Set(scope) } : {});
  const plan = planScan(inventory, { folder: resolved.label, batchSize: Number(options.batchSize ?? DEFAULT_BATCH_SIZE), batchesMode: options.batches ?? "auto", budgetUsd: Number(options.budget), ...(tier ? { tier: tierInfo(tier) } : {}) });
  deps.out(options.format === "json" ? `${JSON.stringify(plan, null, 2)}\n` : `${planText(plan)}\n`);
}

/** `--coverage`: print the ledger of a scan of this folder (the latest, or the id given) and start nothing. */
async function printCoverage(resolved: ResolvedTarget, options: ScanOptions, deps: ScanDeps): Promise<void> {
  const ledger = (deps.openLedger ?? defaultScanDeps.openLedger!)(options.dbPath);
  try {
    const wanted = typeof options.coverage === "string" && options.coverage.trim() ? options.coverage.trim() : "latest";
    const scan = wanted === "latest" ? ledger.latestScan(resolved.folder) : ledger.getScan(wanted);
    if (!scan) throw new UsageError(wanted === "latest" ? `No batched scan of ${resolved.folder} is recorded. A scan is batched when the folder has more entry points than one thread takes; see --batches.` : `No scan ${wanted} in the findings database.`);
    const units = ledger.units(scan.id);
    const body = options.format === "json" ? `${JSON.stringify(coverageJson(scan, units), null, 2)}\n` : `${coverageText(scan, units)}\n`;
    if (options.output) deps.writeBytes(options.output, new TextEncoder().encode(body)); else deps.out(body);
  } finally { ledger.close(); }
}

/** The failure a report carries: the cause of a failed scan, of a batch that failed or timed out, of the budget or the time limit. */
function scanFailure(input: { failed: boolean; changedError?: string | undefined; budgetExhausted: boolean; timedOut: boolean; batchFailures: ReadonlyArray<{ batch?: number; cause: FailureCause; message: string }>; hardError?: string | undefined }): ScanFailure | undefined {
  if (input.changedError) return classifyFailure(input.changedError, "target_changed");
  const first = input.batchFailures[0];
  // A batch failure already has its plain message; it is carried over as it is.
  const carried = first ? { cause: first.cause, transient: false, message: first.message } : undefined;
  if (input.failed) return carried ?? classifyFailure(input.hardError);
  if (carried) return carried;
  if (input.budgetExhausted) return classifyFailure(undefined, "budget");
  if (input.timedOut) return classifyFailure(undefined, "timeout");
  return undefined;
}

const emptyStoredReport = (startedAt: string): ScanReport => ({ target: "", scanDepth: "default", startedAt, completedAt: startedAt, durationMs: 0, summary: { totalAttacks: 0, totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }, findings: [], warnings: [] } as unknown as ScanReport);

/** Which of the files the threads were to open they opened, over all of them; undefined when no file was expected. */
function fileCoverageOf(passes: readonly PassResult[], allowed: number): ScanFileCoverage | undefined {
  // A file belongs to one batch, but two passes (several --passes) may both be asked about it: it counts as opened when any pass opened it.
  const expected = new Set(passes.flatMap(pass => pass.files.expected));
  if (!expected.size) return undefined;
  const missed = [...expected].filter(file => passes.filter(pass => pass.files.expected.includes(file)).every(pass => pass.files.unopened.includes(file))).sort();
  return { inScope: expected.size, opened: expected.size - missed.length, unopened: missed.slice(0, 100), unopenedCount: missed.length, rounds: { allowed, used: passes.reduce((sum, pass) => sum + pass.files.rounds, 0) } };
}

/**
 * The batched flow: one thread per batch of units, a ledger row per unit, and a report that says how much was reviewed.
 * A unit is reviewed only when its batch's thread finished normally; everything else stays pending with the reason.
 */
async function runBatchedScan(ctx: PassContext, setup: BatchedSetup, before: Set<string> | undefined, startedAt: string, budget: number): Promise<void> {
  const { client, deps, resolved, options } = ctx;
  const { ledger, scan } = setup;
  const ran = new Map<string, PassResult>();
  const count = setup.batches.length;
  deps.err(`${setup.resumed ? `resuming scan ${scan.id}` : `scan ${scan.id}`}: ${setup.summaryText} ${count ? `${count} batch${count === 1 ? "" : "es"} to run` : "nothing is pending"}`);

  const run = await runBatches({
    batches: setup.batches, ledger, scanId: scan.id, budgetUsd: budget, deadline: ctx.deadline, concurrency: Number(options.concurrency ?? 1), log: deps.err, retries: retryCount(options), sleep: deps.sleep,
    run: async (batch: Batch, batchBudget: number): Promise<BatchOutcome> => {
      // Hits of the pattern scanners that sit in this batch's files are its leads; the others belong to other batches.
      const files = new Set(batch.units.flatMap(unit => unit.files ?? [unit.path]));
      const leads = ctx.prePass?.leads.filter(lead => lead.path !== undefined && files.has(lead.path)) ?? [];
      const prePass = ctx.prePass && leads.length ? { ...ctx.prePass, leads, total: leads.length } : undefined;
      const info: BatchPromptInfo = { index: batch.index, total: count, units: batch.units, summary: setup.summaryText };
      const inScope = new Set(ctx.scopeFiles);
      const pass = await runPass(ctx, batch.index, { batch: info, budget: batchBudget, prePass, files: [...files].filter(file => inScope.has(file)).sort(), ...(ctx.known ? { known: knownIn(ctx.known, files) } : {}) });
      ran.set(pass.threadId, pass);
      const hardFailure = pass.done.failed && !pass.budgetExhausted && !pass.timedOut && !pass.batchTimedOut;
      const reviewed = !pass.done.failed && !pass.done.claimBlocked && !pass.budgetExhausted && !pass.timedOut && !pass.batchTimedOut;
      // A batch that hit its own time limit was cancelled by the scan: that is a timeout, not a provider failure.
      const failure = pass.batchTimedOut ? classifyFailure(undefined, "batch_timeout") : pass.failure;
      return {
        threadId: pass.threadId, reviewed,
        ...(pass.costUsd !== undefined ? { costUsd: pass.costUsd } : {}), budgetExhausted: pass.budgetExhausted, timedOut: pass.timedOut, failed: hardFailure || pass.done.claimBlocked,
        ...(pass.batchTimedOut ? { batchTimedOut: true } : {}),
        ...(pass.done.error ? { error: pass.done.error } : {}), ...(failure && !reviewed ? { failure } : {}),
        // A unit counts as reviewed only when the thread opened its files (with --coverage-rounds 0 the check is off).
        ...(reviewed && coverageRounds(options) > 0 && pass.files.unopened.length ? { notOpenedUnitIds: batch.units.filter(unit => (unit.files ?? [unit.path]).some(file => pass.files.unopened.includes(file))).map(unit => unit.id) } : {}),
      };
    },
  });
  const firstError = run.outcomes.map(item => item.outcome.error).find(Boolean);
  if (count && !ran.size && run.outcomes.length) throw new Error(`No batch could run${firstError ? `: ${firstError}` : "."}`);
  for (const item of run.outcomes) if (!item.outcome.reviewed && item.outcome.error && item.outcome.threadId === undefined) deps.err(`batch ${item.batch.index + 1}: ${item.outcome.error}`);

  const units = ledger.units(scan.id);
  const summary = summarizeCoverage(scan.id, units);
  const fileCoverage = fileCoverageOf([...ran.values()], coverageRounds(options));
  // Files of a thread that finished and were never opened: their units are pending ("not opened"), and the sentence says so.
  const neverOpened = coverageRounds(options) > 0 ? new Set([...ran.values()].filter(pass => !pass.done.failed && !pass.budgetExhausted && !pass.timedOut && !pass.batchTimedOut).flatMap(pass => pass.files.unopened)).size : 0;
  const statement = `${coverageSentence(summary)}${neverOpened ? `; ${neverOpened} file${neverOpened === 1 ? "" : "s"} never opened` : ""}`;
  const failures = run.failures.length ? run.failures.map(item => item.message) : run.outcomes.filter(item => !item.outcome.reviewed && item.outcome.failed).map(item => item.outcome.error ?? "no reason given");
  const hint: ResumeHint | undefined = resumeHint(resolved.label, summary, { budgetHit: run.budgetHit, budgetUsd: budget, timedOut: run.timedOut, timeoutSeconds: Number(options.timeout), failures });
  const coverage = { ...coverageReport(summary, statement, units, { retried: run.retried, failures: run.failures, retriesAllowed: retryCount(options), ...(fileCoverage ? { files: fileCoverage } : {}) }), ...(hint ? { resume: hint.command, stoppedBy: hint.stoppedBy } : {}) };
  // Findings of every thread of this scan, including the threads an earlier run started and partial batches.
  const threadIds = ledger.getScan(scan.id)?.threadIds ?? [...ran.keys()];
  const stored: ScanReport[] = [];
  for (const id of threadIds) {
    const pass = ran.get(id);
    if (pass) { stored.push(pass.stored); continue; }
    try { stored.push(await deps.loadReport(client, id)); }
    catch (error) { deps.err(`could not read the findings of thread ${id} from an earlier run: ${error instanceof Error ? error.message : String(error)}`); }
  }
  // Batches are not passes: the same flaw found from two batches is one finding, with no "found in N passes" note.
  const merged = mergePasses(stored.map(report => report.findings), resolved.roots).map(({ foundInPasses: _ignored, ...finding }) => finding);
  const changedError = await unexpectedChanges(deps, resolved.folder, before);
  if (changedError) deps.err(changedError);

  const customLeads = ctx.prePass?.leads.filter(lead => lead.ruleSource === "custom") ?? [];
  const results = [...ran.values()];
  const cost = results.reduce((sum, result) => sum + (result.costUsd ?? 0), 0);
  const costKnown = results.some(result => result.costUsd !== undefined);
  const failed = (results.length > 0 && results.every(result => (result.done.failed && !result.budgetExhausted && !result.timedOut) || result.done.claimBlocked)) || changedError !== undefined;
  const lead = results.reduce<PassResult | undefined>((best, result) => (!best || result.stored.findings.length > best.stored.findings.length ? result : best), undefined);
  const hardError = results.map(result => (!result.budgetExhausted && !result.timedOut ? result.done.error : undefined)).find(Boolean);
  const failure = scanFailure({ failed, changedError, budgetExhausted: run.budgetHit, timedOut: run.timedOut, batchFailures: run.failures, hardError });
  for (const item of run.retried) if (!item.recovered) deps.err(`batch ${item.batch}: still failing after ${item.attempts - 1} ${item.attempts === 2 ? "retry" : "retries"}`);
  const outcome: ScanOutcome = {
    target: resolved.reportTarget, roots: resolved.roots, threadId: threadIds[0] ?? "none", startedAt, completedAt: deps.now().toISOString(), budgetUsd: budget,
    ...(costKnown ? { costUsd: cost } : {}), budgetExhausted: run.budgetHit, ...(run.timedOut ? { timedOut: true } : {}), failed, ...(options.allowPartial ? { allowPartial: true } : {}),
    ...(changedError ? { error: changedError } : failed && hardError ? { error: hardError } : {}), ...(failure ? { failure } : {}),
    // The thread's own summary can say it covered everything; the ledger's account comes first.
    summary: `Coverage: ${statement}.${lead?.done.reply ? `\n\n${lead.done.reply}` : ""}`,
    coverage, ...(threadIds.length > 1 ? { threadIds } : {}),
    ...(customLeads.length ? { customLeads } : {}),
    ...ctx.extras,
  };
  const base = stored[0] ?? emptyStoredReport(startedAt);
  await writeReport(outcome, merged, { ...base, findings: merged }, `0-scan-${threadIds[0] ?? scan.id}`, options, deps);
  noteKnown(outcome, merged, deps);
  if (failure && !failure.cause.startsWith("budget") && failure.cause !== "timeout") deps.err(`scan ${failed ? "failed" : "stopped early"}: ${failure.message}`);
  if (fileCoverage) deps.err(`opened ${fileCoverage.opened} of ${fileCoverage.inScope} source files${fileCoverage.rounds.used ? ` after ${fileCoverage.rounds.used} follow-up round${fileCoverage.rounds.used === 1 ? "" : "s"}` : ""}`);
  deps.err(`${merged.length} finding${merged.length === 1 ? "" : "s"}; ${statement}${hint ? `\n${hint.text}` : ""}\nUsage: ${count} batch${count === 1 ? "" : "es"}, cost ${costKnown ? `$${cost.toFixed(4)}` : "unknown"}`);
  const code = scanExitCode(outcome, merged, options.failOn as typeof SEVERITIES[number] | undefined);
  if (code !== 0) process.exitCode = code;
}

/** The part of a resolved tier the report carries. */
const tierInfo = ({ settings: _settings, file: _file, ...info }: ResolvedTier) => info;

/** On stderr: how many findings are new, already known and confirmed independently. */
function noteKnown(outcome: ScanOutcome, merged: Parameters<typeof markKnown>[1], deps: Pick<ScanDeps, "err">): void {
  const { summary } = markKnown(outcome, merged);
  if (!summary) return;
  const { new: fresh, alreadyKnown, confirmedIndependently } = summary.findings;
  deps.err(`known findings: ${fresh} new, ${alreadyKnown} already known (${confirmedIndependently} confirmed independently)${summary.hidden ? `; ${summary.hidden} hidden by --only-new` : ""}`);
}

/** The tier map for this target: which tier applies, or undefined when no tier map exists. Says on stderr which tier applied and why. */
async function pickTier(resolved: ResolvedTarget, target: string, options: ScanOptions, deps: ScanDeps): Promise<ResolvedTier | undefined> {
  const map = loadTierMap(options.tiers, homeStateDir());
  if (!map) return undefined;
  const isUrl = GIT_TARGET.test(target.trim());
  const remote = isUrl ? target.trim() : await (deps.gitRemote ?? defaultScanDeps.gitRemote!)(resolved.folder);
  const repo = repoIdentifier(remote);
  const path = isUrl ? undefined : realPath(resolved.folder).replace(/\\/g, "/");
  // A tier file that sits inside the scanned folder can be edited by the change under review.
  if (options.tiers && !isUrl) {
    const root = `${realPath(resolved.folder).replace(/\\/g, "/").replace(/\/+$/, "")}/`;
    if (realPath(resolve(options.tiers)).replace(/\\/g, "/").startsWith(root)) deps.err(`warning: --tiers ${options.tiers} is inside the folder being scanned. Whoever can change that folder can change its tier. In CI read the tier file from the base branch or a separate checkout.`);
  }
  return resolveTier(map, { ...(repo ? { repo } : {}), ...(path ? { path } : {}) });
}

/** The pre-pass as the main scan runs it: main's isolation arguments, and the warning when --repo-ignores lets the folder's own ignore files in. */
async function runPrePassFor(deps: ScanDeps, folder: string, options: ScanOptions): Promise<PrePassLeads | undefined> {
  if (options.repoIgnores) deps.err("warning: --repo-ignores makes the pre-pass scanners read configuration and ignore files from the scanned folder (.foxguard.yml, .semgrepignore, .gitleaks.toml, .gitleaksignore, .trivyignore, osv-scanner.toml, .checkov.yaml). A change under review can use them to hide findings. Inline suppressions such as gitleaks:allow, nosemgrep and trivy:ignore apply with or without this flag.");
  const scanners = parseScannerList(options.scanner);
  const rules = resolveRulePaths(options.rules);
  return options.repoIgnores
    ? deps.prePass(folder, scanners, rules, { repoIgnores: true })
    : rules.length ? deps.prePass(folder, scanners, rules) : deps.prePass(folder, scanners);
}

/** A tier that runs the pattern scanners only: no console, no model. The leads become findings that say so. */
async function runPrePassOnly(resolved: ResolvedTarget, options: ScanOptions, deps: ScanDeps, scope: string[] | undefined, extras: Partial<ScanOutcome>, startedAt: string): Promise<void> {
  let prePass = await runPrePassFor(deps, resolved.folder, options);
  if (prePass && scope) {
    const inScope = new Set(scope);
    const leads = prePass.leads.filter(lead => lead.path !== undefined && inScope.has(lead.path));
    prePass = { ...prePass, leads, total: leads.length };
  }
  const budget = Number(options.budget);
  const base = { target: resolved.reportTarget, roots: resolved.roots, threadId: "none", startedAt, completedAt: deps.now().toISOString(), budgetUsd: budget, budgetExhausted: false, ...(options.allowPartial ? { allowPartial: true } : {}) };
  // With no scanner at all nothing was reviewed: that is a failure, not a clean result.
  const outcome: ScanOutcome = prePass
    ? { ...base, failed: false, summary: `Pre-pass only (${extras.tier?.name ?? "tier"}): ${prePass.tools.join(", ")} reported ${prePass.total} hit${prePass.total === 1 ? "" : "s"}. No model reviewed the code.`, ...extras }
    : { ...base, failed: true, error: `Tier ${extras.tier?.name ?? ""} runs the pattern scanners only, but none could run. Install one (for example foxguard) or choose another tier.`, ...extras };
  const findings = prePass ? leadsToFindings(prePass.leads, deps.now()) : [];
  await writeReport(outcome, findings, { ...emptyStoredReport(startedAt), findings }, "0-scan-prepass", options, deps);
  noteKnown(outcome, findings, deps);
  deps.err(prePass ? `${findings.length} pre-pass finding${findings.length === 1 ? "" : "s"}, not reviewed by a model` : outcome.error!);
  const code = scanExitCode(outcome, findings, options.failOn as typeof SEVERITIES[number] | undefined);
  if (code !== 0) process.exitCode = code;
}

export async function runScan(target: string | undefined, options: ScanOptions, deps: ScanDeps = defaultScanDeps): Promise<void> {
  let resolved: ResolvedTarget | undefined;
  let client: ConsoleClient | undefined;
  let stopConsole: (() => void) | undefined;
  let batched: BatchedSetup | undefined;
  try {
    validate(target, options);
    resolved = await resolveScanTarget(target?.trim() ? target : ".", deps);
    // The operator's tier map decides budget, batches and skill unless a flag was typed, and may skip the scan.
    let tier: ResolvedTier | undefined;
    if (options.coverage === undefined) {
      tier = await pickTier(resolved, target?.trim() ? target : ".", options, deps);
      if (tier) {
        const applied = applyTierSettings(options, tier, explicitFlags(options));
        options = applied.options;
        deps.err(`${tierSentence(tier)}: ${settingsSentence(tier)}`);
        for (const note of applied.notes) deps.err(note);
        if (tier.prepassOnly && options.prepass === "off") throw new UsageError(`tier ${tier.name} runs the pattern scanners only; drop --prepass off.`);
      }
    }
    if (options.plan) { await printPlan(resolved, options, deps, tier); return; }
    if (options.coverage !== undefined) { await printCoverage(resolved, options, deps); return; }
    const known: KnownSet | undefined = options.known?.length ? loadKnown(options.known, resolved.roots) : undefined;
    if (known) deps.err(`known: ${known.items.length} item${known.items.length === 1 ? "" : "s"} from ${known.tools.join(", ") || "the given files"}; the scan is told to look for what they missed`);
    const declaredScope = loadScope(resolved.folder, options, deps.err);
    const extras: Partial<ScanOutcome> = {
      ...(declaredScope ? { scope: declaredScope, ...(options.scopeSarif === "suppress" ? { scopeSarifSuppress: true } : {}) } : {}),
      ...(tier ? { tier: tierInfo(tier), ...(options.failOnSkip ? { failOnSkip: true } : {}) } : {}),
      ...(known ? { known: { items: known.items, tools: known.tools, ...(options.onlyNew ? { onlyNew: true } : {}) } } : {}),
    };
    if (tier?.skipped) {
      // A scan that did not run says so, in every format, and exits 0 unless --fail-on-skip.
      const at = deps.now().toISOString();
      deps.err(`skipped by tier ${tier.name}${tier.reason ? `: ${tier.reason}` : ""}`);
      const outcome: ScanOutcome = { target: resolved.reportTarget, roots: resolved.roots, threadId: "none", startedAt: at, completedAt: at, budgetUsd: Number(options.budget), budgetExhausted: false, failed: false, summary: `skipped by tier ${tier.name}${tier.reason ? `: ${tier.reason}` : ""}`, ...extras };
      await writeReport(outcome, [], emptyStoredReport(at), "0-scan-skipped", options, deps);
      const code = scanExitCode(outcome, [], undefined);
      if (code !== 0) process.exitCode = code;
      return;
    }
    const steering = loadSteering(resolved.folder, options, deps.err);
    if (steering.policies.length && options.skill === "scan") options = { ...options, skill: POLICY_SKILL };
    if (deps.resolveSkill) options = { ...options, skill: deps.resolveSkill(options.skill) };
    const budget = Number(options.budget);
    const total = Number(options.passes);
    const startedAt = deps.now().toISOString();
    const before = await deps.changedFiles(resolved.folder);
    let scope: string[] | undefined;
    if (options.diff) {
      try { scope = await deps.diffFiles(resolved.folder, options.diff); }
      catch { throw new UsageError(`'${options.diff}' is not a git ref in ${resolved.label}, or the folder is not a git work tree.`); }
      if (!scope.length) {
        // Nothing changed: a valid, empty report, so a pipeline that reads the file keeps working.
        deps.err(`no files differ from ${options.diff}; nothing to scan`);
        const empty = { target: "", scanDepth: "default", startedAt, completedAt: startedAt, durationMs: 0, summary: { totalAttacks: 0, totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }, findings: [], warnings: [] } as unknown as ScanReport;
        const outcome: ScanOutcome = { target: resolved.reportTarget, roots: resolved.roots, threadId: "none", startedAt, completedAt: startedAt, budgetUsd: budget, budgetExhausted: false, failed: false, summary: `No files differ from ${options.diff}, so nothing was scanned.` };
        await writeReport(outcome, [], empty, "0-scan-empty", options, deps);
        return;
      }
    }
    if (tier?.prepassOnly) { await runPrePassOnly(resolved, options, deps, scope, extras, startedAt); return; }
    // A folder with more entry points than one thread takes is reviewed in batches, each with a ledger row (docs: Large repositories).
    batched = await planBatchedScan({
      folder: resolved.folder, label: resolved.label, mode: options.batches ?? "auto", batchSize: Number(options.batchSize ?? DEFAULT_BATCH_SIZE), ...(options.resume !== undefined ? { resume: options.resume } : {}),
      ...(options.force ? { force: true } : {}), budgetUsd: budget, passes: total, singleThread: options.skill !== "scan", ...(scope ? { scope } : {}), ...(options.dbPath ? { dbPath: options.dbPath } : {}),
      openLedger: deps.openLedger ?? defaultScanDeps.openLedger!, gitHead: deps.gitHead ?? defaultScanDeps.gitHead!, err: deps.err,
    });
    ({ client, stop: stopConsole } = await connect(options, deps));
    // --budget is the total: each pass gets an equal share, so the cost stays predictable however many passes run.
    let prePass = options.prepass === "off" ? undefined : await runPrePassFor(deps, resolved.folder, options);
    const customLeads = prePass?.leads.filter(lead => lead.ruleSource === "custom");
    if (prePass && scope) {
      const inScope = new Set(scope);
      const leads = prePass.leads.filter(lead => lead.path !== undefined && inScope.has(lead.path));
      prePass = leads.length ? { ...prePass, leads, total: leads.length } : undefined;
    }
    if (prePass) deps.err(`${prePass.tools.join(", ")} pre-pass: ${prePass.total} lead${prePass.total === 1 ? "" : "s"} for the scan to check`);
    const scopeFiles = options.skill === "scan" ? reviewScopeFiles(resolved.folder, scope) : [];
    const ctx: PassContext = { scopeFiles, extras, ...(known ? { known: known.items } : {}), steering, ...(prePass ? { prePass } : {}), ...(scope ? { scope } : {}), client, deps, resolved, options, total, budget: budget / total, deadline: Date.now() + Number(options.timeout) * 1000 };
    if (batched) { await runBatchedScan(ctx, batched, before, startedAt, budget); return; }

    const passErrors: string[] = [];
    const results = (await inPool(total, MAX_PARALLEL_PASSES, async (index): Promise<PassResult | undefined> => {
      // The time limit covers all passes: one that has not started when it runs out is not started.
      if (index > 0 && Date.now() > ctx.deadline) { passErrors.push(`pass ${index + 1} did not start before the time limit`); return undefined; }
      try { return await runPass(ctx, index); }
      catch (error) {
        // One scan has nothing else to fall back on. With several, the others still count.
        if (total === 1) throw error;
        passErrors.push(`pass ${index + 1}: ${error instanceof Error ? error.message : String(error)}`);
        return undefined;
      }
    })).filter((result): result is PassResult => result !== undefined);
    if (!results.length) throw new Error(`No scan pass finished. ${passErrors.join(" ")}`);
    for (const message of passErrors) deps.err(message);

    const failedPasses = total - results.length;
    const merged = mergePasses(results.map(result => result.stored.findings), resolved.roots);
    // The thread has the same tools as any thread, so it could edit the code it reads. Say so if it did.
    const changedError = await unexpectedChanges(deps, resolved.folder, before);
    if (changedError) deps.err(changedError);

    const budgetExhausted = results.some(result => result.budgetExhausted);
    const timedOut = results.some(result => result.timedOut);
    const cost = results.reduce((sum, result) => sum + (result.costUsd ?? 0), 0);
    const costKnown = results.some(result => result.costUsd !== undefined);
    // The summary of the pass that found the most is the best account of what was covered.
    const lead = results.reduce((best, result) => (result.stored.findings.length > best.stored.findings.length ? result : best), results[0]!);
    const failed = results.every(result => (result.done.failed && !result.budgetExhausted && !result.timedOut) || result.done.claimBlocked) || changedError !== undefined;
    const firstError = results.map(result => (!result.budgetExhausted && !result.timedOut ? result.done.error : undefined)).find(Boolean);
    const partialFailure = results.map(result => result.failure).find(Boolean);
    const failure = scanFailure({ failed, changedError, budgetExhausted, timedOut, batchFailures: partialFailure ? [{ batch: 1, cause: partialFailure.cause, message: partialFailure.message }] : [], hardError: firstError });
    // A scan that found nothing and never named most of the source files has not shown the code is clean: say which files it did not open.
    const shallow = merged.length === 0 && !failure && !failed && !budgetExhausted && !timedOut && !results.some(result => result.batchTimedOut) && options.skill === "scan"
      ? shallowReviewWarning(reviewDepth(resolved.folder, results.map(result => result.toolCalls).join("\n"), scope))
      : undefined;
    const fileCoverage = fileCoverageOf(results, coverageRounds(options));
    const outcome: ScanOutcome = {
      target: resolved.reportTarget, roots: resolved.roots, threadId: results[0]!.threadId, startedAt, completedAt: deps.now().toISOString(), budgetUsd: budget,
      ...(costKnown ? { costUsd: cost } : {}), budgetExhausted, ...(timedOut ? { timedOut } : {}), failed, ...(options.allowPartial ? { allowPartial: true } : {}),
      ...(changedError ? { error: changedError } : failed && firstError ? { error: firstError } : {}), ...(failure ? { failure } : {}), ...(lead.done.reply ? { summary: lead.done.reply } : {}),
      ...(customLeads?.length ? { customLeads } : {}),
      ...(shallow ? { shallowReview: shallow } : {}),
      ...(fileCoverage ? { fileCoverage } : {}),
      ...(total > 1 ? { passes: { requested: total, completed: results.length, failed: failedPasses }, threadIds: results.map(result => result.threadId) } : {}),
      ...ctx.extras,
    };

    await writeReport(outcome, merged, { ...results[0]!.stored, findings: merged }, `0-scan-${results[0]!.threadId}`, options, deps);
    noteKnown(outcome, merged, deps);
    const usage = results.length === 1 ? usageLine(results[0]!.done.usage) : `Usage: ${results.length} passes, cost ${costKnown ? `$${cost.toFixed(4)}` : "unknown"}`;
    if (failure && failure.cause !== "budget" && failure.cause !== "timeout") deps.err(`scan ${failed ? "failed" : "stopped early"}: ${failure.message}${merged.length ? `. The ${merged.length} finding${merged.length === 1 ? "" : "s"} recorded so far ${merged.length === 1 ? "is" : "are"} in the report` : ""}`);
    if (fileCoverage) deps.err(`opened ${fileCoverage.opened} of ${fileCoverage.inScope} source files${fileCoverage.rounds.used ? ` after ${fileCoverage.rounds.used} follow-up round${fileCoverage.rounds.used === 1 ? "" : "s"}` : ""}`);
    deps.err(`${merged.length} finding${merged.length === 1 ? "" : "s"}${total > 1 ? ` from ${results.length} of ${total} passes` : ""}${budgetExhausted ? `, stopped at the $${budget} budget (partial)` : timedOut ? `, stopped at the ${options.timeout}s time limit (partial)` : ""}\n${usage}`);
    const code = scanExitCode(outcome, merged, options.failOn as typeof SEVERITIES[number] | undefined);
    if (code !== 0) process.exitCode = code;
  } catch (error) {
    finishWithError(error, deps, false);
  } finally {
    client?.dispose();
    stopConsole?.();
    batched?.ledger.close();
    resolved?.dispose?.();
  }
}

export function registerScanCommand(program: Command, deps: ScanDeps = defaultScanDeps): void {
  consoleTransportOptions(program.command("scan [target]")
    .description("Scan a folder or git repository for security bugs; prints the findings as a report")
    .option("--budget <usd>", "Stop when the estimated spend reaches this many USD; partial findings are kept", String(DEFAULT_BUDGET_USD))
    .option("--format <format>", `Report format: ${FORMATS.join(", ")}`, "md")
    .option("-o, --output <file>", "Write the report to a file instead of stdout")
    .option("--fail-on <severity>", "Exit 1 when a finding is at or above this severity (critical, high, medium, low, info)")
    .option("--passes <n>", `Scan this many times and merge the findings (a scan misses some issues that another run finds); the budget is split between them, up to ${MAX_PASSES}`, "1")
    .option("--diff <ref>", "Review only the files that differ from this git ref (for example origin/main), and what they connect to; an empty diff scans nothing")
    .option("--prepass <mode>", "auto runs the pattern scanners first when they are installed and gives their hits to the scan as leads; off skips them", "auto")
    .option("--scanner <id>", `Scanner for the pre-pass (${SCANNERS.map(scanner => scanner.id).join(", ")}); repeat or separate with commas to use several (default: foxguard). gitleaks, trivy and osv-scanner must be installed; secret values are redacted`, (value: string, previous: string[] = []) => [...previous, value])
    .option("--rules <file-or-folder>", "Semgrep or OpenGrep rules for the pre-pass (a file or a folder); repeat for several. Replaces the default rules and needs --scanner semgrep or opengrep. Rules are never read from the scanned folder unless you name them", (value: string, previous: string[] = []) => [...previous, value])
    .option("--context <file>", "Give the scan this file (a threat model, notes on who may do what) as lower-priority background; repeat for several. It can steer what the scan weighs but cannot change how it works", (value: string, previous: string[] = []) => [...previous, value])
    .option("--policy <file-or-folder>", "Check the code against these Markdown policies (a file or a folder of .md files) and report pass or fail for each; repeat for several. Runs the policy-check skill", (value: string, previous: string[] = []) => [...previous, value])
    .option("--org-policy <folder>", "An organisation's policy folder: evaluated first, and wins when a --policy says otherwise or uses the same id; repeat for several", (value: string, previous: string[] = []) => [...previous, value])
    .option("--scope <file>", "Read the declared scope from the '## Scope' section of this Markdown file (usually SECURITY.md). Findings that match a vector it lists as out of scope are labelled, listed apart and left out of the counts, --fail-on and the exit code; none are removed. In CI pass the base branch's copy")
    .option("--repo-scope", "Read SECURITY.md from the scanned folder as the declared scope. Off by default: a change under review can edit that file; in CI pass the base branch's copy with --scope instead")
    .option("--scope-sarif <mode>", "With --scope: label (default) writes the scope as result properties; suppress also marks out-of-scope results suppressed, which GitHub code scanning then dismisses", "label")
    .option("--repo-context", "Also read .0/threat-model.md from the scanned folder as context. Off by default: a change under review can edit that file; in CI pass the base branch's copy with --context instead")
    .option("--repo-ignores", "Also let the pre-pass scanners read their configuration and ignore files from the scanned folder (.foxguard.yml, .semgrepignore, .gitleaks.toml, .gitleaksignore, .trivyignore, osv-scanner.toml, .checkov.yaml). Off by default: a change under review can use them to hide findings. Inline suppressions such as nosemgrep always apply")
    .option("--skill <id>", "Skill that holds the scan method", "scan")
    .option("--model <model>", `Model for the scan thread (default: ${DEFAULT_SCAN_MODEL})`)
    .option("--batches <mode>", "auto reviews a large folder in batches, one thread per group of entry points, and records what each batch covered; on always does; off keeps one thread", "auto")
    .option("--batch-size <n>", `Entry points one batch reviews (1 to ${MAX_BATCH_SIZE}); a folder with more than this many is split under --batches auto`, String(DEFAULT_BATCH_SIZE))
    .option("--retries <n>", `Run a batch again when it fails for a reason that may pass: a dropped connection, a provider timeout, rate limit or server error (0 to ${MAX_RETRIES}; 0 turns it off). A thread that is not a batch is asked once to continue. The cost of every attempt counts against --budget`, String(DEFAULT_RETRIES))
    .option("--coverage-rounds <n>", `After a thread ends, send it a follow-up that names the source files it never opened, up to this many times (0 to ${MAX_COVERAGE_ROUNDS}; 0 turns it off). Each round counts against --budget`, String(DEFAULT_COVERAGE_ROUNDS))
    .option("--batch-timeout <seconds>", `Longest one batch may run before it is cancelled and left pending (the scan goes on with the next batch); --timeout still limits the whole scan`, String(DEFAULT_BATCH_TIMEOUT_SECONDS))
    .option("--concurrency <n>", `Batches that run at the same time (1 to ${MAX_PARALLEL_PASSES})`, "1")
    .option("--resume <scan>", "Continue the units an earlier batched scan of this folder did not reach (a scan id from its report, or latest); refuses when the git HEAD changed unless --force")
    .option("--force", "With --resume: continue even though the folder's git HEAD changed")
    .option("--coverage [scan]", "Print the coverage ledger of a batched scan of this folder (the latest, or the id given) and exit; --format json for JSON")
    .option("--allow-partial", "Exit by the findings alone (0, or 1 with --fail-on) when the scan stops before it reviews everything; the report still says it is partial")
    .option("--plan", "List the entry points, the batches and a rough cost range for the folder, then exit; calls no model and writes nothing")
    .option("--tiers <file>", "An operator's tier map (YAML or JSON) that sets the budget, batches and skill for this repository, or skips it. Default: scan-tiers.yaml|yml|json in the 0 state folder. Never read from the scanned folder on its own; in CI read it from the base branch")
    .option("--fail-on-skip", "Exit 1 when the tier map skips this scan (default: exit 0, with the skip stated in the report)")
    .option("--known <sarif>", "SARIF from other tools: the scan is told what is already known and looks for what they missed; findings are labelled new or already-known (confirmedIndependently when the scan analysed it itself). Repeat for several", (value: string, previous: string[] = []) => [...previous, value])
    .option("--only-new", "With --known: leave findings that match a known item out of the report")
    .option("--timeout <seconds>", "Maximum seconds for the whole scan; what it reviewed so far is reported as partial", String(DEFAULT_TIMEOUT_SECONDS)))
    .addHelpText("after", "\nExit codes: 0 done, 1 findings at or above --fail-on or the scan failed, 2 usage error, 3 stopped before it reviewed everything (budget, time limit, or entry points not reached): not finished, not failed; --allow-partial exits 0 or 1 instead.\nThe scan is a thread: follow it with `0security threads list`.")
    .action(async (target: string, options: ScanOptions, command: Command) => {
      // Precedence: a flag you typed (or set in the environment) > the tier map > the operator's workflow defaults > the built-in default.
      // Workflow defaults fill budget and model here; runScan lets a tier replace them unless the flag was typed.
      const typed = ["budget", "batches", "skill"].filter(name => ["cli", "env"].includes(String(command.getOptionValueSource(name))));
      await runScan(target, { ...applyWorkflowDefaults("scan", options, command), explicit: typed }, deps);
    });
}
