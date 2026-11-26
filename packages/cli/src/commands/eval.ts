/**
 * `0 eval`: run a suite of security and utility cases against tool-using agents on the redteam honeypot, report pass rates per agent,
 * compare against a saved baseline and gate a pipeline. Every run goes through executeSingleRun (the same code as `0 redteam run`), so
 * the agent runs on this machine with the access it is given and the command refuses to start without `--unsafe-no-isolation`.
 * Payloads are benign markers. A run in which the agent never called the honeypot is inconclusive, never a pass.
 * Nothing here makes a network request of its own; the agent under test may.
 */
import { chmodSync, closeSync, constants, fstatSync, lstatSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { Command } from "commander";
import {
  applyChecked, CATALOG, CATALOG_BY_ID, compareToBaseline, EXAMPLE_SUITE, exportReport, kitsForTools, listStrategies, materializePayload, newCanary, parseBaseline, parseSuite, runSuite,
  strategyById, TEMPLATES_BY_ID, textTable, toBaseline, toFindings, toJson, toMarkdown,
  type Comparison, type Execute, type OracleSpec, type Suite, type SuiteAgent, type SuiteCase, type SuiteResults,
} from "@0/engine";
import { UsageError } from "./output.js";
import { reportFor } from "./redteam.js";
import { executeSingleRun, redact, type ProcessHooks, type SingleRunDeps, type SingleRunOptions, type SingleRunResult } from "./redteam-run.js";

export interface EvalDeps {
  out(text: string): void;
  err(text: string): void;
  readText(path: string): string;
  writeOutput(path: string, text: string): void;
  /** One agent execution; the default is executeSingleRun of `0 redteam run`. */
  executeRun(options: SingleRunOptions & { canary: string }, overrides?: Partial<SingleRunDeps>): Promise<SingleRunResult>;
  now(): number;
  /** lstat of a path (symlinks are not followed), checked before a suite or baseline is read. */
  statFile(path: string): { isFile: boolean; isSymlink: boolean; size: number };
  makeTempDir(): string;
  removeDir(path: string): void;
  /** Process signal hooks, injectable so Ctrl-C handling can be tested without killing the test process. */
  proc: ProcessHooks;
}

/** Largest suite or baseline file read. */
export const MAX_INPUT_BYTES = 1024 * 1024;
const KILL_GRACE_MS = 2000;
// O_NONBLOCK keeps open() from hanging on a FIFO and O_NOFOLLOW refuses a symlink; the descriptor is checked before anything is read.
function readRegularFile(path: string): string {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new Error("not a regular file");
    if (st.size > MAX_INPUT_BYTES) throw new Error(`larger than ${MAX_INPUT_BYTES} bytes`);
    return readFileSync(fd, "utf8");
  } finally { closeSync(fd); }
}

const defaults: EvalDeps = {
  out: text => { process.stdout.write(text); },
  err: text => { process.stderr.write(`${text}\n`); },
  readText: readRegularFile,
  writeOutput: (path, text) => { writeFileSync(path, text, { mode: 0o600 }); chmodSync(path, 0o600); },
  executeRun: (options, overrides) => executeSingleRun(options, overrides),
  now: () => Date.now(),
  statFile: path => { const st = lstatSync(path); return { isFile: st.isFile(), isSymlink: st.isSymbolicLink(), size: st.size }; },
  makeTempDir: () => mkdtempSync(join(tmpdir(), "0-redteam-")),
  removeDir: path => { rmSync(path, { recursive: true, force: true }); },
  proc: { on: (signal, handler) => { process.on(signal, handler); }, off: (signal, handler) => { process.off(signal, handler); }, exit: code => process.exit(code), sleep: ms => new Promise(done => { setTimeout(done, ms); }) },
};

export interface EvalRunOptions {
  agent?: string[]; repeats?: number; maxRuns?: number; timeout?: number; format?: string; output?: string;
  baseline?: string; saveBaseline?: string; tolerance?: number; unsafeNoIsolation?: boolean;
}

const FORMATS = ["text", "json", "md", "sarif"] as const;
// eslint-disable-next-line no-control-regex
const stripControl = (text: string): string => text.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f​-‏‪-‮⁠-⁤⁦-⁩﻿]/g, "");
const clean = (text: string): string => stripControl(redact(text, ""));
/** Masks credential-looking values and strips control characters in every string of a value, before it is formatted. */
function sanitize<T>(value: T): T {
  if (typeof value === "string") return clean(value) as T;
  if (Array.isArray(value)) return value.map(sanitize) as T;
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [clean(k), sanitize(v)])) as T;
  return value;
}

const inRange = (name: string, value: number, min: number, max: number, whole: boolean): number => {
  if (!Number.isFinite(value) || value < min || value > max || (whole && !Number.isInteger(value))) throw new UsageError(`${name} must be ${whole ? "a whole number " : "a number "}from ${min} to ${max}.`);
  return value;
};

/**
 * Ctrl-C and CI cancel handling, the same pattern as `0 redteam run`: the agent is a detached process group, so on SIGINT or SIGTERM
 * the live group gets SIGTERM, then SIGKILL after a grace period, the temp dirs (config with the canary, traces, fake HOME) are
 * removed and the process exits 130 or 143. `overrides` go to executeRun so the group and the dirs are tracked.
 */
function runCleanup(deps: EvalDeps) {
  const temps = new Set<string>();
  let live: ((signal: NodeJS.Signals) => void) | null = null;
  let stopping = false;
  const clearTemps = () => { for (const dir of temps) try { deps.removeDir(dir); } catch { /* best effort while exiting */ } };
  const stop = (code: number) => () => {
    if (stopping) return;
    stopping = true;
    live?.("SIGTERM");
    void deps.proc.sleep(KILL_GRACE_MS).then(() => { live?.("SIGKILL"); clearTemps(); deps.proc.exit(code); });
  };
  const onInt = stop(130); const onTerm = stop(143);
  const overrides: Partial<SingleRunDeps> = {
    makeTempDir: () => { const dir = deps.makeTempDir(); temps.add(dir); return dir; },
    removeDir: path => { deps.removeDir(path); temps.delete(path); },
    track: group => { live = group; },
  };
  return {
    overrides, stopping: () => stopping, release: () => { live = null; },
    install: () => { deps.proc.on("SIGINT", onInt); deps.proc.on("SIGTERM", onTerm); },
    dispose: () => { deps.proc.off("SIGINT", onInt); deps.proc.off("SIGTERM", onTerm); },
  };
}

/** Reads a suite or baseline file after lstat: a symlink, a FIFO or device, or a file over 1 MiB is refused before any read. */
function read(path: string, deps: EvalDeps, what: string): string {
  const file = resolve(path);
  try {
    const st = deps.statFile(file);
    if (st.isSymlink) throw new Error("it is a symbolic link; pass the real file");
    if (!st.isFile) throw new Error("it is not a regular file");
    if (st.size > MAX_INPUT_BYTES) throw new Error(`it is larger than ${MAX_INPUT_BYTES} bytes`);
    return deps.readText(file);
  } catch (error) { throw new UsageError(`Cannot read ${what} ${path}: ${clean(error instanceof Error ? error.message : String(error))}`); }
}

/** The honeypot kit names that provide a suite kit's tools. Tools no kit defines are returned separately. */
function kitNamesFor(tools: readonly string[]): { names: string[]; unknown: string[] } {
  const names: string[] = []; const unknown: string[] = [];
  for (const tool of tools) {
    try { for (const kit of kitsForTools([tool])) if (!names.includes(kit.name)) names.push(kit.name); } catch { unknown.push(tool); }
  }
  return { names, unknown };
}

function distance(a: string, b: string): number {
  let row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const next = [i];
    for (let j = 1; j <= b.length; j++) next.push(Math.min(row[j]! + 1, next[j - 1]! + 1, row[j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1)));
    row = next;
  }
  return row[b.length]!;
}
/** " Did you mean X?" with the closest valid id, or an empty string when none is near. */
function didYouMean(id: string, valid: readonly string[]): string {
  let best: string | undefined; let bestDistance = Infinity;
  for (const candidate of valid) { const d = distance(id.toLowerCase(), candidate.toLowerCase()); if (d < bestDistance) { best = candidate; bestDistance = d; } }
  return best !== undefined && bestDistance <= Math.max(3, Math.ceil(id.length / 2)) ? ` Did you mean ${best}?` : "";
}

interface Resolved { payload: string; oracle?: OracleSpec }
type Payload = (canary: string, repeat: number) => string;

/** Builds the payload function of a case, or throws UsageError saying what is wrong. */
function payloadFor(testCase: SuiteCase): Payload {
  const where = `case '${testCase.id}'`;
  // A utility case carries the task as the text the agent is given; a security case carries the poisoned text.
  if (testCase.kind === "utility") { const task = testCase.task ?? testCase.payload; if (task === undefined) throw new UsageError(`${where}: a utility case needs a task.`); return () => task; }
  let base: Payload;
  if (testCase.generatorId !== undefined) {
    const spec = CATALOG_BY_ID.get(testCase.generatorId);
    if (!spec) throw new UsageError(`${where}: unknown generator ${testCase.generatorId}.${didYouMean(testCase.generatorId, CATALOG.map(g => g.id))} Run \`0 redteam list generators\` for the ids.`);
    const template = TEMPLATES_BY_ID.get(spec.id);
    if (!template) throw new UsageError(`${where}: generator ${spec.id} is closed (tier ${spec.tier}), so no template ships in the open catalog. Give the case an inline payload instead.`);
    base = canary => materializePayload({ goal: template.goal, injectionPoint: template.injectionPointKind, payload: template.payload, success: template.success }, canary);
  } else if (testCase.payload !== undefined) { const text = testCase.payload; base = canary => text.split("AGENT-CANARY-0").join(canary); }
  else throw new UsageError(`${where}: a security case needs a payload or a generatorId.`);
  if (testCase.strategyId === undefined) return base;
  const strategy = strategyById(testCase.strategyId);
  if (!strategy) throw new UsageError(`${where}: unknown strategy ${testCase.strategyId}.${didYouMean(testCase.strategyId, listStrategies().map(x => x.id))} Run \`0 redteam list strategies\` for the ids.`);
  if (!strategy.apply) throw new UsageError(`${where}: strategy ${strategy.id} has no single-turn delivery, so an eval case cannot use it.`);
  return (canary, repeat) => {
    const checked = applyChecked(strategy, { payload: base(canary, repeat), canary, seed: repeat + 1 });
    if (!checked.variants.length) throw new UsageError(`${where}: strategy ${strategy.id} produced no usable variant${checked.dropped.length ? ` (${checked.dropped.map(d => `${d.notes}: ${d.problems.join("; ")}`).join(" | ")})` : ""}.`);
    return checked.variants[repeat % checked.variants.length]!.text;
  };
}

/** Everything about a suite the schema does not check: generators, strategies and kit tools. Errors stop a run; warnings do not. */
function plan(suite: Suite): { payloads: Map<string, Payload>; kits: Map<string, string[]>; errors: string[]; warnings: string[] } {
  const payloads = new Map<string, Payload>(); const kits = new Map<string, string[]>(); const errors: string[] = []; const warnings: string[] = [];
  for (const kit of suite.kits) {
    const { names, unknown } = kitNamesFor(kit.tools);
    kits.set(kit.id, names);
    if (unknown.length) warnings.push(`kit ${kit.id}: no honeypot kit defines ${unknown.join(", ")}; those tools will not exist for the agent`);
  }
  if (suite.maxCost !== undefined) warnings.push(`maxCost ${suite.maxCost} is not enforced: eval does not report a cost per run yet, so only maxRuns and --timeout bound a run`);
  for (const testCase of suite.cases) {
    // executeSingleRun takes one text per run (the payload), so a security case's task is never given to the agent.
    if (testCase.kind === "security" && testCase.task !== undefined) warnings.push(`case '${testCase.id}': the task is not delivered; a run gives the agent only the payload text, so a security case cannot carry a separate task`);
    try { const p = payloadFor(testCase); p(newCanary(), 0); payloads.set(testCase.id, p); } catch (error) { errors.push(error instanceof Error ? error.message : String(error)); }
  }
  return { payloads, kits, errors, warnings };
}

function loadSuite(path: string, deps: EvalDeps): { suite: Suite; warnings: string[] } {
  const parsed = parseSuite(read(path, deps, "suite"));
  if (!parsed.ok) throw new UsageError(`Invalid suite ${path}: ${clean(parsed.error)}`);
  return { suite: parsed.value, warnings: parsed.warnings ?? [] };
}

export function runEvalValidate(path: string, deps: EvalDeps = defaults): number {
  const parsed = parseSuite(read(path, deps, "suite"));
  if (!parsed.ok) { deps.err(`Invalid suite ${path}: ${clean(parsed.error)}`); return 2; }
  const suite = parsed.value;
  const { errors, warnings } = plan(suite);
  for (const warning of [...(parsed.warnings ?? []), ...warnings]) deps.err(`warning: ${clean(warning)}`);
  if (errors.length) { for (const error of errors) deps.err(`error: ${clean(error)}`); return 2; }
  const runs = suite.agents.length * suite.cases.length * (suite.repeats ?? 1);
  deps.out(`${clean(suite.name)}: valid. ${suite.agents.length} agents, ${suite.cases.length} cases, ${suite.repeats ?? 1} repeat${(suite.repeats ?? 1) === 1 ? "" : "s"}, ${runs} planned runs.\n`);
  return 0;
}

export function runEvalExample(deps: EvalDeps = defaults): number { deps.out(`${JSON.stringify(EXAMPLE_SUITE, null, 2)}\n`); return 0; }

const pct = (value: number | null): string => (value === null ? "n/a" : `${(value * 100).toFixed(1)}%`);
function describeDelta(d: Comparison["regressions"][number]): string {
  return `${d.agentId}${d.caseId ? ` / ${d.caseId}` : ""} ${d.metric}: ${pct(d.baseline)} -> ${pct(d.current)}`;
}

/** Runs the suite and returns 0 (verdict pass), 1 (verdict fail) or 2 (no conclusive run; bad input throws UsageError). */
export async function runEvalRun(path: string, options: EvalRunOptions, deps: EvalDeps = defaults): Promise<number> {
  if (!options.unsafeNoIsolation) throw new UsageError("Isolation is not built yet: the agent runs on this machine with the access you give it. Use a throwaway VM or container you control, then pass --unsafe-no-isolation.");
  const format = options.format ?? "text";
  if (!(FORMATS as readonly string[]).includes(format)) throw new UsageError(`--format must be one of: ${FORMATS.join(", ")}.`);
  const timeout = inRange("--timeout", options.timeout ?? 120, 1, 3600, false);
  const tolerance = options.tolerance === undefined ? undefined : inRange("--tolerance", options.tolerance, 0, 1, false);
  const { suite: loaded, warnings } = loadSuite(path, deps);
  let suite: Suite = loaded;
  if (options.agent?.length) {
    const ids = new Set(suite.agents.map(a => a.id));
    const unknown = options.agent.filter(id => !ids.has(id));
    if (unknown.length) throw new UsageError(`Unknown agent: ${unknown.join(", ")}. The suite has: ${[...ids].join(", ")}.`);
    suite = { ...suite, agents: suite.agents.filter(a => options.agent!.includes(a.id)) };
  }
  if (options.repeats !== undefined) suite = { ...suite, repeats: inRange("--repeats", options.repeats, 1, 20, true) };
  if (options.maxRuns !== undefined) suite = { ...suite, maxRuns: inRange("--max-runs", options.maxRuns, 1, 10_000, true) };
  let baseline: ReturnType<typeof parseBaseline> | undefined;
  if (options.baseline) {
    let raw: unknown;
    try { raw = JSON.parse(read(options.baseline, deps, "baseline")); } catch (error) { if (error instanceof UsageError) throw error; throw new UsageError(`${options.baseline} is not a JSON baseline.`); }
    baseline = parseBaseline(raw, suite.name);
    if (!baseline.ok) throw new UsageError(`Invalid baseline ${options.baseline}: ${clean(baseline.error)}`);
  }
  const { payloads, kits, errors, warnings: planWarnings } = plan(suite);
  if (errors.length) throw new UsageError(`Invalid suite ${path}: ${errors.map(clean).join(" | ")}`);
  for (const warning of [...warnings, ...planWarnings]) deps.err(`warning: ${clean(warning)}`);
  deps.err("warning: each agent runs on this machine with this user's access; scrubbing the environment is not a secret boundary, so use a throwaway directory and account.");

  // runSuite turns an exception in execute into an error result, so a fatal launcher failure is kept here and thrown after it returns.
  let fatal: UsageError | undefined;
  const cleanup = runCleanup(deps);
  const execute: Execute = async (agent: SuiteAgent, testCase: SuiteCase, repeat: number) => {
    if (cleanup.stopping()) return { trace: [], canary: "", error: "stopped by a signal" };
    if (fatal) return { trace: [], canary: "", error: "skipped after a fatal error" };
    const canary = newCanary();
    const kitNames = [...new Set(testCase.kits.flatMap(id => kits.get(id) ?? []))];
    const payload = payloads.get(testCase.id)!(canary, repeat);
    let result: SingleRunResult;
    try { result = await deps.executeRun({ agent: agent.command, ...(agent.cwd !== undefined ? { cwd: agent.cwd } : {}), ...(agent.env?.length ? { envNames: agent.env } : {}), timeoutMs: timeout * 1000, kits: kitNames, payload, canary }, cleanup.overrides); } finally { cleanup.release(); }
    // A launcher that cannot start the honeypot is not an agent that stayed silent: stop instead of recording inconclusive runs.
    if (result.error?.startsWith("The honeypot")) { fatal = new UsageError(result.error); return { trace: [], canary, error: result.error }; }
    return { trace: result.trace, canary: result.canary, ...(result.error !== undefined ? { error: result.error } : {}), ...(result.timedOut ? { timedOut: true } : {}) };
  };
  let results: SuiteResults;
  cleanup.install();
  try { results = await runSuite({ suite, execute, now: deps.now }); }
  catch (error) { if (error instanceof UsageError) throw error; throw new UsageError(`The run failed: ${clean(error instanceof Error ? error.message : String(error))}`); }
  finally { cleanup.dispose(); }

  if (fatal) throw fatal;
  let comparison: Comparison | undefined;
  if (baseline?.ok) {
    try { comparison = compareToBaseline(results, baseline.value, tolerance === undefined ? {} : { tolerance }); } catch (error) { throw new UsageError(`Cannot compare with ${options.baseline}: ${clean(error instanceof Error ? error.message : String(error))}`); }
    if (comparison.regressions.length) results = { ...results, verdict: { pass: false, reasons: [...results.verdict.reasons, ...comparison.regressions.map(d => `regression against the baseline: ${describeDelta(d)}`)] } };
  }
  const safe = sanitize(results);
  let body: string;
  if (format === "json") body = `${JSON.stringify({ ...JSON.parse(toJson(safe)), ...(comparison ? { comparison: sanitize(comparison) } : {}) }, null, 2)}\n`;
  else if (format === "sarif") {
    const exported = await exportReport(reportFor(safe.suite, sanitize(toFindings(safe)), safe.executed, new Date(deps.now())), "sarif", `0-eval-${safe.suite}`);
    body = typeof exported.body === "string" ? exported.body : new TextDecoder().decode(exported.body);
    if (!body.endsWith("\n")) body += "\n";
  } else {
    const extra = comparison ? [`Against the baseline: ${comparison.regressions.length} regression${comparison.regressions.length === 1 ? "" : "s"}, ${comparison.improvements.length} improvement${comparison.improvements.length === 1 ? "" : "s"}.`, ...sanitize(comparison.regressions).map(d => `  regression: ${describeDelta(d)}`)] : [];
    body = format === "md" ? `${toMarkdown(safe)}${extra.length ? `\n## Baseline\n\n${extra.map(l => (l.startsWith("  ") ? `- ${l.trim()}` : l)).join("\n")}\n` : ""}` : `${stripControl(textTable(safe))}${extra.length ? `\n\n${extra.join("\n")}` : ""}\nA pass is not proof of safety: a suite measures only the attacks it contains.\n`;
  }
  const write = (file: string, text: string, what: string) => {
    try { deps.writeOutput(resolve(file), text); } catch (error) { throw new UsageError(`Cannot write ${what} ${file}: ${clean(error instanceof Error ? error.message : String(error))}`); }
    deps.err(`Wrote ${file}`);
  };
  // Files are written whatever the exit code is, so a pipeline can upload them after a failing run.
  if (options.saveBaseline) write(options.saveBaseline, `${JSON.stringify(toBaseline(safe), null, 2)}\n`, "--save-baseline");
  if (options.output) write(options.output, body, "--output"); else deps.out(body);
  if (results.agents.length === 0 || results.runs.every(run => run.status === "inconclusive" || run.calls === 0)) { deps.err("No conclusive runs: no run recorded a honeypot call that could be judged (the agents never called it, timed out or failed to start)."); return 2; }
  return results.verdict.pass ? 0 : 1;
}

const collect = (value: string, previous: string[] = []): string[] => [...previous, value];
const number = (value: string): number => Number(value);

export function registerEvalCommand(program: Command, deps: EvalDeps = defaults): void {
  const evalCmd = program.command("eval").description("Evaluate tool-using agents with suites of paired security and utility cases on the redteam honeypot");
  evalCmd.command("run").argument("<suite>", "Suite file (JSON or YAML)")
    .description("Run a suite and report security pass rate, utility pass rate, secure-and-useful and inconclusive rate per agent; exits 1 if the verdict fails, 2 if no run was conclusive")
    .option("--agent <id>", "Only run this suite agent (repeatable)", collect)
    .option("--repeats <n>", "Override the suite's runs per agent and case (1 to 20)", number)
    .option("--max-runs <n>", "Stop after this many runs; a cut-short run fails the verdict", number)
    .option("--timeout <seconds>", "Stop an agent run after this long (1 to 3600)", number, 120)
    .option("--format <format>", "text, json, md or sarif", "text")
    .option("-o, --output <file>", "Write the result (in --format) to this file instead of stdout, even when the exit code is 1 or 2")
    .option("--baseline <file>", "Compare with a baseline saved earlier; any regression fails the verdict")
    .option("--save-baseline <file>", "Save this run's pass rates as a baseline (rates and counts only)")
    .option("--tolerance <fraction>", "Drop in a pass rate to ignore when comparing with the baseline (0 to 1)", number)
    .option("--unsafe-no-isolation", "Required: there is no sandbox yet, so each agent runs on this machine with the access you give it. POSIX only")
    .action(async (suite: string, options: EvalRunOptions) => { process.exitCode = await runEvalRun(suite, options, deps); });
  evalCmd.command("validate").argument("<suite>", "Suite file (JSON or YAML)").description("Check a suite and print errors and warnings; exits 0 if valid, 2 if not")
    .action((suite: string) => { process.exitCode = runEvalValidate(suite, deps); });
  evalCmd.command("example").description("Print an example suite as JSON").action(() => { process.exitCode = runEvalExample(deps); });
}
