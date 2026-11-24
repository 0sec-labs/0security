/**
 * `0 threat-model [folder]`: a thread that follows the `threat-model` skill and writes `.0/threat-model.md`.
 *
 * With `--pr` the thread works in a separate git work tree on the branch `0/threat-model`, and the file goes up as a
 * pull request people review and merge. Nothing is pushed to the base branch and nothing is merged. Later scans read
 * the merged file with `--context` (or `--repo-context`; see the scan command for why that is opt-in).
 *
 * With `--interview` the command also asks the person a few specific questions (threat-interview.ts) and writes the answers
 * into the `## Scope` section of SECURITY.md and into a human block of the threat-model file. Only this command writes them.
 *
 * The git and gh steps below follow `0 fix` (fix.ts). They are written out here on purpose, because gh access is
 * being moved behind a Host port in fix.ts, burndown.ts and the findings commands; when that lands, `git` and `gh`
 * in ThreatModelDeps should become calls on the port.
 */
import { execFile } from "node:child_process";
import { createInterface } from "node:readline";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { promisify } from "node:util";
import { Command } from "commander";
import { buildInventory } from "@0/engine";
import { parseScope, THREAT_MODEL_PATH, threatModelPrompt } from "@0/engine/shared";
import { consoleTransportOptions, type ConsoleClient, type ConsoleTransportOptions } from "../console-client.js";
import { connect, DEFAULT_SCAN_MODEL, defaultScanDeps, registerScanCommand, waitForThread, type ScanDeps } from "./scan.js";
import { planScan } from "../scan-plan.js";
import { DEFAULT_BATCH_SIZE } from "../scan-batched.js";
import { findingsFromReport, latestScanFindings, loadReportFile, MAX_SCAN_AGE_DAYS, type ScanSnapshot } from "../threat-interview-findings.js";
import { finishWithError, UsageError } from "./output.js";
import { asJson, finishedThread, usageLine } from "./thread-output.js";
import { ensureScopeLink, runInterview, scopeLinkFor, upsertScopeDecisions, type InterviewIO, type InterviewModel, type InterviewResult } from "../threat-interview.js";

const exec = promisify(execFile);
const DEFAULT_BUDGET_USD = 3;
const DEFAULT_TIMEOUT_SECONDS = 1800;
/** What the two interview threads (questions, wording) may spend together. */
export const DEFAULT_INTERVIEW_BUDGET_USD = 0.5;
/** What the scan that `--scan` runs first may spend. */
export const DEFAULT_SCAN_BUDGET_USD = 3;
export const SECURITY_FILE = "SECURITY.md";
export const THREAT_MODEL_BRANCH = "0/threat-model";
export const REQUIRED_HEADINGS = ["Summary", "What matters most", "Assets", "Actors", "Trust boundaries", "Entry points", "Authorization and business rules", "Data flows", "Open questions"];

export interface ThreatModelDeps extends Pick<ScanDeps, "open" | "err" | "sleep" | "startConsole"> {
  out(text: string): void;
  git(cwd: string, args: string[]): Promise<string>;
  gh(cwd: string, args: string[]): Promise<string>;
  makeTemp(): string;
  removeTemp(path: string): void;
  writeFile(path: string, text: string): void;
  readFile(path: string): string | undefined;
  /** A file the team shares (SECURITY.md): written with the default permissions, unlike the 0600 files above. */
  writePublic?(path: string, text: string): void;
  /** `--interview` needs a person at a terminal. */
  isTTY?(): boolean;
  /** The terminal the interview reads and writes. Tests give scripted answers. */
  openTerminal?(): InterviewIO & { close(): void };
  now?(): Date;
  /** The latest scan of the folder in the findings database, newer than 30 days. Tests give their own. */
  latestScan?(folder: string, now: Date): ScanSnapshot | undefined;
  /** A rough cost range for a scan of the folder, from its files alone. Calls no model. */
  estimateScan?(folder: string, budgetUsd: number): { lowUsd: number; highUsd: number };
  /** Run a scan of the folder as `0 scan --format json` and return its report text. */
  runScan?(folder: string, options: { budget: number; model?: string; timeout: string; client?: ConsoleClient }): Promise<{ text?: string; costUsd?: number; note?: string }>;
}

/** Lines typed at the terminal, one per question. Prompts and notes go to standard error so standard output stays for the result. */
export function openStdioTerminal(): InterviewIO & { close(): void } {
  const rl = createInterface({ input: process.stdin, terminal: false });
  const queue: string[] = [];
  const waiting: Array<(line: string | undefined) => void> = [];
  let closed = false;
  rl.on("line", line => { const next = waiting.shift(); if (next) next(line); else queue.push(line); });
  rl.on("close", () => { closed = true; for (const next of waiting.splice(0)) next(undefined); });
  return {
    say: text => { process.stderr.write(`${text}\n`); },
    ask: question => { process.stderr.write(question); return queue.length ? Promise.resolve(queue.shift()) : closed ? Promise.resolve(undefined) : new Promise(resolve => waiting.push(resolve)); },
    close: () => rl.close(),
  };
}

export const defaultThreatModelDeps: ThreatModelDeps = {
  open: defaultScanDeps.open, err: defaultScanDeps.err, sleep: defaultScanDeps.sleep, startConsole: defaultScanDeps.startConsole,
  out: text => process.stdout.write(`${text}\n`),
  async git(cwd, args) { return (await exec("git", ["-C", cwd, ...args], { maxBuffer: 32 * 1024 * 1024 })).stdout; },
  async gh(cwd, args) { return (await exec("gh", args, { cwd, maxBuffer: 32 * 1024 * 1024 })).stdout; },
  makeTemp: () => mkdtempSync(join(tmpdir(), "0-threat-model-")),
  removeTemp: path => rmSync(path, { recursive: true, force: true }),
  writeFile: (path, text) => writeFileSync(path, text, { mode: 0o600 }),
  readFile: path => { try { return readFileSync(path, "utf8"); } catch { return undefined; } },
  writePublic: (path, text) => writeFileSync(path, text),
  isTTY: () => Boolean(process.stdin.isTTY && process.stderr.isTTY),
  openTerminal: openStdioTerminal,
  now: () => new Date(),
  latestScan: (folder, now) => latestScanFindings(folder, { now }),
  estimateScan: (folder, budgetUsd) => {
    const { estimate } = planScan(buildInventory(folder), { folder, batchSize: DEFAULT_BATCH_SIZE, batchesMode: "auto", budgetUsd });
    return { lowUsd: estimate.lowUsd, highUsd: estimate.highUsd };
  },
  async runScan(folder, options) {
    const dir = mkdtempSync(join(tmpdir(), "0-interview-scan-"));
    const out = join(dir, "report.json");
    const exitBefore = process.exitCode;
    try {
      const program = new Command().exitOverride();
      // The scan runs on the console this command already connected to; stopping a console of its own would leave a stale registration behind.
      const shared = options.client;
      const scanClient: ConsoleClient | undefined = shared && { request: (method, path, body) => shared.request(method, path, body), dispose: () => {} };
      registerScanCommand(program, { ...defaultScanDeps, scopeHint: () => undefined, ...(scanClient ? { open: async () => scanClient } : {}) });
      await program.parseAsync(["scan", folder, "--budget", String(options.budget), "--format", "json", "--output", out, "--timeout", options.timeout, ...(options.model ? ["--model", options.model] : [])], { from: "user" });
      const failed = process.exitCode === 2 || process.exitCode === 1 && !existsSync(out);
      if (!existsSync(out)) return { note: failed ? "the scan failed before it wrote a report" : "the scan wrote no report" };
      const text = readFileSync(out, "utf8");
      let costUsd: number | undefined;
      try { const cost = (JSON.parse(text) as { costUsd?: unknown }).costUsd; if (typeof cost === "number") costUsd = cost; } catch { /* no cost */ }
      return { text, ...(costUsd !== undefined ? { costUsd } : {}) };
    } catch (error) {
      return { note: `the scan failed: ${error instanceof Error ? error.message.split("\n")[0]!.slice(0, 200) : "unknown error"}` };
    } finally {
      // The scan reports its own exit code (findings, partial); this command's exit code is about the threat model.
      process.exitCode = exitBefore;
      rmSync(dir, { recursive: true, force: true });
    }
  },
};

export interface ThreatModelOptions extends ConsoleTransportOptions {
  base?: string; budget: string; model?: string; timeout: string; pr?: boolean; format?: string; interview?: boolean; interviewBudget?: string; output?: string; scan?: boolean; fromScan?: string; scanBudget?: string;
}

export interface ThreatModelOutcome {
  file: string; written: boolean; changed: boolean; problems: string[]; humanSectionsKept?: boolean;
  interview?: { mode: string; fallbackReason?: string; asked: number; answered: number; entries: number; wroteSecurity: boolean; securityFile?: string; scan?: { source: string; findings: number; questions: number } };
  notices?: string[];
  branch?: string; pullRequest?: { url: string; created: boolean }; threadId?: string; costUsd?: number; budgetExhausted?: boolean; timedOut?: boolean; summary?: string;
}

/** What is wrong with a threat-model file the thread wrote, in words a person can act on. Empty when it is fine. */
export function checkThreatModel(text: string | undefined): string[] {
  if (text === undefined) return [`${THREAT_MODEL_PATH} was not written.`];
  const problems: string[] = [];
  const front = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (!front) problems.push("it has no front matter");
  else for (const key of ["generated", "commit"]) if (!new RegExp(`^${key}:\\s*\\S`, "m").test(front[1]!)) problems.push(`the front matter has no ${key}`);
  const missing = REQUIRED_HEADINGS.filter(heading => !new RegExp(`^##\\s+${heading.replace(/ /g, "\\s+")}\\s*$`, "mi").test(text));
  if (missing.length) problems.push(`missing sections: ${missing.join(", ")}`);
  return problems;
}

/** The human-marked blocks of a file: the lines after each `<!-- human -->` marker, up to the next heading or end marker. */
export function humanBlocks(text: string): string[] {
  const blocks: string[] = [];
  let current: string[] | undefined;
  for (const line of text.split("\n")) {
    if (/<!--\s*human\s*-->/.test(line)) { if (current) blocks.push(current.join("\n").trim()); current = []; continue; }
    if (current && (/<!--\s*\/human\s*-->/.test(line) || /^#{1,6}\s/.test(line))) { blocks.push(current.join("\n").trim()); current = undefined; continue; }
    current?.push(line);
  }
  if (current) blocks.push(current.join("\n").trim());
  return blocks.filter(Boolean);
}

/** Text from a model goes into a pull request body: stop it from notifying people or referencing other issues. */
const inert = (text: string): string => text.replace(/@/g, "@​").replace(/(^|\s)#(\d)/g, "$1#​$2");

/**
 * The path of the threat-model file as `--output` names it: relative, inside the folder, a Markdown file, with forward
 * slashes. Throws a UsageError for anything else, including a path that leaves the folder through a link.
 */
export function resolveOutputPath(folder: string, output: string | undefined): string {
  if (output === undefined) return THREAT_MODEL_PATH;
  const bad = () => new UsageError("--output must be a relative path to a Markdown file inside the folder, for example THREAT_MODEL.md.");
  // eslint-disable-next-line no-control-regex
  if (!output.trim() || /[\u0000-\u001f\u007f]/.test(output) || isAbsolute(output) || /^[A-Za-z]:/.test(output) || output.startsWith("~")) throw bad();
  const normalized = output.replace(/\\/g, "/").replace(/^(\.\/)+/, "").replace(/\/{2,}/g, "/");
  const parts = normalized.split("/");
  if (parts.some(part => part === ".." || part === "." || part === "" || part === ".git") || !/\.md$/i.test(normalized) || normalized.toLowerCase() === SECURITY_FILE.toLowerCase()) throw bad();
  const root = resolve(folder);
  const target = resolve(root, normalized);
  if (target !== root && !target.startsWith(root + sep)) throw bad();
  // The nearest folder that exists must really be inside the folder: a link could lead anywhere.
  if (!existsSync(root)) return normalized;
  let probe = dirname(target);
  while (!existsSync(probe) && probe !== root) probe = dirname(probe);
  try {
    const real = realpathSync(probe), realRoot = realpathSync(root);
    if (real !== realRoot && !real.startsWith(realRoot + sep)) throw bad();
    if (existsSync(target) && !statSync(target).isFile()) throw bad();
  } catch (error) { if (error instanceof UsageError) throw error; throw bad(); }
  return normalized;
}

export function pullRequestBody(summary: string | undefined, problems: string[], humanKept: boolean | undefined, path: string = THREAT_MODEL_PATH, interview?: { securityFile: string; mode: string }): string {
  return [
    `A drafted threat model for this repository: \`${path}\`.`,
    ...(interview ? ["", `It also changes the Scope section of \`${interview.securityFile}\` and adds a human-marked Scope decisions section. A person gave the answers in a terminal (${interview.mode === "model" ? "questions the model proposed" : "the fixed questionnaire"}) and confirmed each entry; check the diff of the Scope section before merging.`] : []),
    "",
    "It was written by a model from what the code shows, so it can be wrong or incomplete. Review it like any document: correct it, answer the items marked `unknown: confirm with the team` (listed under Open questions), and mark any section you wrote or approved with `<!-- human -->` so later runs keep it unchanged.",
    "",
    `Once merged, scans use it as context: \`0security scan . --context ${path}\`.${interview ? " To honour the declared scope, pass the base branch's copy: `0security scan . --scope base-security.md`." : ""} In CI read it from the base branch, not from the pull request head, so a change under review cannot edit the rules it is checked against.`,
    ...(problems.length ? ["", `Checks 0 ran on the file found problems: ${inert(problems.join("; "))}.`] : []),
    ...(humanKept === undefined ? [] : ["", humanKept ? "Sections marked human from the earlier file were kept unchanged." : "Warning: a section marked human in the earlier file differs from the new one. Compare them in the diff before merging."]),
    "",
    "### What the model reports",
    "",
    inert((summary ?? "").slice(0, 4000)) || "No summary.",
    "",
    "0 does not merge this; a person should.",
  ].join("\n");
}

async function defaultBase(deps: ThreatModelDeps, repo: string, requested?: string): Promise<{ ref: string; name: string }> {
  if (requested) return { ref: requested, name: requested.replace(/^origin\//, "") };
  try {
    const head = (await deps.git(repo, ["symbolic-ref", "--short", "refs/remotes/origin/HEAD"])).trim();
    if (head) return { ref: head, name: head.replace(/^origin\//, "") };
  } catch { /* no remote HEAD */ }
  const current = (await deps.git(repo, ["rev-parse", "--abbrev-ref", "HEAD"])).trim();
  return { ref: "HEAD", name: current === "HEAD" ? "main" : current };
}

async function runThread(client: ConsoleClient, deps: ThreatModelDeps, folder: string, text: string, options: ThreatModelOptions, budget: number, title: string, note: string) {
  const created = asJson(asJson(await client.request("POST", "/api/console/sessions", { runtime: { model: options.model ?? DEFAULT_SCAN_MODEL }, title: title.slice(0, 120), costCeilingUsd: budget })).session);
  const id = String(created.id);
  const path = `/api/console/sessions/${encodeURIComponent(id)}`;
  await client.request("PATCH", `${path}/configuration`, { workspacePath: folder });
  await client.request("POST", `${path}/messages`, { text });
  deps.err(`${note} in thread ${id} (budget $${Number(budget.toFixed(4))})`);
  const { snapshot, timedOut } = await waitForThread(client, deps, id, Date.now() + Number(options.timeout) * 1000);
  const done = finishedThread(snapshot);
  const costUsd = typeof done.usage.costUsd === "number" ? done.usage.costUsd : undefined;
  return { id, reply: done.reply, error: done.error, failed: done.failed && !timedOut, timedOut, budgetExhausted: asJson(done.session).costCeilingExceeded === true, usage: usageLine(done.usage), ...(costUsd !== undefined ? { costUsd } : {}) };
}

const insideFile = (folder: string, relative: string): boolean => {
  const root = resolve(folder);
  const full = resolve(root, relative);
  if (full !== root && !full.startsWith(root + sep)) return false;
  try { return statSync(full).isFile(); } catch { return false; }
};

export async function runThreatModel(folderArg: string | undefined, options: ThreatModelOptions, deps: ThreatModelDeps = defaultThreatModelDeps): Promise<ThreatModelOutcome> {
  let stopConsole: (() => void) | undefined;
  let temp: string | undefined;
  let repo = "";
  let tree = "";
  let madeBranch: { branch: string; existed: boolean } | undefined;
  let committed = false;
  try {
    const budget = Number(options.budget);
    if (!Number.isFinite(budget) || budget <= 0) throw new UsageError("--budget must be a positive number of USD.");
    if (!Number.isFinite(Number(options.timeout)) || Number(options.timeout) <= 0) throw new UsageError("--timeout must be a positive number of seconds.");
    const interviewBudget = Number(options.interviewBudget ?? DEFAULT_INTERVIEW_BUDGET_USD);
    if (!Number.isFinite(interviewBudget) || interviewBudget <= 0) throw new UsageError("--interview-budget must be a positive number of USD.");
    if (options.computer || options.engineUrl) throw new UsageError("0security threat-model writes a file on this machine; run it against the local console.");
    if (options.interviewBudget !== undefined && !options.interview) throw new UsageError("--interview-budget applies to --interview.");
    if ((options.scan || options.fromScan !== undefined || options.scanBudget !== undefined) && !options.interview) throw new UsageError("--scan, --from-scan and --scan-budget apply to --interview.");
    if (options.scan && options.fromScan !== undefined) throw new UsageError("Use --scan or --from-scan, not both.");
    if (options.scanBudget !== undefined && !options.scan) throw new UsageError("--scan-budget applies to --scan.");
    const scanBudget = Number(options.scanBudget ?? DEFAULT_SCAN_BUDGET_USD);
    if (!Number.isFinite(scanBudget) || scanBudget <= 0) throw new UsageError("--scan-budget must be a positive number of USD.");
    if (options.interview && !(deps.isTTY?.() ?? false)) throw new UsageError("0security threat-model --interview asks questions on the terminal. Run it in a terminal.");
    const folder = resolve(folderArg ?? ".");
    if (!existsSync(folder) || !statSync(folder).isDirectory()) throw new UsageError(`${folderArg ?? "."} is not a folder.`);
    const rel = resolveOutputPath(folder, options.output);
    let workFolder = folder;
    let fileRel = rel;
    let securityRel = SECURITY_FILE;
    let base: { ref: string; name: string } | undefined;
    let startRef = "";

    if (options.pr) {
      try { repo = (await deps.git(folder, ["rev-parse", "--show-toplevel"])).trim(); }
      catch { throw new UsageError("--pr needs a folder inside a git repository."); }
      const sub = relative(repo, folder);
      fileRel = sub ? join(sub, rel) : rel;
      securityRel = sub ? join(sub, SECURITY_FILE) : SECURITY_FILE;
      base = await defaultBase(deps, repo, options.base);
      if (THREAT_MODEL_BRANCH === base.name) throw new Error("Refusing to work on the base branch.");
      // Pick up reviewers' commits already on the branch, so running again adds to the pull request instead of replacing it.
      await deps.git(repo, ["fetch", "--quiet", "origin", THREAT_MODEL_BRANCH]).catch(() => undefined);
      const remoteExists = await deps.git(repo, ["rev-parse", "--verify", "--quiet", `refs/remotes/origin/${THREAT_MODEL_BRANCH}`]).then(() => true, () => false);
      startRef = remoteExists ? `origin/${THREAT_MODEL_BRANCH}` : base.ref;
      temp = deps.makeTemp();
      tree = join(temp, "tree");
      const existed = await deps.git(repo, ["rev-parse", "--verify", "--quiet", `refs/heads/${THREAT_MODEL_BRANCH}`]).then(() => true, () => false);
      await deps.git(repo, ["worktree", "add", "--quiet", "-B", THREAT_MODEL_BRANCH, tree, startRef]);
      madeBranch = { branch: THREAT_MODEL_BRANCH, existed };
      workFolder = sub ? join(tree, sub) : tree;
      deps.err(`drafting on branch ${THREAT_MODEL_BRANCH} (isolated work tree, base ${base.name})`);
      // The work tree starts from the base branch: a path that lands on a link there must not leave it.
      resolveOutputPath(workFolder, options.output);
    }

    const target = join(workFolder, rel);
    const securityPath = join(workFolder, SECURITY_FILE);
    const before = deps.readFile(target);
    const securityBefore = deps.readFile(securityPath);
    // The scope section is read as data only: its presence adds a link to the threat model, nothing else.
    const scopeFound = securityBefore !== undefined && parseScope(securityBefore).found;
    // Without --pr the thread edits the folder itself, so remember what was already changed there.
    const dirtyBefore = !options.pr ? await deps.git(workFolder, ["status", "--porcelain", "--untracked-files=all"]).catch(() => undefined) : undefined;
    if (!options.pr) mkdirSync(dirname(target), { recursive: true });

    // The interview's terminal is also where --scan shows its cost and asks before it runs.
    let terminal: (InterviewIO & { close(): void }) | undefined;
    const openTerminal = (): InterviewIO & { close(): void } => (terminal ??= (deps.openTerminal ?? defaultThreatModelDeps.openTerminal!)());
    let client: ConsoleClient | undefined;
    let snapshot: ScanSnapshot | undefined;
    let scanNote: string | undefined;
    let scanCost = 0;
    if (options.interview) {
      const now = (deps.now ?? (() => new Date()))();
      if (options.fromScan !== undefined) {
        try { snapshot = loadReportFile(resolve(options.fromScan), workFolder); }
        catch (error) { throw new UsageError(`--from-scan: ${error instanceof Error ? error.message : String(error)}`); }
      } else if (options.scan) {
        const io = openTerminal();
        const estimate = deps.estimateScan?.(folder, scanBudget) ?? { lowUsd: 0, highUsd: scanBudget };
        io.say(`Scan first: about $${estimate.lowUsd.toFixed(2)} to $${estimate.highUsd.toFixed(2)} for the scan (stops at $${Number(scanBudget.toFixed(4))}), plus up to $${Number(budget.toFixed(4))} for the threat model and $${Number(interviewBudget.toFixed(4))} for the interview. This is a rough estimate, not a quote.`);
        const go = ((await io.ask("Run the scan now? [y/N]: ")) ?? "n").trim().toLowerCase();
        if (go === "y" || go === "yes") {
          try { const connected = await connect(options, deps); stopConsole = connected.stop; client = connected.client; }
          catch (error) { deps.err(`could not reach a console for the scan: ${(error instanceof Error ? error.message : String(error)).split("\n")[0]!.slice(0, 200)}`); }
          const ran = (await deps.runScan?.(folder, { budget: scanBudget, ...(options.model ? { model: options.model } : {}), timeout: options.timeout, ...(client ? { client } : {}) })) ?? { note: "no scan runner" };
          scanCost = ran.costUsd ?? 0;
          if (ran.text) {
            try { snapshot = { findings: findingsFromReport(ran.text, folder), source: "new", label: "the scan that just ran" }; }
            catch (error) { scanNote = `The scan report could not be used (${error instanceof Error ? error.message : String(error)}), so the questions come from reading the code only.`; }
          } else scanNote = `The scan gave no findings to ask about (${ran.note ?? "no report"}), so the questions come from reading the code only.`;
        } else io.say("The scan was not run.");
      }
      if (!snapshot && !scanNote) {
        snapshot = deps.latestScan?.(folder, now);
        if (!snapshot) scanNote = `No scan of this folder from the last ${MAX_SCAN_AGE_DAYS} days is stored, so the questions come from reading the code only. Add --scan to scan first, or --from-scan <report.json> to use a saved report.`;
      }
    }

    let thread: Awaited<ReturnType<typeof runThread>> | undefined;
    let draftError: string | undefined;
    try {
      if (!client) {
        const connected = await connect(options, deps);
        stopConsole = connected.stop;
        client = connected.client;
      }
      thread = await runThread(client, deps, workFolder, threatModelPrompt(folder, { exists: before !== undefined, ...(options.output ? { path: rel } : {}), ...(scopeFound ? { scopeLink: scopeLinkFor(rel) } : {}) }), options, budget, `Threat model ${folder}`, "drafting the threat model");
    } catch (error) {
      // The interview still works without a model: it falls back to the fixed questionnaire.
      if (!options.interview) throw error;
      draftError = error instanceof Error ? error.message : String(error);
      deps.err(`could not draft the threat model: ${draftError.split("\n")[0]!.slice(0, 200)}`);
    }

    let interview: InterviewResult | undefined;
    let wroteSecurity = false;
    let interviewCost = 0;
    const notices: string[] = [];
    if (options.interview) {
      const io = openTerminal();
      try {
        const live = client;
        const model: InterviewModel | undefined = live && thread && !thread.failed && !thread.timedOut ? async (prompt, title) => {
          try {
            const run = await runThread(live, deps, workFolder, prompt, options, interviewBudget, title, title.toLowerCase());
            interviewCost += run.costUsd ?? 0;
            return { ...(run.reply ? { reply: run.reply } : {}), failed: run.failed || run.timedOut || !run.reply, budgetExhausted: run.budgetExhausted };
          } catch { return { failed: true }; }
        } : undefined;
        const draftNow = deps.readFile(target);
        interview = await runInterview({
          target: folder, folder: workFolder, draftPath: rel, draftExists: draftNow !== undefined, securityText: securityBefore,
          humanText: humanBlocks(draftNow ?? before ?? ""), io, ...(model ? { model } : {}), ...(snapshot ? { scan: snapshot } : {}), ...(scanNote ? { scanNote } : {}), fileExists: path => insideFile(workFolder, path), now: (deps.now ?? (() => new Date()))(),
        });
      } finally { terminal?.close(); terminal = undefined; }
      if (interview.securityText !== undefined) { (deps.writePublic ?? deps.writeFile)(securityPath, interview.securityText); wroteSecurity = true; }
      const latest = deps.readFile(target);
      if (interview.writeNotes && interview.notes.length) {
        if (latest === undefined) notices.push(`the threat model was not drafted, so your answers are not in ${rel}; run 0security threat-model again when a model is available`);
        else {
          const found = parseScope(interview.securityText ?? securityBefore ?? "").found;
          const date = (deps.now ?? (() => new Date()))().toISOString().slice(0, 10);
          let next = upsertScopeDecisions(latest, interview.notes, date, found ? scopeLinkFor(rel) : undefined);
          if (found) next = ensureScopeLink(next, scopeLinkFor(rel));
          if (next !== latest) deps.writeFile(target, next);
        }
      } else if (latest !== undefined && scopeFound !== false) {
        const next = ensureScopeLink(latest, scopeLinkFor(rel));
        if (scopeFound && next !== latest) deps.writeFile(target, next);
      }
      if (latest === undefined && draftError === undefined && !notices.length) notices.push(`the threat model was not written to ${rel}`);
      if (draftError) notices.push(`the threat model was not drafted (${draftError.split("\n")[0]!.slice(0, 120)})`);
    }

    const text = deps.readFile(target);
    const problems = checkThreatModel(text);
    const humanKept = before !== undefined ? humanBlocks(before).every(block => text !== undefined && text.includes(block)) : undefined;
    const costUsd = (thread?.costUsd ?? 0) + interviewCost + scanCost;
    const common = {
      file: options.pr ? fileRel : target, written: text !== undefined || wroteSecurity, problems, ...(humanKept === undefined ? {} : { humanSectionsKept: humanKept }),
      ...(thread ? { threadId: thread.id } : {}), ...(thread?.costUsd !== undefined || interviewCost || scanCost ? { costUsd } : {}), ...(thread?.budgetExhausted ? { budgetExhausted: true } : {}), ...(thread?.timedOut ? { timedOut: true } : {}), ...(thread?.reply ? { summary: thread.reply } : {}),
      ...(interview ? { interview: { mode: interview.mode, ...(interview.fallbackReason ? { fallbackReason: interview.fallbackReason } : {}), asked: interview.asked, answered: interview.answered, entries: interview.entries.length, wroteSecurity, ...(wroteSecurity ? { securityFile: options.pr ? securityRel : securityPath } : {}), ...(interview.scan ? { scan: interview.scan } : {}) } } : {}),
      ...(notices.length ? { notices } : {}),
    };
    if (humanKept === false) problems.push("a section marked <!-- human --> was changed; compare with the earlier file before keeping this one");
    // A draft that failed in interview mode is reported as a notice: the interview itself worked.
    if (draftError !== undefined && text === undefined) problems.splice(0, problems.length);

    if (!options.pr) {
      const dirtyAfter = await deps.git(workFolder, ["status", "--porcelain", "--untracked-files=all"]).catch(() => undefined);
      if (dirtyBefore !== undefined && dirtyAfter !== undefined) {
        const earlier = new Set(dirtyBefore.split("\n"));
        const others = dirtyAfter.split("\n").filter(line => line && !earlier.has(line) && !line.endsWith(rel) && !(wroteSecurity && line.endsWith(SECURITY_FILE)));
        if (others.length) problems.push(`the thread also changed ${others.length} other file${others.length === 1 ? "" : "s"}: ${others.slice(0, 5).map(line => line.slice(3)).join(", ")}; review and revert them`);
      }
      return { ...common, changed: (text !== undefined && text !== before) || (wroteSecurity && interview?.securityText !== securityBefore) };
    }

    const status = (await deps.git(tree, ["status", "--porcelain", "--untracked-files=all"])).trim();
    const others = status.split("\n").filter(line => line && !line.endsWith(fileRel) && !(wroteSecurity && line.endsWith(securityRel)));
    if (others.length) problems.push(`the thread also changed ${others.length} other file${others.length === 1 ? "" : "s"}; they were left out of the commit`);
    const malformed = problems.some(problem => problem.startsWith("it has no front matter") || problem.startsWith("missing sections"));
    if ((text === undefined && !wroteSecurity) || (text !== undefined && malformed)) {
      deps.err(`not opening a pull request: ${problems.join("; ") || "nothing was written"}`);
      return { ...common, changed: false };
    }
    if (text !== undefined) await deps.git(tree, ["add", "--", fileRel]);
    if (wroteSecurity) await deps.git(tree, ["add", "--", securityRel]);
    const unchanged = await deps.git(tree, ["diff", "--cached", "--quiet"]).then(() => true, () => false);
    if (unchanged) { deps.err("the threat model is unchanged; no pull request was opened."); return { ...common, changed: false, branch: THREAT_MODEL_BRANCH }; }
    // A clean machine or an Actions runner has no git identity; use a neutral one rather than fail the commit.
    const configured = (await deps.git(tree, ["config", "user.email"]).catch(() => "")).trim();
    const identity = configured ? [] : ["-c", "user.name=0", "-c", "user.email=noreply@0.security"];
    await deps.git(tree, [...identity, "commit", "--quiet", "-m", `docs: ${before === undefined ? "draft" : "update"} the threat model${wroteSecurity ? " and declare its scope" : ""}\n\nWritten by 0security threat-model${options.interview ? " --interview" : ""} for review.`]);
    committed = true;
    await deps.git(tree, ["push", "--set-upstream", "origin", `${THREAT_MODEL_BRANCH}:${THREAT_MODEL_BRANCH}`]);
    const bodyFile = join(temp!, "body.md");
    deps.writeFile(bodyFile, pullRequestBody(thread?.reply, problems, humanKept, rel, interview && wroteSecurity ? { securityFile: SECURITY_FILE, mode: interview.mode } : undefined));
    const existing = JSON.parse((await deps.gh(tree, ["pr", "list", "--head", THREAT_MODEL_BRANCH, "--state", "open", "--json", "number,url"])) || "[]") as Array<{ number: number; url: string }>;
    let url: string; let created = false;
    if (existing[0]) { url = existing[0].url; await deps.gh(tree, ["pr", "edit", String(existing[0].number), "--body-file", bodyFile]); }
    else { created = true; url = (await deps.gh(tree, ["pr", "create", "--base", base!.name, "--head", THREAT_MODEL_BRANCH, "--title", `docs: ${before === undefined ? "draft" : "update"} the threat model${wroteSecurity ? " and scope" : ""} (review needed)`, "--body-file", bodyFile])).trim().split("\n").pop() ?? ""; }
    return { ...common, changed: true, branch: THREAT_MODEL_BRANCH, pullRequest: { url, created } };
  } finally {
    stopConsole?.();
    if (tree && repo) await deps.git(repo, ["worktree", "remove", "--force", tree]).catch(() => undefined);
    if (madeBranch && !madeBranch.existed && !committed) await deps.git(repo, ["branch", "-D", madeBranch.branch]).catch(() => undefined);
    if (temp) deps.removeTemp(temp);
  }
}

export function registerThreatModelCommand(program: Command, deps: ThreatModelDeps = defaultThreatModelDeps): void {
  consoleTransportOptions(program.command("threat-model [folder]")
    .description("Draft the repository's threat model as a file for people to review (optionally as a pull request)")
    .option("--pr", "Commit the file on the branch 0/threat-model in a separate git work tree and open or update a pull request")
    .option("--base <branch>", "With --pr: the branch to start from and open the pull request against (default: the remote's default branch)")
    .option("--interview", "After the draft, ask a few specific questions on the terminal and write your answers to the Scope section of SECURITY.md and to a human block of the threat model. Needs a terminal")
    .option("--interview-budget <usd>", `With --interview: the most each interview thread may spend (default: ${DEFAULT_INTERVIEW_BUDGET_USD})`)
    .option("--scan", "With --interview: run a scan of the folder first and ask about the classes of vulnerability it finds. Shows the estimated cost and asks before it runs")
    .option("--from-scan <report>", "With --interview: ask about the classes in this saved report (from 0security scan --format json). Without --scan or --from-scan, the latest scan of the folder from the last 30 days is used when there is one")
    .option("--scan-budget <usd>", `With --scan: the most the scan may spend (default: ${DEFAULT_SCAN_BUDGET_USD})`)
    .option("--output <path>", `Where to write the threat model, relative to the folder, a .md file (default: ${THREAT_MODEL_PATH}); for example THREAT_MODEL.md`)
    .option("--format <format>", "json prints the outcome as JSON")
    .option("--budget <usd>", "Stop when the estimated spend reaches this many USD", String(DEFAULT_BUDGET_USD))
    .option("--model <model>", `Model for the thread (default: ${DEFAULT_SCAN_MODEL})`)
    .option("--timeout <seconds>", "Maximum seconds to wait", String(DEFAULT_TIMEOUT_SECONDS)))
    .addHelpText("after", `\nSections you mark with <!-- human --> are kept unchanged when the file is updated. Later scans take the file with \`0security scan --context ${THREAT_MODEL_PATH}\`.\nExit codes: 0 file written and well formed, 1 not written or malformed, 2 usage error, 3 stopped at the budget or time limit.`)
    .action(async (folder: string | undefined, options: ThreatModelOptions) => {
      try {
        const outcome = await runThreatModel(folder, options, deps);
        if (options.format === "json") deps.out(JSON.stringify(outcome, null, 2));
        else {
          if (outcome.pullRequest) deps.out(`${outcome.pullRequest.created ? "Opened" : "Updated"} pull request: ${outcome.pullRequest.url}`);
          else if (outcome.written) deps.out(`Wrote ${outcome.file}${outcome.changed ? "" : " (unchanged)"}${outcome.interview?.wroteSecurity ? ` and ${outcome.interview.securityFile}` : ""}. Review ${outcome.interview?.wroteSecurity ? "them" : "it"}, then commit ${outcome.interview?.wroteSecurity ? "them" : "it"}.`);
          else deps.out("No threat model was written.");
          for (const problem of outcome.problems) deps.err(`warning: ${problem}`);
          for (const notice of outcome.notices ?? []) deps.err(`note: ${notice}`);
        }
        process.exitCode = outcome.budgetExhausted || outcome.timedOut ? 3 : outcome.written && outcome.problems.length === 0 ? 0 : 1;
      } catch (error) { finishWithError(error, { err: deps.err }, options.format === "json"); }
    });
}
