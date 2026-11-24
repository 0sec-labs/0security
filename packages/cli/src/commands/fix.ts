/**
 * `0 fix <finding>`: a thread that follows the `fix-finding` skill in an isolated git work tree, then a pull request.
 *
 * The thread makes the smallest change it can. This command does the rest, the same way every time: it runs the
 * checks you name, commits on a branch of its own and opens or updates one pull request, a draft when a check
 * fails. It never pushes to the default branch and never merges; a person reviews and merges.
 */
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { Option, type Command } from "commander";
import { assertEgressAllowed } from "@0/engine";
import { fixPrompt, type FixPolicy, type FixPromptFinding } from "@0/engine/shared";
import { loadFixPolicyFile, type FixPolicyOptions, type LoadedFixPolicy } from "./fix-policy.js";
import { osecDB, resolveOsecDbPath } from "@0/engine/storage";
import { consoleTransportOptions, type ConsoleClient, type ConsoleTransportOptions } from "../console-client.js";
import { connect, DEFAULT_SCAN_MODEL, defaultScanDeps, waitForThread, type ScanDeps } from "./scan.js";
import { resolveFindingId, shortFindingId } from "../finding-id.js";
import { selectHost, type Host } from "../host/index.js";
import { commitSubject, footerText, isDraft, pullRequestTitle, type PullRequestConventions } from "./fix-conventions.js";
import { finishWithError, UsageError } from "./output.js";
import { runInSandbox, sandboxLabel, validateSandboxImage, type SandboxSpec } from "./fix-sandbox.js";
import { appendRunMetric, type RunMetric } from "../run-metrics.js";
import { applyWorkflowDefaults } from "../workflow-defaults.js";

export { DEFAULT_FIX_POLICY_FILES, parseFixPolicy, loadFixPolicyFile } from "./fix-policy.js";
import { asJson, finishedThread, usageLine } from "./thread-output.js";

const exec = promisify(execFile);
const DEFAULT_BUDGET_USD = 3;
const DEFAULT_TIMEOUT_SECONDS = 1800;
const CHECK_TIMEOUT_MS = 10 * 60 * 1000;
export const BRANCH_PREFIX = "0/fix-";

export interface CheckResult { command: string; code: number; output: string; /** Set when the command ran in a container: "<image>, network off". */ sandbox?: string }
export interface FindingToFix extends FixPromptFinding { fingerprint: string }

export interface FixDeps extends Pick<ScanDeps, "open" | "err" | "sleep" | "startConsole"> {
  out(text: string): void;
  git(cwd: string, args: string[]): Promise<string>;
  gh(cwd: string, args: string[], input?: string): Promise<string>;
  /** Run one check command in the work tree through the shell, or in a container with `sandbox`. Never throws on a failing command. */
  check(cwd: string, command: string, sandbox?: SandboxSpec): Promise<CheckResult>;
  loadFinding(id: string, dbPath: string | undefined): FindingToFix;
  loadPolicy(repoRoot: string, options: FixPolicyOptions): LoadedFixPolicy | undefined;
  makeTemp(): string;
  removeTemp(path: string): void;
  writeFile(path: string, text: string): void;
  /** Record one run in the metrics file (counts and ids only). Absent in tests, so they write nothing. */
  metrics?(record: Omit<RunMetric, "version" | "ci">): void;
}

function resolveRow(rows: Array<Record<string, unknown>>, id: string): Record<string, unknown> {
  try {
    const row = resolveFindingId(rows as Array<{ id: string } & Record<string, unknown>>, id);
    if (row) return row;
  } catch (error) { throw new UsageError(error instanceof Error ? error.message : String(error)); }
  throw new UsageError(`Finding '${id}' not found.`);
}

const defaults: FixDeps = {
  open: defaultScanDeps.open, err: defaultScanDeps.err, sleep: defaultScanDeps.sleep, startConsole: defaultScanDeps.startConsole,
  out: text => process.stdout.write(`${text}\n`),
  async git(cwd, args) { return (await exec("git", ["-C", cwd, ...args], { maxBuffer: 32 * 1024 * 1024 })).stdout; },
  async gh(cwd, args, input) {
    assertEgressAllowed("GitHub (gh)");
    const running = exec("gh", args, { cwd, maxBuffer: 32 * 1024 * 1024 });
    running.child.stdin?.end(input ?? "");
    return (await running).stdout;
  },
  async check(cwd, command, sandbox) {
    if (sandbox) return runInSandbox(cwd, command, sandbox);
    try {
      const { stdout, stderr } = await exec("/bin/sh", ["-c", command], { cwd, timeout: CHECK_TIMEOUT_MS, maxBuffer: 8 * 1024 * 1024 });
      return { command, code: 0, output: `${stdout}${stderr}` };
    } catch (error) {
      const failure = error as { code?: number | string; stdout?: string; stderr?: string; killed?: boolean };
      return { command, code: typeof failure.code === "number" ? failure.code : failure.killed ? 124 : 1, output: `${failure.stdout ?? ""}${failure.stderr ?? ""}` };
    }
  },
  loadFinding(id, dbPath) {
    const db = new osecDB(resolveOsecDbPath(dbPath));
    try {
      const row = resolveRow(db.listFindings({ limit: 5000 }) as unknown as Array<Record<string, unknown>>, id);
      const annotation = db.getFindingReviewFields(String(row.id)).reviewAnnotation;
      return {
        id: String(row.id), title: String(row.title), severity: String(row.severity), category: String(row.category),
        tool: typeof row.tool === "string" ? row.tool : null, description: String(row.description ?? ""),
        fingerprint: String(row.fingerprint ?? row.id),
        ...(annotation ? { path: annotation.path, startLine: annotation.startLine, ...(annotation.endLine ? { endLine: annotation.endLine } : {}) } : {}),
        ...(typeof row.evidenceResponse === "string" && row.evidenceResponse ? { snippet: row.evidenceResponse } : {}),
      };
    } finally { db.close(); }
  },
  loadPolicy: (repoRoot, options) => loadFixPolicyFile(repoRoot, options),
  makeTemp: () => mkdtempSync(join(tmpdir(), "0-fix-")),
  removeTemp: path => rmSync(path, { recursive: true, force: true }),
  writeFile: (path, text) => writeFileSync(path, text, { mode: 0o600 }),
  metrics: record => appendRunMetric(record),
};

export const defaultFixDeps: FixDeps = defaults;

/** The same finding always gets the same branch, so a second run updates the same pull request. */
export function fixBranchName(fingerprint: string, prefix: string = BRANCH_PREFIX): string {
  return `${prefix}${createHash("sha256").update(fingerprint).digest("hex").slice(0, 12)}`;
}

/** Report text goes into a pull request body: stop it from notifying people or referencing other issues. */
const inert = (text: string): string => text.replace(/@/g, "@\u200b").replace(/(^|\s)#(\d)/g, "$1#\u200b$2");

/** Text for a table cell or an HTML element: no markup, no pipes, one line. */
const escapeHtml = (text: string): string => text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const cell = (text: string): string => inert(escapeHtml(text.replace(/\s+/g, " ").trim())).replace(/\|/g, "\\|").replace(/`/g, "'");

/** The model's own words can claim anything about the checks; leave out any line that is headed "Checks" so the real table stays the only one. */
const withoutCheckHeadings = (text: string): string => {
  let skipping = false;
  return text.split("\n").filter(line => {
    if (/^\s*(?:(?:#{1,6}|[*_]{1,3})\s*checks?\b|checks?\s*:?\s*$)/i.test(line)) { skipping = true; return false; }
    if (skipping && (!line.trim() || /^\s*#{1,6}\s/.test(line))) skipping = false;
    return !skipping;
  }).join("\n").trim();
};

/** The sandbox line is written only when every check ran in a container and passed. */
export function sandboxVerifiedLine(checks: CheckResult[]): string | undefined {
  if (!checks.length || checks.some(check => check.code !== 0 || !check.sandbox)) return undefined;
  const labels = [...new Set(checks.map(check => check.sandbox!))];
  return labels.length === 1 ? `Verified in a sandbox: ${cell(labels[0]!)}.` : undefined;
}

export function pullRequestBody(finding: FindingToFix, summary: string | undefined, checks: CheckResult[], footer?: string, draftUnchecked = false): string {
  const where = finding.path ? `\`${finding.path.replace(/`/g, "'")}${finding.startLine ? `:${finding.startLine}` : ""}\`` : "not given";
  const rows = checks.length ? checks.map(check => `| \`${escapeHtml(check.command.replace(/`/g, "'").replace(/\s+/g, " ")).replace(/\|/g, "\\|")}\` | ${check.code === 0 ? "passed" : `failed (exit ${check.code})`} |`).join("\n") : "| none were run | |";
  const failed = checks.filter(check => check.code !== 0);
  const tails = failed.map(check => `<details><summary>${inert(escapeHtml(check.command.replace(/\s+/g, " ")))}</summary>\n\n\`\`\`\n${check.output.slice(-2000).replace(/```/g, "'''")}\n\`\`\`\n</details>`).join("\n");
  const modelText = withoutCheckHeadings((summary ?? "").slice(0, 5000));
  return [
    `Fixes finding ${shortFindingId(finding.id)}: ${inert(finding.title)}`,
    "",
    `| Severity | Category | Reported by | Where |\n| --- | --- | --- | --- |\n| ${cell(finding.severity)} | ${cell(finding.category)} | ${cell(finding.tool ?? "0")} | ${where} |`,
    "",
    "### Checks",
    `| Command | Result |\n| --- | --- |\n${rows}`,
    ...(sandboxVerifiedLine(checks) ? ["", sandboxVerifiedLine(checks)!] : checks.some(check => check.sandbox) ? ["", "Not verified in a sandbox: a sandboxed check failed."] : checks.length ? ["", "These checks ran on the machine that ran 0, not in a sandbox."] : []),
    ...(tails ? ["", tails] : []),
    "",
    "### What changed",
    "Summary written by the model (not verified). The Checks table above is what 0 ran.",
    "",
    inert(modelText || "The change is in the diff."),
    "",
    ...(!checks.length ? ["No checks were run."] : []),
    failed.length ? "Opened as a draft because a check failed. Review it before it is marked ready." : draftUnchecked ? "Opened as a draft because no check ran. Review it before it is marked ready." : "A person should review this before merging; 0 does not merge.",
    ...(footer ? ["", footer] : []),
  ].join("\n");
}

export interface FixOptions extends ConsoleTransportOptions {
  repo?: string; base?: string; test?: string[]; ready?: boolean; budget: string; model?: string; timeout: string; pr: boolean; format?: string; policy?: string; repoPolicy?: boolean; sandbox?: string; sandboxImage?: string; sandboxNetwork?: boolean;
}

export interface FixOutcome {
  finding: string; branch: string; changed: boolean; committed: boolean; checks: CheckResult[]; verified: boolean;
  pullRequest?: { url: string; created: boolean; draft: boolean }; threadId?: string; costUsd?: number; tokens?: number; budgetExhausted?: boolean; timedOut?: boolean; summary?: string;
}

/** The metrics record of one fix run; `outcome` is undefined when the run failed before it had one. */
export function fixMetric(outcome: FixOutcome | undefined, options: Pick<FixOptions, "model" | "budget">, startedAt: number, endedAt: number): Omit<RunMetric, "version" | "ci"> {
  const status = !outcome ? "failed" : outcome.timedOut ? "timeout" : outcome.budgetExhausted ? "budget" : outcome.committed ? "ok" : "failed";
  return {
    at: new Date(startedAt).toISOString(), command: "fix", model: options.model ?? DEFAULT_SCAN_MODEL, budgetUsd: Number(options.budget), costUsd: outcome?.costUsd ?? null,
    durationSeconds: Math.max(0, Math.round((endedAt - startedAt) / 1000)), findingsAttempted: 1, findingsProposed: outcome?.committed ? 1 : 0, checksPassed: outcome?.committed && outcome.verified ? 1 : 0,
    tokens: outcome?.tokens ?? null, status, findingIds: outcome ? [outcome.finding] : [],
  };
}

async function defaultBase(deps: FixDeps, repo: string, requested?: string): Promise<{ ref: string; name: string }> {
  if (requested) return { ref: requested, name: requested.replace(/^origin\//, "") };
  try {
    const head = (await deps.git(repo, ["symbolic-ref", "--short", "refs/remotes/origin/HEAD"])).trim();
    if (head) return { ref: head, name: head.replace(/^origin\//, "") };
  } catch { /* no remote HEAD */ }
  const current = (await deps.git(repo, ["rev-parse", "--abbrev-ref", "HEAD"])).trim();
  return { ref: "HEAD", name: current === "HEAD" ? "main" : current };
}

/** Check the sandbox flags together. Without --sandbox the checks run on this machine with your privileges. */
export function sandboxSpec(options: FixOptions, env: NodeJS.ProcessEnv = process.env): SandboxSpec | undefined {
  if (!options.sandbox) {
    if (options.sandboxImage || options.sandboxNetwork) throw new UsageError("--sandbox-image and --sandbox-network need --sandbox docker.");
    return undefined;
  }
  if (options.sandbox !== "docker") throw new UsageError("--sandbox must be docker.");
  if (!options.sandboxImage) throw new UsageError("--sandbox docker needs --sandbox-image, for example maven:3-eclipse-temurin-21.");
  if (!options.test?.length) throw new UsageError("--sandbox runs your --test commands in the container; give at least one --test.");
  let image: string;
  try { image = validateSandboxImage(options.sandboxImage); } catch (error) { throw new UsageError(error instanceof Error ? error.message : String(error)); }
  if (options.sandboxNetwork) assertEgressAllowed("the network from the fix sandbox (--sandbox-network)", env);
  return { image, network: Boolean(options.sandboxNetwork) };
}

export async function runFix(id: string, options: FixOptions, deps: FixDeps): Promise<FixOutcome | undefined> {
  const started = Date.now();
  try {
    const outcome = await runFixFlow(id, options, deps);
    deps.metrics?.(fixMetric(outcome, options, started, Date.now()));
    return outcome;
  } catch (error) {
    // A usage error is a mistyped command, not a run.
    if (!(error instanceof UsageError)) deps.metrics?.(fixMetric(undefined, options, started, Date.now()));
    throw error;
  }
}

async function runFixFlow(id: string, options: FixOptions, deps: FixDeps): Promise<FixOutcome | undefined> {
  let stopConsole: (() => void) | undefined;
  let temp: string | undefined;
  let repo = "";
  let tree = "";
  let madeBranch: { repo: string; branch: string; existed: boolean } | undefined;
  let committedBranch = false;
  try {
    const budget = Number(options.budget);
    if (!Number.isFinite(budget) || budget <= 0) throw new UsageError("--budget must be a positive number of USD.");
    if (!Number.isFinite(Number(options.timeout)) || Number(options.timeout) <= 0) throw new UsageError("--timeout must be a positive number of seconds.");
    const sandbox = sandboxSpec(options);
    if (options.computer || options.engineUrl) throw new UsageError("0security fix edits files on this machine; run it against the local console.");
    const finding = deps.loadFinding(id, options.dbPath);
    try { repo = (await deps.git(resolve(options.repo ?? process.cwd()), ["rev-parse", "--show-toplevel"])).trim(); }
    catch { throw new UsageError("Run this inside the git repository the finding is in, or pass --repo."); }
    const base = await defaultBase(deps, repo, options.base);
    // The policy is read before anything is created: a bad pull request setting stops the run first.
    const loaded = deps.loadPolicy(repo, options);
    const conventions: PullRequestConventions | undefined = loaded && !loaded.fromRepo ? loaded.conventions : undefined;
    const prefix = conventions?.branchPrefix ?? BRANCH_PREFIX;
    const branch = fixBranchName(finding.fingerprint, prefix);
    if (branch === base.name || !branch.startsWith(prefix)) throw new Error("Refusing to work on the base branch.");

    temp = deps.makeTemp();
    tree = join(temp, "tree");
    const branchExisted = await deps.git(repo, ["rev-parse", "--verify", "--quiet", `refs/heads/${branch}`]).then(() => true, () => false);
    await deps.git(repo, ["worktree", "add", "--quiet", "-B", branch, tree, base.ref]);
    madeBranch = { repo, branch, existed: branchExisted };
    deps.err(`fixing ${finding.title} on branch ${branch} (isolated work tree, base ${base.name})`);

    const { client, stop } = await connect(options, deps);
    stopConsole = stop;
    const policy = loaded?.policy;
    if (loaded) {
      const libs = loaded.policy.approvedLibraries?.length ?? 0;
      const rules = loaded.policy.rules?.length ?? 0;
      deps.err(`applying fix policy from ${loaded.source} (${libs} approved ${libs === 1 ? "library" : "libraries"}, ${rules} ${rules === 1 ? "rule" : "rules"})`);
      if (loaded.fromRepo) deps.err("warning: this policy comes from the repository being fixed, which is untrusted; it is guidance for the model, not a safety control, and its pull request settings are ignored");
      if (conventions) deps.err("applying pull request conventions from the policy");
    }
    const outcomeBase = { finding: finding.id, branch };
    const thread = await runThread(client, deps, tree, finding, options, budget, policy, Boolean(sandbox));
    const status = (await deps.git(tree, ["status", "--porcelain", "--untracked-files=all"])).trim();
    const common = { ...outcomeBase, threadId: thread.id, ...(thread.costUsd !== undefined ? { costUsd: thread.costUsd } : {}), ...(thread.tokens !== undefined ? { tokens: thread.tokens } : {}), ...(thread.budgetExhausted ? { budgetExhausted: true } : {}), ...(thread.timedOut ? { timedOut: true } : {}), ...(thread.reply ? { summary: thread.reply } : {}) };
    if (!status) {
      deps.err(thread.error ?? "The thread made no change; no pull request was opened.");
      return { ...common, changed: false, committed: false, checks: [], verified: false };
    }

    const checks: CheckResult[] = [];
    for (const command of options.test ?? []) { deps.err(`running${sandbox ? ` in a sandbox (${sandboxLabel(sandbox)})` : ""}: ${command}`); checks.push(await deps.check(tree, command, sandbox)); }
    const verified = checks.every(check => check.code === 0) && !thread.failed;

    await deps.git(tree, ["add", "-A"]);
    // A clean machine or an Actions runner has no git identity; use a neutral one rather than fail the commit.
    const configured = (await deps.git(tree, ["config", "user.email"]).catch(() => "")).trim();
    const identity = configured ? [] : ["-c", "user.name=0", "-c", "user.email=noreply@0.security"];
    await deps.git(tree, [...identity, "commit", "--quiet", "-m", `${commitSubject(finding, conventions)}\n\nFinding ${finding.id}`]);
    committedBranch = true;
    const outcome: FixOutcome = { ...common, changed: true, committed: true, checks, verified };
    if (!options.pr) { deps.err(`committed on ${branch}; not pushed (--no-pr).`); return outcome; }

    // The branch is ours and only ours: never the base, always with a lease so a person's later push is not overwritten.
    const host = selectHost({ run: (args, input) => deps.gh(tree, args, input), git: args => deps.git(tree, args) });
    await host.pushBranch(branch);
    const bodyFile = join(temp, "body.md");
    const draft = isDraft(verified, conventions, !checks.length && !options.ready);
    deps.writeFile(bodyFile, pullRequestBody(finding, thread.reply, checks, footerText(conventions), draft && verified && !checks.length));
    const existing = await host.findOpenPullRequest(branch);
    let url: string; let created = false;
    if (existing) {
      url = existing.url;
      await host.updatePullRequestBody(existing.number, bodyFile);
      if (existing.isDraft && !draft) await host.setPullRequestReady(existing.number, true);
      if (!existing.isDraft && draft) await host.setPullRequestReady(existing.number, false);
    } else {
      created = true;
      url = await host.createPullRequest({ base: base.name, head: branch, title: pullRequestTitle(finding, conventions), bodyFile, draft });
    }
    if (conventions?.labels?.length || conventions?.reviewers?.length) await decoratePullRequest(host, url, conventions, deps.err);
    return { ...outcome, pullRequest: { url, created, draft } };
  } finally {
    stopConsole?.();
    if (tree && repo) await deps.git(repo, ["worktree", "remove", "--force", tree]).catch(() => undefined);
    // A branch this run made and never committed to is only clutter.
    if (madeBranch && !madeBranch.existed && !committedBranch) await deps.git(madeBranch.repo, ["branch", "-D", madeBranch.branch]).catch(() => undefined);
    if (temp) deps.removeTemp(temp);
  }
}

/** Labels that exist (or can be made) and reviewers go on the pull request. A refusal is a warning: the pull request is already open. */
async function decoratePullRequest(host: Host, url: string, conventions: PullRequestConventions, warn: (text: string) => void): Promise<void> {
  const number = Number(/\/pull\/(\d+)/.exec(url)?.[1]);
  if (!Number.isInteger(number) || number < 1) { warn(`could not tell the pull request number from ${url}; labels and reviewers were not added`); return; }
  try {
    let labels: string[] = [];
    if (conventions.labels?.length) {
      const repo = await host.currentRepo();
      if (!repo) warn("could not tell the repository, so the labels were skipped");
      else {
        const checked = await host.issues(repo).ensureLabels(conventions.labels);
        for (const warning of checked.warnings) warn(`warning: ${warning}`);
        labels = checked.usable;
      }
    }
    if (labels.length) await host.editPullRequest(number, { addLabels: labels });
  } catch (error) { warn(`warning: labels were not added (${error instanceof Error ? error.message.split("\n")[0]!.slice(0, 160) : "unknown error"})`); }
  if (conventions.reviewers?.length) {
    try { await host.editPullRequest(number, { addReviewers: conventions.reviewers }); }
    catch (error) { warn(`warning: reviewers were not requested (${error instanceof Error ? error.message.split("\n")[0]!.slice(0, 160) : "unknown error"})`); }
  }
}

async function runThread(client: ConsoleClient, deps: FixDeps, folder: string, finding: FindingToFix, options: FixOptions, budget: number, policy?: FixPolicy, sandboxed = false) {
  const created = asJson(asJson(await client.request("POST", "/api/console/sessions", { runtime: { model: options.model ?? DEFAULT_SCAN_MODEL }, title: `Fix: ${finding.title}`.slice(0, 120), costCeilingUsd: budget })).session);
  const id = String(created.id);
  const path = `/api/console/sessions/${encodeURIComponent(id)}`;
  await client.request("PATCH", `${path}/configuration`, { workspacePath: folder });
  await client.request("POST", `${path}/messages`, { text: fixPrompt(finding, { tests: options.test ?? [], policy, sandboxed }) });
  deps.err(`working in thread ${id} (budget $${Number(budget.toFixed(4))})`);
  const { snapshot, timedOut } = await waitForThread(client, deps, id, Date.now() + Number(options.timeout) * 1000);
  const done = finishedThread(snapshot);
  const costUsd = typeof done.usage.costUsd === "number" ? done.usage.costUsd : undefined;
  const tokens = typeof done.usage.inputTokens === "number" && typeof done.usage.outputTokens === "number" ? done.usage.inputTokens + done.usage.outputTokens : undefined;
  return { id, reply: done.reply, error: done.error, failed: done.failed && !timedOut, ...(tokens !== undefined ? { tokens } : {}), timedOut, budgetExhausted: asJson(done.session).costCeilingExceeded === true, usage: usageLine(done.usage), ...(costUsd !== undefined ? { costUsd } : {}) };
}

export function registerFixCommand(program: Command, deps: FixDeps = defaults): void {
  const collect = (value: string, previous: string[] = []) => [...previous, value];
  consoleTransportOptions(program.command("fix <finding>")
    .description("Fix one finding in an isolated git work tree and open a pull request for review")
    .option("--repo <dir>", "Git repository the finding is in (default: the current directory)")
    .option("--base <branch>", "Branch to start from and open the pull request against (default: the remote's default branch)")
    .option("--test <command>", "Check to run after the change; repeat for several. A failing check makes the pull request a draft", collect)
    .option("--ready", "Open the pull request ready for review even when no --test ran. Without it, a pull request with no checks is a draft")
    .addOption(new Option("--sandbox <mode>", "Run the --test commands in a container instead of on this machine (docker)").choices(["docker"]))
    .option("--sandbox-image <image>", "Image for --sandbox docker, for example maven:3-eclipse-temurin-21. It must hold the tools and dependencies the tests need")
    .option("--sandbox-network", "Give the sandbox network access (to download dependencies). Off by default")
    .option("--policy <file>", "Policy file (.json or .yaml) of approved libraries and fix rules; any path you name, relative to the current directory. Default: ~/.0/fix-policy.json|yaml|yml")
    .option("--repo-policy", "Also read fix-policy.* or .zero/fix-policy.* from the repository being fixed (untrusted content; off by default)")
    .option("--no-pr", "Commit on the fix branch but do not push or open a pull request")
    .option("--budget <usd>", "Stop when the estimated spend reaches this many USD", String(DEFAULT_BUDGET_USD))
    .option("--model <model>", `Model for the fix thread (default: ${DEFAULT_SCAN_MODEL})`)
    .option("--timeout <seconds>", "Maximum seconds to wait for the fix", String(DEFAULT_TIMEOUT_SECONDS))
    .addOption(new Option("--format <format>", "Output: text or json").choices(["text", "json"]))
    )
    .addHelpText("after", "\nNothing is pushed to the base branch and nothing is merged: the change goes to a branch named 0/fix-<id>, and running it again updates the same pull request.\nWithout --sandbox, --test commands run on this machine with your privileges. With --sandbox docker they run in a container with no network, limited memory, CPU and processes, a copy of the work tree and none of your environment variables; the pull request says so only when every check passed there.\nA pull request is a draft when a check failed or when no --test ran; --ready opens it ready in the second case.\nExit codes: 0 a change was made and no check failed (also with --no-pr), 1 no change or a failed check, 2 usage error, 3 stopped at the budget or time limit.")
    .action(async (finding: string, options: FixOptions, command: Command) => {
      try {
        const outcome = await runFix(finding, applyWorkflowDefaults("fix", options, command), deps);
        if (!outcome) return;
        if (options.format === "json") deps.out(JSON.stringify(outcome, null, 2));
        else if (outcome.pullRequest) deps.out(`${outcome.pullRequest.created ? "Opened" : "Updated"} ${outcome.pullRequest.draft ? "draft " : ""}pull request: ${outcome.pullRequest.url}`);
        else if (outcome.committed) deps.out(`Committed on ${outcome.branch}.`);
        else deps.out("No change was made.");
        process.exitCode = outcome.budgetExhausted || outcome.timedOut ? 3 : outcome.changed && outcome.verified ? 0 : 1;
      } catch (error) { finishWithError(error, { err: deps.err }, options.format === "json"); }
    });
}
