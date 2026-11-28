import { metricPullRequest } from "../metric-pr.js";
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
import { assertEgressAllowed, bumpJavaDependency, parseDependencyFinding, untrustedGitActionConfig } from "@0/engine";
import { fixPrompt, type FixPolicy, type FixPromptFinding, type RootCause } from "@0/engine/shared";
import { loadPolicyBundle } from "../policy-bundle/index.js";
import { loadFixPolicyFile, parseFixPolicyDocument, type FixPolicyOptions, type LoadedFixPolicy } from "./fix-policy.js";
import { osecDB, resolveOsecDbPath } from "@0/engine/storage";
import { consoleTransportOptions, type ConsoleClient, type ConsoleTransportOptions } from "../console-client.js";
import { VariantBudget, defaultVariantStore, DEFAULT_VARIANT_BUDGET_USD, huntVariants, rescanSummary, rescanVariants, type VariantParent, type VariantStore } from "./variants.js";
import { connect, DEFAULT_SCAN_MODEL, scanModelField, scanModelLabel, defaultScanDeps, waitForThread, type ScanDeps } from "./scan.js";
import { resolveFindingId, shortFindingId } from "../finding-id.js";
import type { Host } from "../host/index.js";
import { selectFixHost } from "../host/fix-host.js";
import { MAX_REVIEWERS, commitSubject, footerText, isDraft, needsTicket, parseTicket, pullRequestTitle, renderBodyTemplate, resolveBranchPrefix, type PullRequestConventions } from "./fix-conventions.js";
import { CODEOWNERS_PATHS, reviewersFromCodeowners } from "./fix-codeowners.js";
import { finishWithError, UsageError } from "./output.js";
import { applySandboxProfile, validateMavenSettingsFile, isPinnedImage, makeSandboxCache, NETWORK_CANARY, runInSandbox, sandboxLabel, validateSandboxImage, type SandboxSpec } from "./fix-sandbox.js";
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
export interface FindingToFix extends FixPromptFinding {
  fingerprint: string;
  /** Where the finding is stored and which scan it belongs to; variants found after the fix are stored there. Absent: no variant hunt. */
  dbPath?: string; scanId?: string; rootCause?: RootCause; variantOf?: string;
}

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
  /** Remember what a standalone fix did, so `findings export-fixes` can report it. Not set for burndown, which keeps its own record. */
  record?(entry: { repo: string; fingerprint: string; outcome: FixOutcome }): void | Promise<void>;
  /** Where root causes and variants are stored. Absent in tests that do not hunt, so they write nothing. */
  variants?: VariantStore;
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
  async git(cwd, args) { return (await exec("git", ["-C", cwd, ...untrustedGitActionConfig(cwd), ...args], { maxBuffer: 32 * 1024 * 1024 })).stdout; },
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
        dbPath: resolveOsecDbPath(dbPath), scanId: String(row.scanId),
        ...(db.getFindingRootCause(String(row.id)) ? { rootCause: db.getFindingRootCause(String(row.id)) } : {}),
        ...(typeof row.variantOf === "string" && row.variantOf ? { variantOf: row.variantOf } : {}),
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
  variants: defaultVariantStore(),
  async record(entry) { const { recordStandaloneFix } = await import("./burndown.js"); recordStandaloneFix(entry.repo, entry.fingerprint, entry.outcome); },
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
export interface SandboxNotes { /** A setup step ran first with the network on. */ setup: boolean; pinned: boolean }
export function sandboxVerifiedLine(checks: CheckResult[], notes?: SandboxNotes): string | undefined {
  if (!checks.length || checks.some(check => check.code !== 0 || !check.sandbox)) return undefined;
  const labels = [...new Set(checks.map(check => check.sandbox!))];
  if (labels.length !== 1) return undefined;
  const setup = notes?.setup ? " Dependencies were downloaded first in a separate setup step with the network on; the checks ran with the network off, and a canary confirmed it." : "";
  const pinned = notes ? (notes.pinned ? " The image is pinned by digest." : " The image is not pinned by digest, so the tag can change.") : "";
  return `Verified in a sandbox: ${cell(labels[0]!)}.${setup}${pinned}`;
}

export function pullRequestBody(finding: FindingToFix, summary: string | undefined, checks: CheckResult[], footer?: string, draftUnchecked = false, layout?: { template: string; ticket?: string }, direct = false, sandboxNotes?: SandboxNotes): string {
  const where = finding.path ? `\`${finding.path.replace(/`/g, "'")}${finding.startLine ? `:${finding.startLine}` : ""}\`` : "not given";
  const rows = checks.length ? checks.map(check => `| \`${escapeHtml(check.command.replace(/`/g, "'").replace(/\s+/g, " ")).replace(/\|/g, "\\|")}\` | ${check.code === 0 ? "passed" : `failed (exit ${check.code})`} |`).join("\n") : "| none were run | |";
  const failed = checks.filter(check => check.code !== 0);
  const tails = failed.map(check => `<details><summary>${inert(escapeHtml(check.command.replace(/\s+/g, " ")))}</summary>\n\n\`\`\`\n${check.output.slice(-2000).replace(/```/g, "'''")}\n\`\`\`\n</details>`).join("\n");
  const modelText = withoutCheckHeadings((summary ?? "").slice(0, 5000));
  const blocks = {
    finding: `Fixes finding ${shortFindingId(finding.id)}: ${inert(finding.title)}`,
    details: `| Severity | Category | Reported by | Where |\n| --- | --- | --- | --- |\n| ${cell(finding.severity)} | ${cell(finding.category)} | ${cell(finding.tool ?? "0")} | ${where} |`,
    checks: [
      "### Checks",
      `| Command | Result |\n| --- | --- |\n${rows}`,
      ...(sandboxVerifiedLine(checks, sandboxNotes) ? ["", sandboxVerifiedLine(checks, sandboxNotes)!] : checks.some(check => check.sandbox) ? ["", "Not verified in a sandbox: a sandboxed check failed."] : checks.length ? ["", "These checks ran on the machine that ran 0, not in a sandbox."] : []),
      ...(tails ? ["", tails] : []),
    ].join("\n"),
    summary: [
      "### What changed",
      direct ? "Written by 0 from the edit it made. The Checks section is what 0 ran." : layout ? "Summary written by the model (not verified). The Checks section is what 0 ran." : "Summary written by the model (not verified). The Checks table above is what 0 ran.",
      "",
      inert(modelText || "The change is in the diff."),
      "",
      ...(!checks.length ? ["No checks were run."] : []),
      failed.length ? "Opened as a draft because a check failed. Review it before it is marked ready." : draftUnchecked ? "Opened as a draft because no check ran. Review it before it is marked ready." : "A person should review this before merging; 0 does not merge.",
    ].join("\n"),
  };
  const text = layout
    ? renderBodyTemplate(layout.template, { id: finding.id, title: finding.title, severity: finding.severity, category: finding.category, ...(finding.path ? { path: finding.path } : {}), ...(layout.ticket ? { ticket: layout.ticket } : {}) }, blocks)
    : [blocks.finding, "", blocks.details, "", blocks.checks, "", blocks.summary].join("\n");
  return [text, ...(footer ? ["", footer] : [])].join("\n");
}

export interface FixOptions extends ConsoleTransportOptions {
  host?: string; bitbucketUrl?: string;
  repo?: string; base?: string; test?: string[]; ready?: boolean; budget: string; model?: string; timeout: string; pr: boolean; format?: string; policy?: string; policyBundle?: string; policyBundleKey?: string[]; policyBundleKeyFile?: string[]; repoPolicy?: boolean; sandbox?: string; sandboxImage?: string; sandboxNetwork?: boolean; variants?: boolean; variantBudget?: string; sandboxSetup?: string[]; sandboxProfile?: string; sandboxMavenSettings?: string; ticket?: string;
}

export interface FixOutcome {
  finding: string; branch: string; changed: boolean; committed: boolean; checks: CheckResult[]; verified: boolean;
  /** The variant hunt that followed the fix: sites recorded, and the earlier variants checked again in the fixed tree. */
  variants?: { created: number; rescanned: { fixed: number; open: number; unchecked: number }; error?: string };
  pullRequest?: { url: string; created: boolean; draft: boolean }; threadId?: string; costUsd?: number; tokens?: number; budgetExhausted?: boolean; timedOut?: boolean; summary?: string;
  /** Written when a Java dependency finding could not be fixed: what is vulnerable, where it is declared, why nothing changed and what to do. */
  advisory?: string;
}

/** The metrics record of one fix run; `outcome` is undefined when the run failed before it had one. */
export function fixMetric(outcome: FixOutcome | undefined, options: Pick<FixOptions, "model" | "budget">, startedAt: number, endedAt: number): Omit<RunMetric, "version" | "ci"> {
  const status = !outcome ? "failed" : outcome.timedOut ? "timeout" : outcome.budgetExhausted ? "budget" : outcome.committed ? "ok" : "failed";
  return {
    ...(metricPullRequest(outcome?.pullRequest?.url) ?? {}),
    at: new Date(startedAt).toISOString(), command: "fix", model: scanModelLabel(options), budgetUsd: Number(options.budget), costUsd: outcome?.costUsd ?? null,
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
  try { options = applySandboxProfile(options); } catch (error) { throw new UsageError((error as Error).message); }
  if (options.sandboxMavenSettings && !options.sandboxSetup?.length) throw new UsageError("--sandbox-maven-settings requires an online --sandbox-setup or --sandbox-profile java.");
  if (!options.sandbox) {
    if (options.sandboxImage || options.sandboxNetwork || options.sandboxSetup?.length) throw new UsageError("--sandbox-image, --sandbox-network and --sandbox-setup need --sandbox docker.");
    return undefined;
  }
  if (options.sandbox !== "docker") throw new UsageError("--sandbox must be docker.");
  if (!options.sandboxImage) throw new UsageError("--sandbox docker needs --sandbox-image, for example maven:3-eclipse-temurin-21.");
  if (!options.test?.length) throw new UsageError("--sandbox runs your --test commands in the container; give at least one --test.");
  let image: string;
  try { image = validateSandboxImage(options.sandboxImage); } catch (error) { throw new UsageError(error instanceof Error ? error.message : String(error)); }
  if (options.sandboxNetwork && options.sandboxSetup?.length) throw new UsageError("--sandbox-setup downloads with the network on and then runs the checks with it off; do not combine it with --sandbox-network.");
  if (options.sandboxNetwork) assertEgressAllowed("the network from the fix sandbox (--sandbox-network)", env);
  if (options.sandboxSetup?.length) assertEgressAllowed("the network from the fix sandbox setup step (--sandbox-setup)", env);
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
  let cache: string | undefined;
  let fixClient: ConsoleClient | undefined;
  try {
    try { options = applySandboxProfile(options); } catch (error) { throw new UsageError((error as Error).message); }
    const budget = Number(options.budget);
    if (!Number.isFinite(budget) || budget <= 0) throw new UsageError("--budget must be a positive number of USD.");
    if (!Number.isFinite(Number(options.timeout)) || Number(options.timeout) <= 0) throw new UsageError("--timeout must be a positive number of seconds.");
    const variantCap = Number(options.variantBudget ?? DEFAULT_VARIANT_BUDGET_USD);
    if (!Number.isFinite(variantCap) || variantCap <= 0) throw new UsageError("--variant-budget must be a positive number of USD.");
    const sandbox = sandboxSpec({ ...options, sandboxProfile: undefined });
    if (options.computer || options.engineUrl) throw new UsageError("0security fix edits files on this machine; run it against the local console.");
    const finding = deps.loadFinding(id, options.dbPath);
    const remember = async (outcome: FixOutcome): Promise<void> => {
      try { await deps.record?.({ repo, fingerprint: finding.fingerprint, outcome }); } catch (error) { deps.err(`warning: could not record this fix for export-fixes (${error instanceof Error ? error.message.split("\n")[0]!.slice(0, 120) : "unknown error"})`); }
    };
    try { repo = (await deps.git(resolve(options.repo ?? process.cwd()), ["rev-parse", "--show-toplevel"])).trim(); }
    catch { throw new UsageError("Run this inside the git repository the finding is in, or pass --repo."); }
    if (options.sandboxMavenSettings) validateMavenSettingsFile(options.sandboxMavenSettings, repo);
    // Resolve the target and require credentials before starting work or pushing a fix.
    const host = options.pr ? await selectFixHost({ host: options.host, bitbucketUrl: options.bitbucketUrl, run: (args, input) => deps.gh(tree || repo, args, input), git: args => deps.git(tree || repo, args) }) : undefined;
    const base = await defaultBase(deps, repo, options.base);
    // The policy is read before anything is created: a bad pull request setting stops the run first.
    if (options.policyBundle && options.policy) throw new UsageError("Pass either --policy or --policy-bundle, not both.");
    const bundle = await loadPolicyBundle(options);
    const loaded: LoadedFixPolicy | undefined = bundle
      ? { ...parseFixPolicyDocument(bundle.policyText, "the policy bundle"), source: `signed policy bundle ${bundle.source} (version ${bundle.version})`, fromRepo: false }
      : deps.loadPolicy(repo, options);
    const conventions: PullRequestConventions | undefined = loaded && !loaded.fromRepo ? loaded.conventions : undefined;
    const ticket = parseTicket(options.ticket);
    if (needsTicket(conventions) && !ticket) throw new UsageError("The pull request settings in your policy use {ticket}. Pass --ticket with a key such as SEC-123.");
    const prefix = resolveBranchPrefix(conventions?.branchPrefix ?? BRANCH_PREFIX, ticket);
    const named = { ...finding, ...(ticket ? { ticket } : {}) };
    const branch = fixBranchName(finding.fingerprint, prefix);
    if (branch === base.name || !branch.startsWith(prefix)) throw new Error("Refusing to work on the base branch.");

    temp = deps.makeTemp();
    tree = join(temp, "tree");
    const branchExisted = await deps.git(repo, ["rev-parse", "--verify", "--quiet", `refs/heads/${branch}`]).then(() => true, () => false);
    await deps.git(repo, ["worktree", "add", "--quiet", "-B", branch, tree, base.ref]);
    madeBranch = { repo, branch, existed: branchExisted };
    deps.err(`fixing ${finding.title} on branch ${branch} (isolated work tree, base ${base.name})`);

    const policy = loaded?.policy;
    if (loaded) {
      const libs = loaded.policy.approvedLibraries?.length ?? 0;
      const rules = loaded.policy.rules?.length ?? 0;
      deps.err(`applying fix policy from ${loaded.source} (${libs} approved ${libs === 1 ? "library" : "libraries"}, ${rules} ${rules === 1 ? "rule" : "rules"})`);
      if (loaded.fromRepo) deps.err("warning: this policy comes from the repository being fixed, which is untrusted; it is guidance for the model, not a safety control, and its pull request settings are ignored");
      if (conventions) deps.err("applying pull request conventions from the policy");
    }
    const outcomeBase = { finding: finding.id, branch };
    // A Maven or Gradle dependency finding with a fixed version is a version edit: make it directly, with no model call, and
    // leave the cases it cannot decide (a parent or BOM outside the repository, a variable, a range) to the model.
    const direct = directJavaBump(tree, finding);
    let thread: ThreadOutcome;
    if (direct.applied) {
      deps.err(direct.log);
      thread = { costUsd: 0, tokens: 0, reply: direct.summary, failed: false, timedOut: false, budgetExhausted: false };
    } else {
      if (direct.reason) deps.err(`not changed directly (${direct.reason}); asking the model`);
      const { client, stop } = await connect(options, deps);
      stopConsole = stop;
      fixClient = client;
      thread = await runThread(client, deps, tree, finding, options, budget, policy, Boolean(sandbox));
    }
    const status = (await deps.git(tree, ["status", "--porcelain", "--untracked-files=all"])).trim();
    const common = { ...outcomeBase, ...(thread.id ? { threadId: thread.id } : {}), ...(thread.costUsd !== undefined ? { costUsd: thread.costUsd } : {}), ...(thread.tokens !== undefined ? { tokens: thread.tokens } : {}), ...(thread.budgetExhausted ? { budgetExhausted: true } : {}), ...(thread.timedOut ? { timedOut: true } : {}), ...(thread.reply ? { summary: thread.reply } : {}) };
    if (!status) {
      deps.err(thread.error ?? "The thread made no change; no pull request was opened.");
      const advisory = thread.failed || thread.timedOut || thread.budgetExhausted || !isJavaDependencyFinding(finding) ? undefined : javaAdvisoryNote(finding, direct.applied ? "" : direct.reason);
      const unchanged: FixOutcome = { ...common, changed: false, committed: false, checks: [], verified: false, ...(advisory ? { advisory } : {}) };
      await remember(unchanged);
      return unchanged;
    }

    const checks: CheckResult[] = [];
    let sandboxNotes: SandboxNotes | undefined;
    if (sandbox && options.sandboxSetup?.length) {
      // Setup downloads dependencies into a cache folder with the network on. The checks then reuse that cache with the network off.
      cache = makeSandboxCache();
      const online = { ...sandbox, network: true, cache, ...(options.sandboxMavenSettings ? { mavenSettingsFile: options.sandboxMavenSettings } : {}) };
      const offline = { ...sandbox, network: false, cache };
      sandboxNotes = { setup: true, pinned: isPinnedImage(sandbox.image) };
      let ready = true;
      for (const command of options.sandboxSetup) {
        deps.err(`setup in a sandbox (${sandboxLabel(online)}): ${command}`);
        const result = await deps.check(tree, command, online);
        if (result.code !== 0) { checks.push({ ...result, command: `setup: ${command}` }); ready = false; break; }
      }
      if (ready) {
        deps.err("checking that the sandbox has no network");
        const canary = await deps.check(tree, NETWORK_CANARY, offline);
        checks.push({ ...canary, command: "network-off canary" });
        ready = canary.code === 0;
      }
      if (ready) for (const command of options.test ?? []) { deps.err(`running in a sandbox (${sandboxLabel(offline)}): ${command}`); checks.push(await deps.check(tree, command, offline)); }
    } else {
      if (sandbox) sandboxNotes = { setup: false, pinned: isPinnedImage(sandbox.image) };
      for (const command of options.test ?? []) { deps.err(`running${sandbox ? ` in a sandbox (${sandboxLabel(sandbox)})` : ""}: ${command}`); checks.push(await deps.check(tree, command, sandbox)); }
    }
    const verified = checks.every(check => check.code === 0) && !thread.failed;

    await deps.git(tree, ["add", "-A"]);
    // A clean machine or an Actions runner has no git identity; use a neutral one rather than fail the commit.
    const configured = (await deps.git(tree, ["config", "user.email"]).catch(() => "")).trim();
    const identity = configured ? [] : ["-c", "user.name=0", "-c", "user.email=noreply@0.security"];
    await deps.git(tree, [...identity, "commit", "--quiet", "-m", `${commitSubject(named, conventions)}\n\nFinding ${finding.id}`]);
    committedBranch = true;
    const outcome: FixOutcome = { ...common, changed: true, committed: true, checks, verified };
    // The fix is the other trigger for a variant hunt: the tree now holds the fix, so a site that still has the bug stands out.
    const followUp = async (done: FixOutcome): Promise<FixOutcome> => {
      if (!deps.variants || options.variants === false || !finding.dbPath || !finding.scanId || finding.variantOf) return done;
      const parent: VariantParent = {
        id: finding.id, dbPath: finding.dbPath, scanId: finding.scanId, title: finding.title, category: finding.category, severity: finding.severity, description: finding.description,
        ...(finding.path ? { path: finding.path } : {}), ...(finding.startLine ? { startLine: finding.startLine } : {}), ...(finding.endLine ? { endLine: finding.endLine } : {}), ...(finding.rootCause ? { rootCause: finding.rootCause } : {}),
      };
      const gate = new VariantBudget(budget);
      gate.record(done.costUsd);
      let totalTokens = done.tokens ?? 0;
      let tokensKnown = done.tokens !== undefined;
      const recordChild = (child: { costUsd?: number; tokens?: number }) => {
        gate.record(child.costUsd);
        if (child.tokens === undefined) tokensKnown = false;
        else totalTokens += child.tokens;
      };
      const run = () => ({ timeout: options.timeout, budget: String(gate.allowance(variantCap)), ...(options.model ? { model: options.model } : {}) });
      const result = (details: NonNullable<FixOutcome["variants"]>): FixOutcome => {
        const { costUsd: _cost, tokens: _tokens, ...rest } = done;
        return { ...rest, ...(tokensKnown ? { tokens: totalTokens } : {}), ...(gate.known ? { costUsd: gate.spent } : {}), variants: details };
      };
      const empty = { created: 0, rescanned: { fixed: 0, open: 0, unchecked: 0 } };
      if (gate.allowance(variantCap) <= 0) {
        deps.err(`variants skipped: ${gate.stoppedReason}`);
        return result({ ...empty, error: gate.stoppedReason });
      }
      try {
        if (!fixClient) { const connection = await connect(options, deps); fixClient = connection.client; stopConsole ??= connection.stop; }
        const store = { store: deps.variants, err: deps.err, sleep: deps.sleep };
        const folder = tree;
        const rescanned = await rescanVariants(fixClient, store, folder, parent, run());
        // No pending sites means no rescan thread and no spend.
        if (rescanned.threadId || rescanned.error) recordChild(rescanned);
        if (gate.allowance(variantCap) <= 0) {
          deps.err(`variant hunt skipped: ${gate.stoppedReason}`);
          return result({ created: 0, rescanned: rescanSummary(rescanned), error: gate.stoppedReason });
        }
        const commit = (await deps.git(tree, ["rev-parse", "HEAD"]).catch(() => "")).trim();
        const hunt = await huntVariants(fixClient, store, folder, parent, run(), commit ? { fixCommit: commit } : {});
        recordChild(hunt);
        const error = (!gate.known ? gate.stoppedReason : undefined) ?? hunt.error ?? rescanned.error;
        deps.err(`variants: ${hunt.created.length} recorded, ${rescanned.items.length} checked again${error ? ` (${error})` : ""}`);
        return result({ created: hunt.created.length, rescanned: rescanSummary(rescanned), ...(error ? { error } : {}) });
      } catch (error) {
        const message = error instanceof Error ? error.message.split("\n")[0]! : String(error);
        deps.err(`warning: the variant hunt did not run (${message})`);
        gate.record(undefined);
        tokensKnown = false;
        return result({ ...empty, error: message });
      }
    };
    if (!options.pr) { deps.err(`committed on ${branch}; not pushed (--no-pr).`); const done = await followUp(outcome); await remember(done); return done; }

    // The branch is ours and only ours: never the base, always with a lease so a person's later push is not overwritten.
    if (!host) throw new Error("No pull request host was selected.");
    // Check API access and locate the existing PR before writing to the git remote.
    const existing = await host.findOpenPullRequest(branch, base.name);
    await host.pushBranch(branch);
    const bodyFile = join(temp, "body.md");
    const draft = isDraft(verified, conventions, !checks.length && !options.ready);
    deps.writeFile(bodyFile, pullRequestBody(finding, thread.reply, checks, footerText(conventions), draft && verified && !checks.length, conventions?.bodyTemplate ? { template: conventions.bodyTemplate, ...(ticket ? { ticket } : {}) } : undefined, direct.applied, sandboxNotes));
    let url: string; let created = false;
    if (existing) {
      url = existing.url;
      await host.updatePullRequestBody(existing.number, bodyFile);
      if (existing.isDraft && !draft) await host.setPullRequestReady(existing.number, true);
      if (!existing.isDraft && draft) await host.setPullRequestReady(existing.number, false);
    } else {
      created = true;
      url = await host.createPullRequest({ base: base.name, head: branch, title: pullRequestTitle(named, conventions), bodyFile, draft });
    }
    if (conventions) {
      const reviewers = await chooseReviewers(deps, repo, base.ref, conventions, finding.path);
      if (conventions.labels?.length || reviewers.length) await decoratePullRequest(host, url, { ...conventions, reviewers }, deps.err);
    }
    const opened: FixOutcome = await followUp({ ...outcome, pullRequest: { url, created, draft } });
    await remember(opened);
    return opened;
  } finally {
    stopConsole?.();
    if (tree && repo) await deps.git(repo, ["worktree", "remove", "--force", tree]).catch(() => undefined);
    // A branch this run made and never committed to is only clutter.
    if (madeBranch && !madeBranch.existed && !committedBranch) await deps.git(madeBranch.repo, ["branch", "-D", madeBranch.branch]).catch(() => undefined);
    if (temp) deps.removeTemp(temp);
    if (cache) rmSync(cache, { recursive: true, force: true });
  }
}

/** The reviewers named in the policy plus, when it asks, the CODEOWNERS owners of the file. The file is read from the base branch as committed. */
async function chooseReviewers(deps: FixDeps, repo: string, baseRef: string, conventions: PullRequestConventions, path: string | undefined): Promise<string[]> {
  const named = conventions.reviewers ?? [];
  if (!conventions.reviewersFromCodeowners || !path) return named;
  for (const file of CODEOWNERS_PATHS) {
    const text = await deps.git(repo, ["show", `${baseRef}:${file}`]).catch(() => undefined);
    if (text === undefined) continue;
    const owners = reviewersFromCodeowners(text, path);
    if (!owners.length) deps.err(`no CODEOWNERS entry covers ${path.slice(0, 80)}; no reviewer was added from it`);
    return [...new Set([...named, ...owners])].slice(0, MAX_REVIEWERS);
  }
  deps.err("reviewersFromCodeowners is on but the base branch has no CODEOWNERS file");
  return named;
}

/** Labels that exist (or can be made) and reviewers go on the pull request. A refusal is a warning: the pull request is already open. */
async function decoratePullRequest(host: Host, url: string, conventions: PullRequestConventions, warn: (text: string) => void): Promise<void> {
  const number = Number(/\/(?:pull|pull-requests)\/(\d+)$/.exec(url)?.[1]);
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

/** A dependency finding that points at a Maven or Gradle build file. */
export function isJavaDependencyFinding(finding: Pick<FindingToFix, "title" | "description" | "path">): boolean {
  return /(?:^|\/)(?:pom\.xml|build\.gradle(?:\.kts)?|libs\.versions\.toml)$/.test(finding.path ?? "") && (parseDependencyFinding(`${finding.title}\n${finding.description}`) !== undefined || dependencyHead(`${finding.title}\n${finding.description}`) !== undefined);
}

/** The package, version and advisory id a dependency finding names, with or without a fixed version. */
function dependencyHead(text: string): { name: string; currentVersion: string; advisory: string } | undefined {
  const head = /(?:^|\s)([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)\s+([0-9][0-9A-Za-z._+-]*)\s+has\s+((?:GHSA|CVE|OSV|PYSEC|GO|RUSTSEC)-[A-Za-z0-9-]+)/.exec(text);
  return head ? { name: head[1]!, currentVersion: head[2]!, advisory: head[3]! } : undefined;
}

/**
 * The advisory written when a Java dependency finding gets no change: it names the dependency, where it is declared, why
 * 0 did not change it and what a person can do. Plain text from structured fields only; no finding prose is copied, so
 * nothing from the repository ends up in a mention, link or markup.
 */
export function javaAdvisoryNote(finding: Pick<FindingToFix, "title" | "description" | "path">, reason: string): string | undefined {
  const text = `${finding.title}\n${finding.description}`;
  const head = dependencyHead(text);
  if (!head) return undefined;
  const fixed = parseDependencyFinding(text)?.fixedVersion;
  const clean = (value: string): string => value.replace(/[^\x20-\x7e]/g, " ").replace(/\s+/g, " ").trim().slice(0, 300);
  return [
    `Advisory (no pull request was opened): ${head.name} ${head.currentVersion} is affected by ${head.advisory}.`,
    `Declared in: ${clean(finding.path ?? "unknown")}`,
    fixed ? `Lowest fixed version from the advisory: ${fixed}` : "Fixed version: the advisory names none, so 0 did not pick one.",
    reason ? `Why nothing changed: ${clean(reason)}` : "Why nothing changed: the fix attempt produced no edit.",
    fixed
      ? `What to do: raise ${head.name} to ${fixed} or newer where your build sets it (a parent POM, a BOM or a version catalog outside this repository may own it), then run your tests.`
      : `What to do: check the advisory for a mitigation or a replacement library, exclude or remove the dependency if the affected code is unused, and watch for a fixed release.`,
  ].join("\n");
}

type ThreadOutcome = { id?: string; reply?: string; error?: string; failed: boolean; tokens?: number; timedOut: boolean; budgetExhausted: boolean; costUsd?: number };

/** Edit the version of a Maven or Gradle dependency named by a dependency finding. `reason` is empty when the finding is not one. */
export function directJavaBump(tree: string, finding: Pick<FindingToFix, "title" | "description">): { applied: true; log: string; summary: string } | { applied: false; reason: string } {
  const parsed = parseDependencyFinding(`${finding.title}\n${finding.description}`);
  if (!parsed) return { applied: false, reason: "" };
  const result = bumpJavaDependency(tree, { name: parsed.name, fixedVersion: parsed.fixedVersion, currentVersion: parsed.currentVersion });
  if (!result.applied) return { applied: false, reason: result.reason };
  const lines = result.edits.map(edit => `${edit.path}:${edit.line} ${edit.where}: ${edit.was} to ${edit.now}`);
  return { applied: true, log: `changed ${parsed.name} to ${parsed.fixedVersion} directly (no model call): ${lines.join("; ")}`, summary: `0 changed the version of ${parsed.name} from ${parsed.currentVersion} to the lowest fixed version, ${parsed.fixedVersion}, where the repository sets it. The version edit used no model.\n\n${lines.map(line => `- ${line}`).join("\n")}` };
}

async function runThread(client: ConsoleClient, deps: FixDeps, folder: string, finding: FindingToFix, options: FixOptions, budget: number, policy?: FixPolicy, sandboxed = false) {
  const created = asJson(asJson(await client.request("POST", "/api/console/sessions", { runtime: { ...scanModelField(options) }, title: `Fix: ${finding.title}`.slice(0, 120), costCeilingUsd: budget })).session);
  const id = String(created.id);
  const path = `/api/console/sessions/${encodeURIComponent(id)}`;
  await client.request("PATCH", `${path}/configuration`, { workspacePath: folder });
  await client.request("POST", `${path}/messages`, { text: fixPrompt(finding, { tests: options.test ?? [], policy, sandboxed, ...(isJavaDependencyFinding(finding) ? { skill: "java-dependency-fix" } : options.sandboxProfile === "java" ? { skill: "java-security-fix" } : {}) }) });
  deps.err(`working in thread ${id} (budget $${Number(budget.toFixed(4))})`);
  const { snapshot, timedOut } = await waitForThread(client, deps, id, Date.now() + Number(options.timeout) * 1000);
  const done = finishedThread(snapshot);
  const costUsd = done.usage.costUnavailable !== true && typeof done.usage.costUsd === "number" && Number.isFinite(done.usage.costUsd) && done.usage.costUsd >= 0 ? done.usage.costUsd : undefined;
  const tokens = typeof done.usage.inputTokens === "number" && typeof done.usage.outputTokens === "number" ? done.usage.inputTokens + done.usage.outputTokens : undefined;
  return { id, reply: done.reply, error: done.error, failed: done.failed && !timedOut, ...(tokens !== undefined ? { tokens } : {}), timedOut, budgetExhausted: asJson(done.session).costCeilingExceeded === true, usage: usageLine(done.usage), ...(costUsd !== undefined ? { costUsd } : {}) };
}

/** One report per failed check: exit code, command and the last 15 lines. Check output comes from the sandboxed build, so terminal control characters (escape sequences) are dropped. */
export function failedCheckReports(checks: CheckResult[]): string[] {
  const plain = (text: string): string => text.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, "");
  return checks.filter((c) => c.code !== 0).map((c) => `check failed (exit ${c.code}): ${plain(c.command).replace(/\n/g, " ")}\n${plain(c.output.trim()).split("\n").slice(-15).map((line) => `  | ${line}`).join("\n")}`);
}

export function registerFixCommand(program: Command, deps: FixDeps = defaults): void {
  const collect = (value: string, previous: string[] = []) => [...previous, value];
  consoleTransportOptions(program.command("fix <finding>")
    .description("Fix one finding in an isolated git work tree and open a pull request for review")
    .option("--host <host>", "Code host: github, bitbucket-cloud or bitbucket-dc (inferred from origin)")
    .option("--bitbucket-url <url>", "Bitbucket Data Center HTTPS base URL, including any context path (or BITBUCKET_URL)")
    .option("--repo <dir>", "Git repository the finding is in (default: the current directory)")
    .option("--base <branch>", "Branch to start from and open the pull request against (default: the remote's default branch)")
    .option("--test <command>", "Check to run after the change; repeat for several. A failing check makes the pull request a draft", collect)
    .option("--ready", "Open the pull request ready for review even when no --test ran. Without it, a pull request with no checks is a draft")
    .addOption(new Option("--sandbox <mode>", "Run the --test commands in a container instead of on this machine (docker)").choices(["docker"]))
    .option("--sandbox-profile <profile>", "Use the pinned Maven/JDK 21 verifier: online dependency setup then offline verify (java)")
    .option("--sandbox-maven-settings <file>", "Owner-only short-lived Maven credentials outside the repository; read-only mount for online setup only; setup output withheld")
    .option("--sandbox-image <image>", "Image for --sandbox docker, for example maven:3-eclipse-temurin-21. It must hold the tools and dependencies the tests need")
    .option("--sandbox-network", "Give the sandbox network access (to download dependencies). Off by default")
    .option("--sandbox-setup <command>", "With --sandbox docker: run this once with the network on to download dependencies (for example mvn -q test), then run the --test checks with the network off; repeat for several", collect)
    .option("--policy <file>", "Policy file (.json or .yaml) of approved libraries and fix rules; any path you name, relative to the current directory. Default: ~/.0/fix-policy.json|yaml|yml")
    .option("--policy-bundle <file|https-url>", "Signed policy bundle to use instead of --policy; refused unless its Ed25519 signature matches a --policy-bundle-key or --policy-bundle-key-file and its version is newer than the last one accepted")
    .option("--policy-bundle-key <key>", "Ed25519 public key as inline text (PEM, base64 or hex; never a path) allowed to sign policy bundles; repeat for several. Also ZERO_POLICY_BUNDLE_KEY", collect)
    .option("--policy-bundle-key-file <path>", "File holding an Ed25519 public key allowed to sign policy bundles: an absolute path, not a symlink, outside the working tree being scanned; repeat for several. Also ZERO_POLICY_BUNDLE_KEY_FILE", collect)
    .option("--ticket <key>", "Ticket key such as SEC-123 for the {ticket} placeholder in your policy's pull request settings")
    .option("--repo-policy", "Also read fix-policy.* or .zero/fix-policy.* from the repository being fixed (untrusted content; off by default)")
    .option("--no-variants", "Do not rescan the recorded variants or hunt for the same bug at other sites after the fix")
    .option("--variant-budget <usd>", "Spend cap for each variant thread, in USD", String(DEFAULT_VARIANT_BUDGET_USD))
    .option("--no-pr", "Commit on the fix branch but do not push or open a pull request")
    .option("--budget <usd>", "Stop when the estimated spend reaches this many USD", String(DEFAULT_BUDGET_USD))
    .option("--model <model>", `Model for the fix thread (default: ${DEFAULT_SCAN_MODEL}; ZERO_MODEL or a pinned provider's default when set)`)
    .option("--timeout <seconds>", "Maximum seconds to wait for the fix", String(DEFAULT_TIMEOUT_SECONDS))
    .addOption(new Option("--format <format>", "Output: text or json").choices(["text", "json"]))
    )
    .addHelpText("after", "\nNothing is pushed to the base branch and nothing is merged: the change goes to a branch named 0/fix-<id>, and running it again updates the same pull request.\nWithout --sandbox, --test commands run on this machine with your privileges. With --sandbox docker they run in a container with no network, limited memory, CPU and processes, a copy of the work tree and none of your environment variables; the pull request says so only when every check passed there.\nA pull request is a draft when a check failed or when no --test ran; --ready opens it ready in the second case.\nExit codes: 0 a change was committed and no --test check failed (with no --test, 0 does not mean the change was checked; see the draft rule above), 1 no change, a failed check or a failed thread, 2 usage error, 3 stopped at the budget or time limit.")
    .action(async (finding: string, options: FixOptions, command: Command) => {
      try {
        const outcome = await runFix(finding, applyWorkflowDefaults("fix", options, command), deps);
        if (!outcome) return;
        if (options.format !== "json") for (const text of failedCheckReports(outcome.checks)) deps.err(text);
        if (options.format === "json") deps.out(JSON.stringify(outcome, null, 2));
        else if (outcome.pullRequest) deps.out(`${outcome.pullRequest.created ? "Opened" : "Updated"} ${outcome.pullRequest.draft ? "draft " : ""}pull request: ${outcome.pullRequest.url}`);
        else if (outcome.committed) deps.out(`Committed on ${outcome.branch}.`);
        else deps.out(outcome.advisory ? `No change was made.\n\n${outcome.advisory}` : "No change was made.");
        process.exitCode = outcome.budgetExhausted || outcome.timedOut ? 3 : outcome.changed && outcome.verified ? 0 : 1;
      } catch (error) { finishWithError(error, { err: deps.err }, options.format === "json"); }
    });
}
