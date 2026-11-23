/**
 * `0 findings issues`: mirror findings into an issue tracker (GitHub Issues), one issue per finding family, so the
 * team triages them where it already works. Running it again never duplicates: each issue carries a hidden marker with
 * the family key, and the issue is created, updated, closed or reopened to match the finding.
 *
 * The issue text is built only from share-safe fields (title, severity, category, location, the attacker-impact
 * sentence, status). Evidence, requests, responses and proof-of-concept bodies can quote code or secrets, so they are
 * never sent. All report text is neutralised so it cannot mention people, reference other issues or inject markup.
 */
import { createHash } from "node:crypto";
import type { Command } from "commander";
import { attackerImpactSentence, effectiveTriageStatus } from "@0/engine/shared";
import { FindingsService, listOsecRunDatabasePaths, resolveOsecDbPath } from "@0/engine/storage";
import { shortFindingId } from "../finding-id.js";
import { finishWithError, UsageError } from "./output.js";
import { GitHubIssueTracker } from "../host/github.js";
import { selectHost, type IssueDraft, type IssueTracker, type TrackerIssue } from "../host/index.js";
import { runGh } from "../host/gh.js";

export { GitHubIssueTracker };
export type { IssueDraft, IssueTracker, TrackerIssue };

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
type Severity = typeof SEVERITIES[number];
const SAFE_KEY = /^[A-Za-z0-9:_.-]{1,80}$/;
const CLOSING_TRIAGE = new Set(["accepted", "suppressed"]);
const CLOSING_STATUS = new Set(["fixed", "false-positive"]);

/** A finding reduced to what may leave this machine. */
export interface TrackedFinding {
  key: string;
  /** Local finding id, shown as a hint for looking the finding up. */
  id: string;
  title: string;
  severity: string;
  category: string;
  path?: string;
  startLine?: number;
  impact?: string;
  /** Why the finding no longer needs work; absent while it is open. */
  closedBecause?: "suppressed" | "accepted" | "fixed" | "false-positive";
  /** The suppression was recorded as a false positive (its triage note says so). */
  falsePositive?: boolean;
  /** The declared scope (`0 scan --scope`) names this finding's vector out of scope. */
  scope?: "in-scope" | "out-of-scope";
}

/** The key for the marker: the fingerprint itself when it is plainly safe, otherwise a hash of it. */
export function findingKey(fingerprint: string): string {
  return SAFE_KEY.test(fingerprint) ? fingerprint : `h:${createHash("sha256").update(fingerprint).digest("hex").slice(0, 32)}`;
}

/** Report text goes into a tracker people read: no mentions, cross references, markup, links or line breaks. */
export function neutralise(text: string, max = 300): string {
  return text.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim().slice(0, max)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/([\\`*_[\]()~|!])/g, "\\$1")
    .replace(/@/g, "@​").replace(/#(?=\d)/g, "#​").replace(/\bGH-(?=\d)/gi, "GH​-")
    .replace(/:\/\//g, ":​//").replace(/\bwww\./gi, "www​.");
}

/** Plain text for places that do not render markdown (issue titles): defused like `neutralise`, but nothing is escaped. */
export function neutralisePlain(text: string, max = 300): string {
  return text.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/[<>]/g, "").replace(/\s+/g, " ").trim().slice(0, max).trim()
    .replace(/@/g, "@\u200b").replace(/#(?=\d)/g, "#\u200b").replace(/\bGH-(?=\d)/gi, "GH\u200b-")
    .replace(/:\/\//g, ":\u200b//").replace(/\bwww\./gi, "www\u200b.");
}

/** A repository-relative path as plain characters, or undefined for anything that names the local machine. */
function safePath(path: string | undefined): string | undefined {
  if (!path || path.startsWith("/") || path.startsWith("~") || /^[A-Za-z]:[\\/]/.test(path) || path.startsWith("\\\\") || path.split(/[\\/]/).includes("..")) return undefined;
  return path.replace(/[^A-Za-z0-9._\-/+]/g, "_").slice(0, 300);
}

const normalSeverity = (severity: string): Severity => (SEVERITIES.includes(severity as Severity) ? severity as Severity : "info");
export function labelsFor(severity: string): string[] { return ["security", `severity:${normalSeverity(severity)}`]; }

export function buildIssue(finding: TrackedFinding): IssueDraft {
  const severity = normalSeverity(finding.severity);
  const path = safePath(finding.path);
  const where = path ? `\`${path}${finding.startLine ? `:${Math.trunc(finding.startLine)}` : ""}\`` : "not given";
  const status = finding.closedBecause ? `closed (${finding.closedBecause})` : "open";
  const body = [
    `<!-- 0-finding:${finding.key} -->`,
    `| Severity | Category | Where | Status |\n| --- | --- | --- | --- |\n| ${severity} | ${neutralise(finding.category, 60)} | ${where} | ${status} |`,
    ...(finding.impact ? ["", `**${finding.category === "policy-violation" ? "What the violation exposes" : "What an attacker gets"}:** ${neutralise(finding.impact, 700)}`] : []),
    "",
    `Mirrored by \`0 findings issues\`. Evidence and proof-of-concept details are not copied here; on the machine that ran the scan, open them with \`0 findings show ${shortFindingId(finding.id).replace(/[^A-Za-z0-9-]/g, "")}\`.`,
    "This issue is kept in sync automatically: edits to the title and body are overwritten, and it closes when the finding is fixed, accepted or suppressed.",
  ].join("\n");
  return { title: `[${severity}] ${neutralisePlain(finding.title, 160)}`, body, labels: labelsFor(severity) };
}

export type IssueAction =
  | { kind: "create"; finding: TrackedFinding; draft: IssueDraft }
  | { kind: "update"; finding: TrackedFinding; draft: IssueDraft; issue: TrackerIssue }
  | { kind: "close"; finding: TrackedFinding; issue: TrackerIssue; draft: IssueDraft; comment: string; completed: boolean }
  | { kind: "reopen"; finding: TrackedFinding; draft: IssueDraft; issue: TrackerIssue; comment: string };

const rank = (severity: string): number => SEVERITIES.indexOf(normalSeverity(severity));
const labelsCurrent = (issue: TrackerIssue, draft: IssueDraft): boolean =>
  draft.labels.every(label => issue.labels.includes(label)) && issue.labels.filter(label => label.startsWith("severity:")).length === 1;

/** Decide what to do, most severe first. Pure: no tracker calls. */
export function planIssueSync(findings: TrackedFinding[], issues: TrackerIssue[], minSeverity: string): { actions: IssueAction[]; unchanged: number; belowMinimum: number } {
  // Two issues for one key can only come from outside this command; manage the oldest and leave the rest.
  const byKey = new Map<string, TrackerIssue>();
  for (const issue of [...issues].sort((a, b) => a.number - b.number)) if (!byKey.has(issue.key)) byKey.set(issue.key, issue);
  const actions: IssueAction[] = [];
  let unchanged = 0; let belowMinimum = 0;
  for (const finding of [...findings].sort((a, b) => rank(a.severity) - rank(b.severity) || a.key.localeCompare(b.key))) {
    const issue = byKey.get(finding.key);
    const draft = buildIssue(finding);
    if (finding.closedBecause) {
      if (issue?.open) actions.push({ kind: "close", finding, issue, draft, completed: finding.closedBecause === "fixed", comment: `Closed by 0: this finding is now ${finding.closedBecause === "false-positive" ? "marked as a false positive" : finding.falsePositive ? "suppressed as a false positive" : finding.closedBecause}. It is reopened if the finding comes back.` });
      else unchanged++;
      continue;
    }
    if (rank(finding.severity) > rank(minSeverity)) { belowMinimum++; continue; }
    if (!issue) actions.push({ kind: "create", finding, draft });
    else if (!issue.open) actions.push({ kind: "reopen", finding, draft, issue, comment: "Reopened by 0: this finding was found again." });
    else if (issue.title !== draft.title || issue.body !== draft.body || !labelsCurrent(issue, draft)) actions.push({ kind: "update", finding, draft, issue });
    else unchanged++;
  }
  return { actions, unchanged, belowMinimum };
}

export interface IssuesDeps {
  out(text: string): void;
  err(text: string): void;
  sleep(ms: number): Promise<void>;
  /** Run `gh` with these arguments and an optional request body on standard input. */
  gh(args: string[], input?: string): Promise<string>;
  loadFindings(dbPath: string | undefined): Promise<TrackedFinding[]>;
  makeTracker(repo: string, gh: IssuesDeps["gh"]): IssueTracker;
}

const errorLine = (error: unknown): string => (error instanceof Error ? error.message : String(error)).split("\n")[0]!.slice(0, 160);

async function loadTrackedFindings(dbPath: string | undefined): Promise<TrackedFinding[]> {
  const service = new FindingsService({ sharedDbPath: resolveOsecDbPath(dbPath), ...(dbPath ? { includeRuns: false } : { listPaths: listOsecRunDatabasePaths }) });
  const merged = await service.list(5000);
  const out: TrackedFinding[] = [];
  for (const family of merged.families) {
    const latest = family.latest;
    const annotation = (await service.readFamily(family.key, db => db.getFindingReviewFields(latest.id).reviewAnnotation)).find(Boolean);
    const triage = effectiveTriageStatus(latest);
    const impact = attackerImpactSentence(latest);
    out.push({
      key: findingKey(family.key), id: latest.id, title: latest.title, severity: latest.severity, category: latest.category,
      ...(annotation && typeof annotation.path === "string" ? { path: annotation.path } : {}),
      ...(annotation && typeof annotation.startLine === "number" ? { startLine: annotation.startLine } : {}),
      ...(impact ? { impact } : {}),
      ...((latest as { scope?: unknown }).scope === "out-of-scope" ? { scope: "out-of-scope" as const } : {}),
      ...(triage === "suppressed" && /^false[ -]positive\b/i.test(String((latest as { triageNote?: unknown }).triageNote ?? "").trim()) ? { falsePositive: true } : {}),
      ...(CLOSING_TRIAGE.has(triage) ? { closedBecause: triage as "accepted" | "suppressed" } : CLOSING_STATUS.has(latest.status) ? { closedBecause: latest.status as "fixed" | "false-positive" } : {}),
    });
  }
  return out;
}

const defaults: IssuesDeps = {
  out: text => process.stdout.write(`${text}\n`),
  err: text => process.stderr.write(`${text}\n`),
  sleep: ms => new Promise(done => setTimeout(done, ms)),
  gh: runGh,
  loadFindings: loadTrackedFindings,
  makeTracker: (repo, gh) => selectHost({ run: gh }).issues(repo),
};

export interface IssuesOptions { includeOutOfScope?: boolean; repo?: string; minSeverity: string; max: string; delay: string; dryRun?: boolean; dbPath?: string; format?: string }
export interface IssueOutcome { action: IssueAction["kind"]; key: string; title: string; issue?: number; ok: boolean; error?: string }
export interface IssuesResult { repo: string; dryRun: boolean; planned: number; deferred: number; unchanged: number; belowMinimum: number; outcomes: IssueOutcome[]; warnings: string[] }

const PAST: Record<IssueAction["kind"], string> = { create: "created", update: "updated", close: "closed", reopen: "reopened" };

export async function runIssues(options: IssuesOptions, deps: IssuesDeps = defaults): Promise<IssuesResult> {
  if (!SEVERITIES.includes(options.minSeverity as Severity)) throw new UsageError(`--min-severity must be one of: ${SEVERITIES.join(", ")}.`);
  const max = Number(options.max); const delay = Number(options.delay);
  if (!Number.isInteger(max) || max < 1 || max > 500) throw new UsageError("--max must be a whole number from 1 to 500.");
  if (!Number.isFinite(delay) || delay < 0 || delay > 60000) throw new UsageError("--delay is milliseconds, from 0 to 60000.");
  const host = selectHost({ run: deps.gh });
  const repo = options.repo ?? await host.currentRepo();
  if (!host.isValidRepo(repo)) throw new UsageError("Name the repository with --repo owner/name (or run this inside its clone).");

  const tracker = deps.makeTracker(repo, deps.gh);
  const loaded = await deps.loadFindings(options.dbPath);
  // Findings the team declared out of scope are not what it asked to act on: no issue is opened for them unless asked.
  const findings = options.includeOutOfScope ? loaded : loaded.filter(finding => finding.scope !== "out-of-scope");
  if (findings.length < loaded.length) deps.err(`${loaded.length - findings.length} finding(s) outside the declared scope were left out; add --include-out-of-scope to open issues for them.`);
  const { actions, unchanged, belowMinimum } = planIssueSync(findings, await tracker.list(), options.minSeverity);
  const todo = actions.slice(0, max);
  const result: IssuesResult = { repo, dryRun: Boolean(options.dryRun), planned: actions.length, deferred: actions.length - todo.length, unchanged, belowMinimum, outcomes: [], warnings: [] };
  const outcomeOf = (action: IssueAction, ok: boolean): IssueOutcome => ({ action: action.kind, key: action.finding.key, title: buildIssue(action.finding).title, ...("issue" in action ? { issue: action.issue.number } : {}), ok });

  if (options.dryRun) {
    for (const action of todo) {
      const outcome = outcomeOf(action, true);
      deps.err(`would ${action.kind}${outcome.issue ? ` #${outcome.issue}` : ""}: ${outcome.title}`);
      result.outcomes.push(outcome);
    }
    if (result.deferred) deps.err(`${result.deferred} more change(s) beyond --max ${max} would wait for a later run.`);
    return result;
  }

  let labels: string[] = [];
  if (todo.some(action => "draft" in action)) {
    const ensured = await tracker.ensureLabels([...new Set(todo.flatMap(action => "draft" in action ? action.draft.labels : []))]);
    labels = ensured.usable; result.warnings = ensured.warnings;
    for (const warning of ensured.warnings) deps.err(`warning: ${warning}`);
  }
  const usable = (draft: IssueDraft): IssueDraft => ({ ...draft, labels: draft.labels.filter(label => labels.includes(label)) });
  let first = true;
  for (const action of todo) {
    if (!first && delay) await deps.sleep(delay);
    first = false;
    const outcome = outcomeOf(action, true);
    try {
      if (action.kind === "create") outcome.issue = await tracker.create(usable(action.draft));
      else if (action.kind === "update") await tracker.update(action.issue, usable(action.draft));
      else if (action.kind === "close") await tracker.close(action.issue, action.comment, action.completed, action.draft);
      else { await tracker.reopen(action.issue, action.comment); await tracker.update({ ...action.issue, open: true }, usable(action.draft)); }
      deps.err(`${PAST[action.kind]}${outcome.issue ? ` #${outcome.issue}` : ""}: ${outcome.title}`);
    } catch (error) {
      outcome.ok = false; outcome.error = errorLine(error);
      deps.err(`failed to ${action.kind}: ${outcome.title}: ${outcome.error}`);
    }
    result.outcomes.push(outcome);
  }
  if (result.deferred) deps.err(`${result.deferred} more change(s) deferred by --max ${max}; run again to continue.`);
  return result;
}

export function registerFindingsIssuesCommand(parent: Command, deps: IssuesDeps = defaults): void {
  parent.command("issues")
    .description("Mirror findings into GitHub Issues, one issue per finding, kept in sync without duplicates")
    .option("--repo <owner/name>", "Repository (default: the current clone's)")
    .option("--min-severity <severity>", "Open issues only for findings at or above this: critical, high, medium, low or info", "medium")
    .option("--max <n>", "Most issues to create, update, close or reopen in one run", "25")
    .option("--delay <ms>", "Wait this long between changes to respect rate limits", "1000")
    .option("--dry-run", "Print what would change and change nothing")
    .option("--include-out-of-scope", "Also open issues for findings the declared scope (0 scan --scope) labelled out of scope; they are skipped by default")
    .option("--db-path <path>", "Path to SQLite database (default: the shared database and every scan's)")
    .option("--format <format>", "Output: text or json", "text")
    .action(async (options: IssuesOptions) => {
      try {
        const result = await runIssues(options, deps);
        if (options.format === "json") deps.out(JSON.stringify(result));
        else {
          const count = (kind: string) => result.outcomes.filter(outcome => outcome.action === kind && outcome.ok).length;
          deps.out(`${result.dryRun ? "Would change" : "Changed"} ${result.outcomes.filter(outcome => outcome.ok).length} issue(s) in ${result.repo}: ${count("create")} created, ${count("update")} updated, ${count("close")} closed, ${count("reopen")} reopened; ${result.unchanged} already current, ${result.belowMinimum} below ${options.minSeverity}.`);
        }
        if (result.outcomes.some(outcome => !outcome.ok)) process.exitCode = 1;
      } catch (error) { finishWithError(error, { err: deps.err }, options.format === "json"); }
    });
}
