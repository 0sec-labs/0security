/**
 * `0 findings export-fixes`: a report of what happened to the fixes `0 findings burndown` proposed, so a team can
 * show how many were accepted. It reads the burndown state file and, for titles and severities, the findings
 * database. It never includes evidence. With --check-merged it asks the code host, one pull request at a time,
 * whether each was merged, closed or edited; without it nothing leaves the machine.
 */
import { UNTRUSTED_GIT_BASE_CONFIG } from "@0/engine";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { Option, type Command } from "commander";
import { osecDB } from "@0/engine/storage";
import { findingDatabasePaths } from "../finding-focus.js";
import { shortFindingId } from "../finding-id.js";
import { settleVariantsOfMergedFix } from "../finding-variants.js";
import { runGh } from "../host/gh.js";
import { selectHost, type Host } from "../host/index.js";
import { fileStore, type FindingRecord, type StateStore } from "./burndown.js";
import { neutralise } from "./fix-conventions.js";
import { finishWithError, UsageError } from "./output.js";
import { compareFindingsByBusinessContext, type FindingBusinessContext } from "@0/engine/shared";
import { findingPath } from "../business-context.js";
import { CONTEXT_FLAG_HELP, contextOptionsOf, detectRepository, labelFor, loadContextFor, REPOSITORY_FLAG_HELP, type LoadedContext } from "../business-context-load.js";

export const FIX_REPORT_SCHEMA = "0.fix-outcomes.v1";
const MAX_ROWS = 5000;
const exec = promisify(execFile);

export type MergeState = "merged" | "closed" | "open" | "unknown";
export interface FixOutcomeRow {
  finding: string; title: string; severity: string; category: string; repo: string; branch: string | null; pullRequestUrl: string | null;
  result: string; draft: boolean | null; checksPassing: boolean | null; costUsd: number | null; recordedAt: string;
  /** Operator declaration that moved this fix in the order; absent without a context. Severity is unchanged. */
  businessContext?: FindingBusinessContext;
  /** Present only with --check-merged. */
  pullRequest: { state: MergeState; draft: boolean | null; commits: number | null; editedAfterOpening: boolean | null } | null;
}
export interface FixOutcomeSummary {
  attempted: number; proposed: number; pullRequestsOpened: number; draft: number; checksPassed: number; checksFailed: number; costUsd: number;
  /** Counts that need --check-merged; null when it was not used. */
  merged: number | null; closedWithoutMerge: number | null; stillOpen: number | null; edited: number | null; unknown: number | null;
  /** merged / (merged + closed without merge); null when none are decided or --check-merged was not used. */
  acceptanceRate: number | null;
}
export interface FixOutcomeReport {
  schema: typeof FIX_REPORT_SCHEMA; generatedAt: string; since: string | null; repo: string | null; checkedMerged: boolean; summary: FixOutcomeSummary;
  /** The same summary for each repository, so one export gives per-workspace figures. */
  workspaces: Array<{ repo: string; summary: FixOutcomeSummary }>;
  fixes: FixOutcomeRow[];
}

export interface FixLookup { title: string; severity: string; category: string; path?: string }
export interface ExportFixesOptions { repo?: string; since?: string; checkMerged?: boolean; output?: string; format?: string; context?: string; repository?: string;
  /** The loaded business context; set by the command from --context or the findingsContext setting. */
  ranking?: LoadedContext }
export interface ExportFixesDeps {
  store: StateStore;
  /** Titles and severities by finding id. */
  lookup(): Map<string, FixLookup>;
  /** The code host; only asked for with --check-merged. */
  host(): Host;
  repoRoot(dir: string): Promise<string>;
  /** Called with a finding id when its fix pull request was observed merged; flips its fixed-pending-merge variants to fixed. */
  settleVariants?(findingId: string): number;
  /** The owner/name of the git remote of a folder; only asked for when the context has per-repository rules. */
  repositoryOf?(dir: string): Promise<string | undefined>;
  now(): Date;
  out(text: string): void;
  err(text: string): void;
  writeReport(dir: string, files: Array<{ name: string; text: string }>): void;
}

/** One line of plain text. */
const line = (text: string): string => text.replace(/[\u0000-\u001f\u007f\u2028\u2029]+/g, " ").replace(/\s+/g, " ").trim();
const cell = (text: string | number | null | undefined): string => neutralise(String(text ?? "")).replace(/\|/g, "\\|") || "-";

function sinceCutoff(text: string | undefined): number | undefined {
  if (text === undefined) return undefined;
  const at = /^\d{4}-\d{2}-\d{2}(T[\d:.]+Z)?$/.test(text) ? Date.parse(text) : NaN;
  if (!Number.isFinite(at)) throw new UsageError("--since must be a date like 2026-01-31.");
  return at;
}

function parseKey(key: string): { repo: string } { return { repo: key.split("\u0000")[0] ?? "" }; }

export function summarise(rows: FixOutcomeRow[], checkedMerged: boolean): FixOutcomeSummary {
  const proposed = rows.filter(r => r.result === "committed" || r.result === "pr-opened" || r.result === "pr-updated");
  const withPr = rows.filter(r => r.pullRequestUrl);
  const states = rows.map(r => r.pullRequest?.state);
  const count = (state: MergeState): number | null => checkedMerged ? states.filter(s => s === state).length : null;
  const merged = count("merged"); const closed = count("closed");
  const decided = (merged ?? 0) + (closed ?? 0);
  return {
    attempted: rows.length, proposed: proposed.length, pullRequestsOpened: withPr.length, draft: rows.filter(r => r.draft === true).length,
    checksPassed: rows.filter(r => r.checksPassing === true).length, checksFailed: rows.filter(r => r.checksPassing === false).length,
    costUsd: Number(rows.reduce((sum, r) => sum + (r.costUsd ?? 0), 0).toFixed(6)),
    merged, closedWithoutMerge: closed, stillOpen: count("open"), unknown: count("unknown"),
    edited: checkedMerged ? rows.filter(r => r.pullRequest?.editedAfterOpening === true).length : null,
    acceptanceRate: checkedMerged && decided > 0 ? Number(((merged ?? 0) / decided).toFixed(4)) : null,
  };
}

export async function buildFixReport(options: ExportFixesOptions, deps: ExportFixesDeps): Promise<FixOutcomeReport> {
  const since = sinceCutoff(options.since);
  const repo = options.repo ? await deps.repoRoot(resolve(options.repo)).catch(() => { throw new UsageError("--repo must be a git repository."); }) : undefined;
  const titles = deps.lookup();
  const rows: FixOutcomeRow[] = [];
  const remotes = new Map<string, string | undefined>();
  const repositoryFor = async (folder: string): Promise<string | undefined> => {
    const loaded = options.ranking;
    if (!loaded) return undefined;
    if (loaded.repository || !loaded.context.repositories.length) return loaded.repository;
    if (!remotes.has(folder)) remotes.set(folder, await (deps.repositoryOf ?? detectRepository)(folder));
    return remotes.get(folder);
  };
  for (const [key, record] of Object.entries(deps.store.load().findings) as Array<[string, FindingRecord]>) {
    const where = parseKey(key).repo;
    if (repo && where !== repo) continue;
    if (since !== undefined && !(Date.parse(record.updatedAt) >= since)) continue;
    const known = titles.get(record.finding);
    const businessContext = options.ranking ? labelFor(options.ranking, { severity: known?.severity ?? "unknown", path: known?.path }, await repositoryFor(where)) : undefined;
    rows.push({
      ...(businessContext ? { businessContext } : {}),
      finding: record.finding, title: line(known?.title ?? "(finding no longer in the database)").slice(0, 200), severity: known?.severity ?? "unknown", category: known?.category ?? "unknown",
      repo: where, branch: record.branch ?? null, pullRequestUrl: record.pullRequestUrl ?? null, result: record.result,
      draft: record.draft ?? null, checksPassing: record.checksPassing ?? null, costUsd: record.costUsd ?? null, recordedAt: record.updatedAt, pullRequest: null,
    });
  }
  // With a business context the fixes that matter most come first; severity is never changed. Without one, oldest first.
  rows.sort((a, b) => (options.ranking ? compareFindingsByBusinessContext(a, b) : 0) || a.recordedAt.localeCompare(b.recordedAt) || a.finding.localeCompare(b.finding));
  if (rows.length > MAX_ROWS) rows.length = MAX_ROWS;
  if (options.checkMerged) {
    const host = deps.host();
    for (const row of rows) {
      if (!row.pullRequestUrl) continue;
      try {
        const state = await host.pullRequestState(row.pullRequestUrl);
        row.pullRequest = { state: state.state, draft: state.draft, commits: state.commits, editedAfterOpening: state.commits > 1 };
        if (state.state === "merged") { const settled = deps.settleVariants?.(row.finding) ?? 0; if (settled) deps.err(`${shortFindingId(row.finding)}: fix merged, ${settled} variant${settled === 1 ? "" : "s"} marked fixed`); }
      } catch (error) {
        deps.err(`could not read ${row.pullRequestUrl}: ${line(error instanceof Error ? error.message : String(error)).slice(0, 120)}`);
        row.pullRequest = { state: "unknown", draft: null, commits: null, editedAfterOpening: null };
      }
    }
  }
  return {
    schema: FIX_REPORT_SCHEMA, generatedAt: deps.now().toISOString(), since: options.since ?? null, repo: repo ?? null, checkedMerged: Boolean(options.checkMerged),
    summary: summarise(rows, Boolean(options.checkMerged)), workspaces: [...new Set(rows.map(r => r.repo))].sort().map(name => ({ repo: name, summary: summarise(rows.filter(r => r.repo === name), Boolean(options.checkMerged)) })), fixes: rows,
  };
}

export function renderFixReportMarkdown(report: FixOutcomeReport): string {
  const s = report.summary;
  const pct = (n: number | null) => n === null ? "not measured" : `${Math.round(n * 100)}%`;
  const out = [
    "# Fix outcomes", "",
    `Generated ${report.generatedAt}${report.since ? `, fixes recorded since ${report.since}` : ""}${report.repo ? `, repository ${cell(report.repo)}` : ""}.`, "",
    "## Summary", "",
    `- Fixes attempted: ${s.attempted}`, `- Proposed (a change was committed): ${s.proposed}`, `- Pull requests opened: ${s.pullRequestsOpened}`, `- Opened as draft: ${s.draft}`,
    `- Checks passed: ${s.checksPassed}, failed: ${s.checksFailed}`, `- Cost: $${s.costUsd.toFixed(4)}`,
    ...(report.checkedMerged
      ? [`- Merged: ${s.merged}`, `- Closed without merging: ${s.closedWithoutMerge}`, `- Still open: ${s.stillOpen}`, `- Edited after opening (more than one commit): ${s.edited}`, `- Could not be read: ${s.unknown}`, `- Acceptance rate (merged of merged and closed): ${pct(s.acceptanceRate)}`]
      : ["- Merged, closed and edited: not measured. Run again with --check-merged to ask the code host."]),
    ...(report.workspaces.length > 1
      ? ["", "## By repository", "", "| Repository | Attempted | Proposed | Pull requests | Merged | Closed without merging | Edited | Acceptance rate |", "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ...report.workspaces.map(w => `| ${cell(w.repo)} | ${w.summary.attempted} | ${w.summary.proposed} | ${w.summary.pullRequestsOpened} | ${w.summary.merged ?? "-"} | ${w.summary.closedWithoutMerge ?? "-"} | ${w.summary.edited ?? "-"} | ${pct(w.summary.acceptanceRate)} |`)]
      : []),
    "", "## Fixes", "",
  ];
  if (!report.fixes.length) return `${out.join("\n")}No fix outcomes are recorded yet. Run 0security findings fix or 0security findings burndown first.\n`;
  const ranked = report.fixes.some(r => r.businessContext);
  out.push(`| Finding | Severity | ${ranked ? "Why ranked | " : ""}Title | Result | Pull request | Draft | Checks | Cost | State | Recorded |`, `| --- | --- | ${ranked ? "--- | " : ""}--- | --- | --- | --- | --- | --- | --- | --- |`);
  for (const r of report.fixes) {
    out.push(`| ${cell(shortFindingId(r.finding))} | ${cell(r.severity)} | ${ranked ? `${cell(r.businessContext?.rationale)} | ` : ""}${cell(r.title)} | ${cell(r.result)} | ${cell(r.pullRequestUrl ?? r.branch)} | ${r.draft === null ? "-" : r.draft ? "yes" : "no"} | ${r.checksPassing === null ? "-" : r.checksPassing ? "passed" : "failed"} | ${r.costUsd === null ? "-" : `$${r.costUsd.toFixed(4)}`} | ${cell(r.pullRequest ? `${r.pullRequest.state}${r.pullRequest.editedAfterOpening ? ", edited" : ""}` : report.checkedMerged ? "-" : "not checked")} | ${cell(r.recordedAt.slice(0, 19))} |`);
  }
  out.push("", "Evidence bodies and proof-of-concept details are never part of this report.");
  return `${out.join("\n")}\n`;
}

function lookupFromDatabases(): Map<string, FixLookup> {
  const found = new Map<string, FixLookup>();
  for (const path of findingDatabasePaths()) {
    let db: osecDB | undefined;
    try {
      db = new osecDB(path, { readOnly: true });
      for (const row of db.listFindings({ limit: MAX_ROWS }) as unknown as Array<Record<string, unknown>>) {
        if (typeof row.id === "string" && !found.has(row.id)) found.set(row.id, { title: String(row.title ?? ""), severity: String(row.severity ?? "unknown"), category: String(row.category ?? "unknown"), ...(findingPath(row.reviewAnnotation) ? { path: findingPath(row.reviewAnnotation)! } : {}) });
      }
    } catch { /* an unreadable run database holds nothing to report */ } finally { db?.close(); }
  }
  return found;
}

const defaults: ExportFixesDeps = {
  store: fileStore(),
  lookup: lookupFromDatabases,
  settleVariants: findingId => settleVariantsOfMergedFix(findingId, findingDatabasePaths()),
  host: () => selectHost({ run: runGh }),
  repoRoot: async dir => (await exec("git", ["-C", dir, ...UNTRUSTED_GIT_BASE_CONFIG, "rev-parse", "--show-toplevel"])).stdout.trim(),
  now: () => new Date(),
  out: text => process.stdout.write(`${text}\n`),
  err: text => process.stderr.write(`${text}\n`),
  writeReport(dir, files) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    for (const file of files) writeFileSync(join(dir, file.name), file.text, { mode: 0o600 });
  },
};

export async function runExportFixes(options: ExportFixesOptions, deps: ExportFixesDeps): Promise<FixOutcomeReport> {
  const report = await buildFixReport(options, deps);
  const markdown = renderFixReportMarkdown(report);
  const json = `${JSON.stringify(report, null, 2)}\n`;
  if (options.output) {
    deps.writeReport(resolve(options.output), [{ name: "fix-outcomes.md", text: markdown }, { name: "fix-outcomes.json", text: json }]);
    deps.err(`Wrote fix-outcomes.md and fix-outcomes.json to ${resolve(options.output)}`);
  } else deps.out((options.format === "json" ? json : markdown).trimEnd());
  return report;
}

export function registerFindingsExportFixesCommand(parent: Command, deps: ExportFixesDeps = defaults): void {
  parent.command("export-fixes")
    .description("Report what happened to the fixes 0 proposed, per repository: counts, pull requests, checks, cost and, on request, merged or closed")
    .option("--repo <dir>", "Only fixes recorded for this git repository (default: all)")
    .option("--since <date>", "Only fixes recorded on or after this date, like 2026-01-31")
    .option("--check-merged", "Ask the code host whether each pull request was merged, closed or edited (one request each); a merged fix also turns its variants from fixed-pending-merge to fixed")
    .option("--context <file>", CONTEXT_FLAG_HELP)
    .option("--repository <name>", REPOSITORY_FLAG_HELP)
    .option("-o, --output <dir>", "Write fix-outcomes.md and fix-outcomes.json into this folder instead of printing")
    .addOption(new Option("--format <format>", "Printed output: markdown or json").choices(["markdown", "json"]).default("markdown"))
    .addHelpText("after", "\nIt reads ~/.0/burndown.json, so it covers fixes made by 0security findings burndown and 0security findings fix. Finding evidence is never included.")
    .action(async (options: ExportFixesOptions, command: Command) => {
      try { await runExportFixes({ ...options, ranking: await loadContextFor(contextOptionsOf(options, command)) }, deps); }
      catch (error) { finishWithError(error, deps, options.format === "json"); }
    });
}
