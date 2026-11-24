/**
 * Review one Bitbucket pull request: scan what it changes, publish a Code Insights report for the head commit, keep one
 * summary comment up to date and put at most a few inline comments on the lines the pull request changed.
 *
 * Re-running is safe. A pull request whose head commit was already reviewed is skipped. Comments carry a marker, so a
 * second run edits the summary, leaves unchanged inline comments alone and removes the ones whose finding is gone.
 * Nothing the scan produced is copied into a comment without removing links, markup and @mentions first.
 */
import { createHash } from "node:crypto";
import { buildCodeInsights, readInsightFindings, DEFAULT_REPORT_ID, type InsightFinding } from "../code-insights.js";
import { withoutOutOfScope } from "../commands/findings-upload.js";
import { oneLine } from "../web/pr-review.js";
import type { BitbucketClient, PullRequest, PullRequestComment } from "./client.js";
import { parseDiff } from "./diff.js";

/** What the checkout step hands back: the exact commit that was scanned and the scan's JSON report. */
export interface ScanResult {
  /** All 40 characters of the head commit that was scanned. */
  sha: string;
  /** Text of `0security scan --format json`. */
  json: string;
  /** Exit code of the scan: 0 done, 1 finding at the fail level or failure, 3 stopped early. */
  exitCode: number;
}
export interface ReviewRunner { scan(pr: PullRequest): Promise<ScanResult> }

/** Remembers which head commit of each pull request was reviewed. */
export interface ReviewState { get(key: string): string | undefined; set(key: string, sha: string): void }

export interface ReviewOptions {
  reportId?: string;
  maxFiles?: number;
  maxInline?: number;
  comments?: boolean;
  insights?: boolean;
}

export type ReviewOutcome =
  | { status: "skipped"; reason: "closed" | "draft" | "fork" | "unchanged" }
  | { status: "too-large"; files: number }
  | { status: "reviewed"; sha: string; total: number; inlinePosted: number; inlineRemoved: number; partial: boolean; warnings: string[] };

export const prKey = (pr: Pick<PullRequest, "platform" | "owner" | "repo" | "id">): string => `${pr.platform}:${pr.owner}/${pr.repo}#${pr.id}`;
const sameCommit = (a: string, b: string): boolean => a.slice(0, 12) === b.slice(0, 12);

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const bySeverity = (a: InsightFinding, b: InsightFinding) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);

const marker = (reportId: string, key: string) => `[0-review:${reportId}:${key}]`;
export const findingKey = (finding: InsightFinding): string => createHash("sha256").update(`${finding.path ?? ""}\n${finding.line}\n${finding.cwe ?? finding.ruleId}`).digest("hex").slice(0, 12);

function inlineBody(reportId: string, finding: InsightFinding): string {
  const lines = [`**${finding.severity.toUpperCase()}**: ${oneLine(finding.title, 160)}`];
  const meta = [oneLine(finding.ruleId, 80), finding.cwe].filter(Boolean).join(", ");
  if (meta) lines.push(`Rule: ${meta}`);
  if (finding.verdict) lines.push(`Verdict: ${oneLine(finding.verdict, 80)}`);
  if (finding.rationale) lines.push(oneLine(finding.rationale, 600));
  if (finding.fix) lines.push(`Fix: ${oneLine(finding.fix.replace(/^Suggested replacement:\s*/, ""), 600)}`);
  lines.push("", `Reported by 0. Review it before you act on it. ${marker(reportId, findingKey(finding))}`);
  return lines.join("\n\n").replace(/\n\n\n/g, "\n\n");
}

function summaryBody(reportId: string, pr: PullRequest, sha: string, findings: InsightFinding[], extra: { partial: boolean; filesScanned: number; outside: number; inline: number }): string {
  const count = (level: string) => findings.filter(finding => finding.severity === level).length;
  const lines = [`0 reviewed ${extra.filesScanned} changed file${extra.filesScanned === 1 ? "" : "s"} at commit ${sha.slice(0, 7)}.`];
  lines.push(findings.length
    ? `Found ${findings.length} issue${findings.length === 1 ? "" : "s"}: ${SEVERITY_ORDER.map(level => [level, count(level)] as const).filter(([, n]) => n).map(([level, n]) => `${n} ${level}`).join(", ")}.`
    : "No findings. This does not mean the code is safe; the scan covered only these files.");
  for (const finding of findings.slice(0, 10)) lines.push(`- ${finding.severity}: ${oneLine(finding.title, 120)}${finding.path ? ` (${oneLine(finding.path, 120)}${finding.line ? `:${finding.line}` : ""})` : ""}`);
  if (findings.length > 10) lines.push(`- and ${findings.length - 10} more in the Code Insights report`);
  if (extra.inline) lines.push(`${extra.inline} inline comment${extra.inline === 1 ? "" : "s"} on the changed lines.`);
  if (extra.outside) lines.push(`${extra.outside} finding${extra.outside === 1 ? " was" : "s were"} outside the changed files and left out.`);
  if (extra.partial) lines.push("The scan stopped before it reviewed everything (budget or time limit), so the result is partial.");
  lines.push("", `${marker(reportId, "summary")} Pull request ${pr.id}.`);
  return lines.join("\n");
}

/** Review one pull request and report the result. Throws when the scan or a required Bitbucket call fails. */
export async function reviewPullRequest(pr: PullRequest, deps: { client: BitbucketClient; runner: ReviewRunner; state: ReviewState }, options: ReviewOptions = {}): Promise<ReviewOutcome> {
  const reportId = options.reportId ?? DEFAULT_REPORT_ID;
  const { client } = deps;
  if (!pr.open) return { status: "skipped", reason: "closed" };
  if (pr.draft) return { status: "skipped", reason: "draft" };
  if (pr.fork) return { status: "skipped", reason: "fork" };
  const seen = deps.state.get(prKey(pr));
  if (seen && sameCommit(seen, pr.headSha)) return { status: "skipped", reason: "unchanged" };

  const comments = options.comments !== false;
  const summaryMarker = marker(reportId, "summary");
  const upsertSummary = async (body: string) => {
    if (!comments) return;
    const existing = (await client.findComments(pr, summaryMarker))[0];
    if (existing) await client.updateComment(pr, existing, body); else await client.addComment(pr, body);
  };

  const diff = await client.diff(pr);
  const files = parseDiff(diff.text);
  const maxFiles = options.maxFiles ?? 50;
  if (diff.truncated || files.length > maxFiles) {
    await upsertSummary([`0 did not review this pull request: it changes ${diff.truncated ? "too much" : `${files.length} files, more than the limit of ${maxFiles}`}.`, "", `${summaryMarker} Pull request ${pr.id}.`].join("\n"));
    deps.state.set(prKey(pr), pr.headSha);
    return { status: "too-large", files: files.length };
  }
  const changed = new Map(files.map(file => [file.path, file]));

  const result = await deps.runner.scan(pr);
  const warnings: string[] = [];
  const all = readInsightFindings(withoutOutOfScope(result.json).text);
  const inScope = all.filter(finding => finding.path !== undefined && changed.has(finding.path));
  const findings = inScope.slice().sort(bySeverity);
  const partial = result.exitCode === 3;

  if (options.insights !== false) {
    try { await client.publishInsights(buildCodeInsights(findings, client.platform, { reportId }), { owner: pr.owner, repo: pr.repo, commit: result.sha }); }
    catch (error) { warnings.push(`Code Insights: ${error instanceof Error ? error.message : String(error)}`.slice(0, 400)); }
  }

  let inlinePosted = 0;
  let inlineRemoved = 0;
  if (comments) {
    const prefix = `[0-review:${reportId}:`;
    const existing = new Map<string, PullRequestComment>();
    for (const comment of await client.findComments(pr, prefix)) {
      const key = new RegExp(`\\[0-review:${reportId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}:([0-9a-f]{12})\\]`).exec(comment.text)?.[1];
      if (key) existing.set(key, comment);
    }
    const wanted = new Map<string, { finding: InsightFinding; kind: "ADDED" | "CONTEXT" }>();
    for (const finding of findings) {
      const kind = changed.get(finding.path!)?.lines.get(finding.line);
      if (!kind) continue;
      const key = findingKey(finding);
      if (!wanted.has(key) && wanted.size < (options.maxInline ?? 10)) wanted.set(key, { finding, kind });
    }
    for (const [key, { finding, kind }] of wanted) {
      if (existing.has(key)) continue;
      try { await client.addComment(pr, inlineBody(reportId, finding), { path: finding.path!, line: finding.line, kind }); inlinePosted++; }
      catch (error) { warnings.push(`Inline comment: ${error instanceof Error ? error.message : String(error)}`.slice(0, 400)); }
    }
    for (const [key, comment] of existing) {
      if (wanted.has(key)) continue;
      try { await client.deleteComment(pr, comment); inlineRemoved++; } catch { /* Not ours to remove, or already gone. */ }
    }
    await upsertSummary(summaryBody(reportId, pr, result.sha, findings, { partial, filesScanned: files.length, outside: all.length - inScope.length, inline: wanted.size }));
  }
  deps.state.set(prKey(pr), result.sha);
  return { status: "reviewed", sha: result.sha, total: findings.length, inlinePosted, inlineRemoved, partial, warnings };
}
