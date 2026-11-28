/**
 * `0 findings upload <sarif>`: put a SARIF file where the team already looks, GitHub code scanning (the Security tab and
 * pull request annotations). The file comes from `0 scan --format sarif` or any scanner. GitHub keys each alert by its
 * fingerprint, so uploading again for a later commit updates the alerts instead of duplicating them.
 */
import { UNTRUSTED_GIT_BASE_CONFIG } from "@0/engine";
import { execFile } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { promisify } from "node:util";
import type { Command } from "commander";
import { looksLikeSarif } from "@0/engine/shared";
import { runGh } from "../host/gh.js";
import { selectHost } from "../host/index.js";
import { buildCodeInsights, postCodeInsights, readInsightFindings, type CodeInsightsPlatform, type FetchLike } from "../code-insights.js";
import { finishWithError, UsageError } from "./output.js";
import { runJiraExport } from "../jira/export.js";
import type { JiraSeverity } from "../jira/findings.js";
import { isServerTarget, runServerUpload, serverUploadDefaults } from "./findings-server-upload.js";

const exec = promisify(execFile);
const MAX_SARIF_BYTES = 20 * 1024 * 1024;
const MAX_GZIP_BYTES = 10 * 1024 * 1024;
const SHA = /^[0-9a-f]{40}$/;
const REF = /^refs\/(heads|tags|pull)\/[A-Za-z0-9._\/-]{1,200}$/;

export interface UploadDeps {
  out(text: string): void;
  err(text: string): void;
  sleep(ms: number): Promise<void>;
  readText(path: string): string;
  /** Run `gh` with these arguments and an optional request body on standard input. */
  gh(args: string[], input?: string): Promise<string>;
  git(args: string[]): Promise<string>;
  /** HTTP for the Bitbucket targets; tests replace it. */
  fetch?: FetchLike;
  /** Environment for the Bitbucket targets (token, repository, commit); defaults to the process's. */
  env?: Record<string, string | undefined>;
}
const defaults: UploadDeps = {
  out: text => process.stdout.write(`${text}\n`),
  err: text => process.stderr.write(`${text}\n`),
  sleep: ms => new Promise(done => setTimeout(done, ms)),
  readText(path) {
    const stat = statSync(path);
    if (!stat.isFile() || stat.size > MAX_SARIF_BYTES) throw new UsageError("The SARIF file must be a regular file of at most 20 MB.");
    return readFileSync(path, "utf8");
  },
  gh: runGh,
  git: async args => (await exec("git", [...UNTRUSTED_GIT_BASE_CONFIG, ...args])).stdout,
};

/**
 * The text of a SARIF file or scan JSON without the findings labelled out of scope (`properties.scope`, `scope`), and how many
 * were dropped. Text that is neither is returned as it is.
 */
export function withoutOutOfScope(text: string): { text: string; dropped: number } {
  let document: unknown;
  try { document = JSON.parse(text); } catch { return { text, dropped: 0 }; }
  if (typeof document !== "object" || document === null) return { text, dropped: 0 };
  const root = document as { runs?: unknown; findings?: unknown };
  let dropped = 0;
  if (Array.isArray(root.runs)) {
    for (const run of root.runs as Array<{ results?: unknown }>) {
      if (!run || !Array.isArray(run.results)) continue;
      const kept = (run.results as Array<{ properties?: { scope?: unknown } }>).filter(result => result?.properties?.scope !== "out-of-scope");
      dropped += run.results.length - kept.length;
      run.results = kept;
    }
  }
  if (Array.isArray(root.findings)) {
    const kept = (root.findings as Array<{ scope?: unknown }>).filter(finding => finding?.scope !== "out-of-scope");
    dropped += root.findings.length - kept.length;
    root.findings = kept;
  }
  return dropped ? { text: JSON.stringify(document), dropped } : { text, dropped: 0 };
}

export interface UploadOptions { includeOutOfScope?: boolean; repo?: string; commit?: string; ref?: string; wait: boolean; tool?: string; format?: string; to?: string; url?: string; source?: string; reportId?: string; print?: boolean; allowInsecureHttp?: boolean; jiraProject?: string; jiraIssueType?: string; jiraLabel?: string[]; jiraMinSeverity?: string; dryRun?: boolean }

const BITBUCKET_TARGETS: Record<string, CodeInsightsPlatform> = { "bitbucket-cloud": "bitbucket-cloud", "bitbucket-dc": "bitbucket-dc" };
const SLUG = /^[A-Za-z0-9._~-]{1,200}$/;
const REPORT_ID = /^[A-Za-z0-9._-]{1,100}$/;

/**
 * Publish findings to Bitbucket Code Insights, or print the payload when there is no token (BITBUCKET_TOKEN) or --print is set.
 * The request bodies are printed as one JSON document: the report and the annotation batches, ready for a CI step to send.
 */
export async function runBitbucketUpload(file: string, options: UploadOptions, deps: UploadDeps = defaults): Promise<{ published: boolean; total: number; emitted: number; dropped: number; requests?: number }> {
  const platform = BITBUCKET_TARGETS[options.to ?? ""];
  if (!platform) throw new UsageError("--to must be github, jira-cloud, jira-dc, bitbucket-cloud or bitbucket-dc.");
  const env = deps.env ?? process.env;
  let findings;
  try {
    const filtered = options.includeOutOfScope ? { text: deps.readText(file), dropped: 0 } : withoutOutOfScope(deps.readText(file));
    if (filtered.dropped) deps.err(`${filtered.dropped} finding(s) outside the declared scope were left out; add --include-out-of-scope to send them.`);
    findings = readInsightFindings(filtered.text);
  } catch (error) { if (error instanceof UsageError) throw error; throw new UsageError(`${error instanceof Error ? error.message : String(error)} Make one with \`0security scan --format json -o scan.json\`.`); }
  const reportId = options.reportId ?? "0-security";
  if (!REPORT_ID.test(reportId)) throw new UsageError("--report-id may hold letters, digits, dots, dashes and underscores (at most 100).");
  const payload = buildCodeInsights(findings, platform, { reportId });
  const token = (env.BITBUCKET_TOKEN ?? "").trim();
  if (options.print || !token) {
    deps.out(JSON.stringify({ platform, reportId, report: payload.report, annotationBatches: payload.batches, annotationsTotal: payload.total, annotationsEmitted: payload.emitted, annotationsDropped: payload.dropped }, null, 2));
    if (!options.print) deps.err("BITBUCKET_TOKEN is not set: printed the payload instead of posting it.");
    if (payload.dropped) deps.err(`${payload.dropped} less severe finding(s) are over Bitbucket's ${payload.emitted}-annotation limit and were left out.`);
    return { published: false, total: payload.total, emitted: payload.emitted, dropped: payload.dropped };
  }

  const cloud = platform === "bitbucket-cloud";
  const repoName = options.repo ?? (cloud && env.BITBUCKET_WORKSPACE && env.BITBUCKET_REPO_SLUG ? `${env.BITBUCKET_WORKSPACE}/${env.BITBUCKET_REPO_SLUG}` : "");
  const [owner, repo, extra] = repoName.split("/");
  if (!owner || !repo || extra !== undefined || !SLUG.test(owner) || !SLUG.test(repo)) throw new UsageError(`Name the repository with --repo ${cloud ? "workspace/repo" : "PROJECT/repo"}.`);
  const commit = (options.commit || env.BITBUCKET_COMMIT || env.GIT_COMMIT || (await deps.git(["rev-parse", "HEAD"]).catch(() => ""))).trim();
  if (!SHA.test(commit)) throw new UsageError("Name the commit with --commit <40-character sha> (or run this inside the clone).");
  const baseUrl = options.url || env.BITBUCKET_URL || undefined;
  if (!cloud) {
    if (!baseUrl || !/^https?:\/\/[^\s/]+/.test(baseUrl)) throw new UsageError("Name the Data Center server with --url https://bitbucket.example.com (or BITBUCKET_URL).");
  }
  if (baseUrl) {
    let target: URL;
    try { target = new URL(baseUrl); } catch { throw new UsageError("--url is not a valid URL."); }
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(target.hostname);
    if (target.protocol === "http:" && !loopback && !options.allowInsecureHttp) throw new UsageError("Refusing to send the Bitbucket token over plaintext HTTP. Use an https:// URL, or pass --allow-insecure-http for a network you trust.");
  }
  const fetcher = deps.fetch ?? ((url, init) => fetch(url, init));
  const result = await postCodeInsights(payload, { owner, repo, commit, ...(baseUrl ? { baseUrl } : {}) }, token, fetcher);
  deps.err(`published ${payload.emitted} annotation(s) to ${owner}/${repo} at ${commit.slice(0, 7)}${payload.dropped ? `; ${payload.dropped} less severe finding(s) were over the limit` : ""}`);
  return { published: true, total: payload.total, emitted: payload.emitted, dropped: payload.dropped, requests: result.requests };
}

/** The SARIF as GitHub wants it: gzip, then base64. */
export function packSarif(text: string): string {
  const packed = gzipSync(Buffer.from(text, "utf8"));
  if (packed.byteLength > MAX_GZIP_BYTES) throw new UsageError("GitHub accepts at most 10 MB of compressed SARIF; split the file.");
  return packed.toString("base64");
}

export async function runUpload(file: string, options: UploadOptions, deps: UploadDeps = defaults): Promise<{ id: string; status: string } | undefined> {
  const raw = deps.readText(file);
  if (!looksLikeSarif(raw)) throw new UsageError("This is not a SARIF 2.1.0 file. Make one with `0security scan --format sarif -o scan.sarif`.");
  const filtered = options.includeOutOfScope ? { text: raw, dropped: 0 } : withoutOutOfScope(raw);
  if (filtered.dropped) deps.err(`${filtered.dropped} finding(s) outside the declared scope were left out; add --include-out-of-scope to upload them.`);
  const text = filtered.text;
  if (!looksLikeSarif(text)) throw new UsageError("This is not a SARIF 2.1.0 file. Make one with `0security scan --format sarif -o scan.sarif`.");

  const host = selectHost({ run: deps.gh });
  const repo = options.repo ?? await host.currentRepo();
  if (!host.isValidRepo(repo)) throw new UsageError("Name the repository with --repo owner/name (or run this inside its clone).");
  const commit = (options.commit || process.env.GITHUB_SHA || (await deps.git(["rev-parse", "HEAD"]).catch(() => ""))).trim();
  if (!SHA.test(commit)) throw new UsageError("Name the commit with --commit <40-character sha> (or run this inside the clone).");
  let ref = options.ref || process.env.GITHUB_REF || undefined;
  if (!ref) { const branch = (await deps.git(["rev-parse", "--abbrev-ref", "HEAD"]).catch(() => "")).trim(); ref = branch && branch !== "HEAD" ? `refs/heads/${branch}` : undefined; }
  if (!ref || !REF.test(ref)) throw new UsageError("Name the ref with --ref refs/heads/<branch> (or refs/pull/<n>/merge).");

  const response = await host.uploadSarif(repo, { commit, ref, sarif: packSarif(text), ...(options.tool ? { tool: options.tool } : {}) });
  if (!response.id) throw new Error("GitHub accepted the upload but returned no id.");
  deps.err(`uploaded to ${repo} at ${commit.slice(0, 7)} (${ref})`);
  if (!options.wait) return { id: response.id, status: "pending" };

  for (let attempt = 0; attempt < 30; attempt++) {
    await deps.sleep(2000);
    const state = await host.sarifStatus(repo, response.id);
    if (state.processing_status === "complete") return { id: response.id, status: "complete" };
    if (state.processing_status === "failed") throw new Error(`GitHub could not process the upload: ${(state.errors ?? []).join("; ").slice(0, 300) || "no reason given"}`);
  }
  return { id: response.id, status: "pending" };
}

export function registerFindingsUploadCommand(parent: Command, deps: UploadDeps = defaults): void {
  parent.command("upload")
    .description("Upload findings to GitHub code scanning (SARIF), to Jira (one issue per open finding), to Bitbucket Code Insights (scan JSON or SARIF) or to a shared findings server (SARIF or scan JSON)")
    .argument("<file>", "SARIF 2.1.0 file from `0security scan --format sarif -o scan.sarif`; for Bitbucket also `0security scan --format json -o scan.json`")
    .option("--to <target>", "github (default), jira-cloud, jira-dc, bitbucket-cloud, bitbucket-dc, or the https URL of a shared findings server (key from ZERO_FINDINGS_API_KEY)", "github")
    .option("--source <label>", "Shared findings server: name of this CI job or machine (default: the key's name)")
    .option("--url <url>", "Bitbucket Data Center base URL (default: BITBUCKET_URL); Jira site URL (default: JIRA_URL)")
    .option("--report-id <id>", "Bitbucket report id or key", "0-security")
    .option("--jira-project <key>", "Jira: project key for the new issues (default: JIRA_PROJECT)")
    .option("--jira-issue-type <name>", "Jira: issue type name", "Task")
    .option("--jira-min-severity <level>", "Jira: lowest severity that gets an issue (critical, high, medium, low or info)", "low")
    .option("--jira-label <label>", "Jira: extra label on every issue (repeatable)", (value: string, previous: string[] = []) => [...previous, value])
    .option("--dry-run", "Jira: print the issues that would be created and send nothing")
    .option("--print", "Bitbucket: print the report and annotation payload instead of posting it (also the behaviour without BITBUCKET_TOKEN)")
    .option("--allow-insecure-http", "Bitbucket and shared findings server: allow sending the token or key to an http:// URL that is not on this machine (default: refuse)")
    .option("--repo <owner/name>", "Repository (default: the current clone's); Bitbucket: workspace/repo or PROJECT/repo")
    .option("--commit <sha>", "Commit the results are for (default: HEAD, or GITHUB_SHA in Actions)")
    .option("--ref <ref>", "refs/heads/<branch> or refs/pull/<n>/merge (default: the current branch, or GITHUB_REF in Actions)")
    .option("--tool <name>", "Name the tool shown in GitHub")
    .option("--include-out-of-scope", "Also send findings the declared scope (0security scan --scope) labelled out of scope; they are skipped by default")
    .option("--no-wait", "Return when GitHub has accepted the upload instead of waiting for it to be processed")
    .option("--format <format>", "Output: text or json", "text")
    .action(async (file: string, options: UploadOptions) => {
      try {
        if (isServerTarget(options.to)) {
          const sent = await runServerUpload(options.includeOutOfScope ? deps.readText(file) : withoutOutOfScope(deps.readText(file)).text, { ...options, to: options.to! }, { ...(deps.fetch ? { fetch: deps.fetch as never } : {}), ...(deps.env ? { env: deps.env } : {}), git: deps.git ?? serverUploadDefaults.git });
          if (options.format === "json") deps.out(JSON.stringify(sent));
          else deps.out(sent.alreadyImported ? `Already sent: this exact file was uploaded before (${sent.total} finding${sent.total === 1 ? "" : "s"} for ${sent.repo}).` : `Sent ${sent.total} finding${sent.total === 1 ? "" : "s"} for ${sent.repo}: ${sent.created} new, ${sent.known} already known.`);
          return;
        }
        if (options.to === "jira-cloud" || options.to === "jira-dc") {
          const jira = await runJiraExport(file, { to: options.to, ...(options.jiraProject ? { project: options.jiraProject } : {}), ...(options.jiraIssueType ? { issueType: options.jiraIssueType } : {}), ...(options.jiraLabel ? { labels: options.jiraLabel } : {}), ...(options.jiraMinSeverity ? { minSeverity: options.jiraMinSeverity as JiraSeverity } : {}), ...(options.url ? { url: options.url } : {}), ...(options.dryRun ? { dryRun: true } : {}), ...(options.allowInsecureHttp ? { allowInsecureHttp: true } : {}) },
            { env: deps.env ?? process.env, fetch: deps.fetch ?? ((url, init) => fetch(url, init)), readText: deps.readText });
          if (options.format === "json") deps.out(JSON.stringify(jira, null, 2));
          else if (jira.dryRun) { deps.out(`Dry run: ${jira.planned!.length} Jira issue(s) would be created; ${jira.skipped} suppressed, fixed or false-positive finding(s) skipped${jira.belowMinimum ? `; ${jira.belowMinimum} below --jira-min-severity left out` : ""}. Nothing was sent.`); for (const issue of jira.planned!) deps.out(`  [${issue.labels[1]}] ${issue.summary} (${issue.label})`); }
          else deps.out(`Jira: created ${jira.created.length} issue(s)${jira.created.length ? ` (${jira.created.map(c => c.key).join(", ")})` : ""}; ${jira.existing.length} already had one (${jira.existing.map(e => e.key).join(", ") || "none"}); ${jira.skipped} suppressed, fixed or false-positive finding(s) skipped${jira.belowMinimum ? `; ${jira.belowMinimum} below --jira-min-severity left out` : ""}.`);
          return;
        }
        if (options.to && options.to !== "github") {
          const posted = await runBitbucketUpload(file, options, deps);
          if (!posted.published) return;
          if (options.format === "json") deps.out(JSON.stringify(posted));
          else deps.out(`Published ${posted.emitted} of ${posted.total} finding(s) to Bitbucket Code Insights.`);
          return;
        }
        const result = await runUpload(file, options, deps);
        if (!result) return;
        if (options.format === "json") deps.out(JSON.stringify(result));
        else deps.out(result.status === "complete" ? `Uploaded and processed (${result.id}). The alerts are in the repository's Security tab.` : `Uploaded (${result.id}); GitHub is still processing it.`);
      } catch (error) { finishWithError(error, { err: deps.err }, options.format === "json"); }
    });
}
