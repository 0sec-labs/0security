/**
 * The code host seam. Commands that open pull requests, mirror issues or upload code-scanning results talk to a
 * `Host`, never to `gh` directly. GitHub is the only implementation today; another host implements this interface
 * and `selectHost` returns it.
 */
import { UsageError } from "../commands/output.js";
import { GitHubHost } from "./github.js";

export interface TrackerIssue { number: number; key: string; title: string; body: string; open: boolean; labels: string[] }
export interface IssueDraft { title: string; body: string; labels: string[] }

/** What the issues command needs from an issue tracker. */
export interface IssueTracker {
  /** Every issue this command manages (those carrying a finding marker). */
  list(): Promise<TrackerIssue[]>;
  /** Make sure the labels exist where possible; returns the ones that can be applied, and warnings for the rest. */
  ensureLabels(labels: string[]): Promise<{ usable: string[]; warnings: string[] }>;
  create(draft: IssueDraft): Promise<number>;
  update(issue: TrackerIssue, draft: IssueDraft): Promise<void>;
  /** Close the issue; `draft` is the closed-state text, so the body's status table stops saying open. */
  close(issue: TrackerIssue, comment: string, completed: boolean, draft?: IssueDraft): Promise<void>;
  reopen(issue: TrackerIssue, comment: string): Promise<void>;
}

export interface PullRequest { number: number; url: string; isDraft: boolean }

/** Where a pull request stands now: open, merged, or closed without merging. */
export interface PullRequestState { state: "open" | "merged" | "closed"; draft: boolean; commits: number }

export interface SarifUpload { commit: string; ref: string; /** gzip + base64 */ sarif: string; tool?: string }

/** Run the host's CLI with these arguments and an optional request body on standard input. */
export type HostRun = (args: string[], input?: string) => Promise<string>;

export interface PullRequestChecks { status: "passing" | "failing" | "pending" | "none"; url?: string }

export interface Host {
  readonly name: string;
  /** Whether `name` is a well-formed repository name for this host. */
  isValidRepo(name: string): boolean;
  /** The repository of the current clone, or "" when it cannot be told. */
  currentRepo(): Promise<string>;
  findOpenPullRequest(branch: string, base?: string): Promise<PullRequest | undefined>;
  /** Returns the new pull request's URL. */
  createPullRequest(input: { base: string; head: string; title: string; bodyFile: string; draft: boolean }): Promise<string>;
  updatePullRequestBody(number: number, bodyFile: string): Promise<void>;
  /** Mark ready for review, or back to draft. */
  setPullRequestReady(number: number, ready: boolean): Promise<void>;
  /** Add labels (which must already exist) and request reviewers (users or `org/team`). */
  editPullRequest(number: number, change: { addLabels?: string[]; addReviewers?: string[] }): Promise<void>;
  /** Read one pull request by its URL. */
  pullRequestState(url: string): Promise<PullRequestState>;
  pullRequestChecks?(url: string): Promise<PullRequestChecks>;
  pushBranch(branch: string): Promise<void>;
  issues(repo: string): IssueTracker;
  uploadSarif(repo: string, upload: SarifUpload): Promise<{ id?: string }>;
  sarifStatus(repo: string, id: string): Promise<{ processing_status?: string; errors?: string[] }>;
}

export interface HostOptions {
  /** Host to use; only "github" (the default) exists today. */
  host?: string;
  /** The host CLI runner. */
  run: HostRun;
  /** Runs git in the repository the host works on; needed by `pushBranch`. */
  git?: (args: string[]) => Promise<string>;
}

export function selectHost(options: HostOptions): Host {
  const wanted = options.host ?? "github";
  if (wanted !== "github") throw new UsageError(`Unsupported code host '${wanted}'; only github is supported.`);
  return new GitHubHost(options.run, options.git);
}
