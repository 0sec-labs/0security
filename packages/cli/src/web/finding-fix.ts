// What the finding detail page shows about where a finding is and what `findings fix` recorded for it.
// Everything comes from stored data: the finding's own review annotation and the fix state file. The only
// other read is a local `git diff` of the recorded fix branch, which never touches the network.
import { execFile } from "node:child_process";
import { statSync } from "node:fs";
import { isAbsolute } from "node:path";
import { promisify } from "node:util";
import { parseFindingReviewAnnotation } from "@0/engine/storage";
import { shortFindingId } from "../finding-id.js";
import { fileStore, type FindingRecord, type StateStore } from "../commands/burndown.js";
import type { TargetFilter } from "./findings-scope.js";

const exec = promisify(execFile);
export const MAX_DIFF_BYTES = 200_000;
const MAX_RECORDS = 3;
const MAX_PATH = 500;
const BRANCH = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,100}$/;

export interface FindingLocation { path: string; startLine: number; endLine?: number; suggestion?: string }
export interface FindingFixRecord {
  branch: string | null;
  /** The run's result: pr-opened, pr-updated or committed. A run that changed nothing is not shown. */
  result: string;
  pullRequestUrl: string | null;
  /** How the pull request was opened. Merged and closed are not recorded, so they are not shown. */
  draft: boolean | null;
  /** The checks you named with --test when the fix ran, on that machine. This is not the code host's CI. */
  checksPassing: boolean | null;
  recordedAt: string;
  /** The fix commit as a unified diff, read from the local branch. Absent when the branch is gone or has more than one commit. */
  diff?: string;
  diffTruncated?: boolean;
}
export interface FindingFixInfo { records: FindingFixRecord[]; command: string }

/** The cited source location of the newest row that has one. The file itself is never read. */
export function locationOf(rows: Array<{ reviewAnnotation?: unknown }>): FindingLocation | null {
  for (const row of rows) {
    const note = parseFindingReviewAnnotation(row.reviewAnnotation);
    if (!note || typeof note.startLine !== "number" || !Number.isSafeInteger(note.startLine) || note.startLine < 1) continue;
    const endLine = typeof note.endLine === "number" && Number.isSafeInteger(note.endLine) && note.endLine >= note.startLine ? note.endLine : undefined;
    return {
      path: note.path.slice(0, MAX_PATH), startLine: note.startLine, ...(endLine !== undefined ? { endLine } : {}),
      ...(typeof note.suggestion === "string" && note.suggestion ? { suggestion: note.suggestion.slice(0, 4000) } : {}),
    };
  }
  return null;
}

const GIT_ENV = { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_OPTIONAL_LOCKS: "0", GIT_CONFIG_NOSYSTEM: "1" };
const git = (repo: string, args: string[], maxBuffer = 64_000) =>
  exec("git", ["-C", repo, "-c", "core.fsmonitor=false", "-c", "core.pager=cat", ...args], { timeout: 5_000, maxBuffer, env: GIT_ENV, encoding: "utf8" });

/** The one commit `findings fix` made on its branch, against its parent. Nothing else is read and nothing leaves the machine. */
export async function readFixDiff(repo: string, branch: string): Promise<{ diff: string; truncated: boolean } | null> {
  if (!isAbsolute(repo) || !BRANCH.test(branch) || branch.includes("..") || branch.endsWith(".lock")) return null;
  try {
    if (!statSync(repo).isDirectory()) return null;
    const tip = (await git(repo, ["rev-parse", "--verify", "--quiet", `refs/heads/${branch}^{commit}`])).stdout.trim();
    const parents = (await git(repo, ["rev-list", "--parents", "-n", "1", tip])).stdout.trim().split(" ").slice(1);
    if (parents.length !== 1 || !/^[0-9a-f]{40,64}$/.test(parents[0]!)) return null;
    try {
      const out = await git(repo, ["diff", "--no-ext-diff", "--no-textconv", "--no-color", "--no-renames", "--unified=3", parents[0]!, tip, "--"], MAX_DIFF_BYTES);
      return { diff: out.stdout, truncated: false };
    } catch (error) {
      const partial = (error as { code?: string; stdout?: string });
      if (partial.code !== "ERR_CHILD_PROCESS_STDIO_MAXBUFFER" || typeof partial.stdout !== "string") return null;
      return { diff: partial.stdout.slice(0, partial.stdout.lastIndexOf("\n") + 1), truncated: true };
    }
  } catch { return null; }
}

const safeUrl = (text: string | undefined): string | null => {
  if (!text) return null;
  try { const url = new URL(text); return url.protocol === "https:" || url.protocol === "http:" ? url.href : null; } catch { return null; }
};

/**
 * Fix records for one finding, newest first. A scoped account only gets records of repositories inside its scope
 * and never sees a repository path.
 */
export async function findingFixInfo(fingerprint: string, findingId: string, scope?: TargetFilter, store: StateStore = fileStore()): Promise<FindingFixInfo> {
  const command = `0security findings fix ${shortFindingId(findingId)}`;
  let state;
  try { state = store.load(); } catch { return { records: [], command }; }
  const matches = Object.entries(state.findings)
    .map(([key, record]) => ({ repo: key.split("\u0000")[0] ?? "", fp: key.split("\u0000")[1], record: record as FindingRecord }))
    .filter(entry => entry.fp === fingerprint && entry.repo && (entry.record.result === "pr-opened" || entry.record.result === "pr-updated" || entry.record.result === "committed"))
    .filter(entry => !scope || scope(entry.repo))
    .sort((a, b) => String(b.record.updatedAt).localeCompare(String(a.record.updatedAt)))
    .slice(0, MAX_RECORDS);
  const records: FindingFixRecord[] = [];
  for (const { repo, record } of matches) {
    const branch = typeof record.branch === "string" && BRANCH.test(record.branch) ? record.branch : null;
    const diff = branch ? await readFixDiff(repo, branch) : null;
    records.push({
      branch, result: record.result, pullRequestUrl: safeUrl(record.pullRequestUrl),
      draft: typeof record.draft === "boolean" ? record.draft : null, checksPassing: typeof record.checksPassing === "boolean" ? record.checksPassing : null,
      recordedAt: String(record.updatedAt), ...(diff ? { diff: diff.diff, diffTruncated: diff.truncated } : {}),
    });
  }
  return { records, command };
}
