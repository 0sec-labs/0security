import type { FindingFixRecord, FindingLocation } from "@/types";

/** `path:line` or `path:start-end`, the form editors and terminals open. */
export function locationText(location: FindingLocation): string {
  return `${location.path}:${location.startLine}${location.endLine && location.endLine > location.startLine ? `-${location.endLine}` : ""}`;
}

/** The pull request line. A pull request is only ever recorded as draft or ready; merged and closed are not stored. */
export function pullRequestLabel(record: FindingFixRecord): string {
  if (!record.pullRequestUrl) return record.result === "committed" ? "Committed on the branch, no pull request" : "No pull request recorded";
  const kind = record.draft === null ? "Pull request" : record.draft ? "Draft pull request" : "Pull request ready for review";
  return `${kind}, as recorded when the fix ran`;
}

/** Local checks only: the ones named with --test when the fix ran. */
export function checksLabel(record: FindingFixRecord): string {
  return record.checksPassing === null ? "No checks recorded" : record.checksPassing ? "Local checks passed" : "Local checks failed";
}

/** Only https and http links are ever rendered as links. */
export function safePullRequestHref(url: string | null): string | null {
  if (!url) return null;
  try { const parsed = new URL(url); return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.href : null; } catch { return null; }
}

export type DiffLineKind = "add" | "remove" | "hunk" | "meta" | "context";
export type DiffLine = { kind: DiffLineKind; text: string };

/** Classify each line of a unified diff so the view can mark it with more than color. */
export function parseDiff(diff: string): DiffLine[] {
  let inHunk = false;
  return diff.replace(/\n$/, "").split("\n").map(text => {
    if (text.startsWith("diff --git")) { inHunk = false; return { kind: "meta", text }; }
    if (text.startsWith("@@")) { inHunk = true; return { kind: "hunk", text }; }
    if (!inHunk) return { kind: "meta", text };
    if (text.startsWith("+")) return { kind: "add", text };
    if (text.startsWith("-")) return { kind: "remove", text };
    return { kind: "context", text };
  });
}
