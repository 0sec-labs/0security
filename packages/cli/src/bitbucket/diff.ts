/**
 * Reads a unified diff (git format, as both Bitbucket products return it) into the files it touches and the lines of
 * the new file a comment can attach to. Pure.
 */

export type LineKind = "ADDED" | "CONTEXT";

export interface ChangedFile {
  path: string;
  /** Line number in the new file to the kind of line it is. Removed lines have no place in the new file. */
  lines: Map<number, LineKind>;
}

const safePath = (path: string): boolean => /^[\w./@+ -]{1,300}$/.test(path) && !path.startsWith("/") && !path.split("/").includes("..");

/** Files changed by the diff. Deleted files and binary files are left out; so are paths with unusual characters. */
export function parseDiff(diff: string): ChangedFile[] {
  const files: ChangedFile[] = [];
  let current: ChangedFile | undefined;
  let next = 0;
  let inHunk = false;
  for (const line of diff.split("\n")) {
    if (line.startsWith("diff --git ")) { current = undefined; inHunk = false; continue; }
    if (!inHunk && line.startsWith("+++ ")) {
      const target = line.slice(4).split("\t")[0]!.trim();
      if (target === "/dev/null") { current = undefined; continue; }
      const path = target.startsWith("b/") ? target.slice(2) : target;
      current = safePath(path) ? { path, lines: new Map() } : undefined;
      if (current) files.push(current);
      continue;
    }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
    if (hunk) { next = Number(hunk[1]); inHunk = true; continue; }
    if (!inHunk || !current) continue;
    if (line.startsWith("\\") || line.startsWith("-")) continue;
    if (line.startsWith("+")) current.lines.set(next++, "ADDED");
    else if (line.startsWith(" ")) current.lines.set(next++, "CONTEXT");
    else inHunk = false;
  }
  return files;
}
