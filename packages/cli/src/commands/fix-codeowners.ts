/**
 * Reviewers from a CODEOWNERS file, for fix pull requests. The file is read from the base branch as committed
 * (never the working tree), and only when the operator's policy turns it on. Owners must look like a user name or
 * an org/team; e-mail addresses and anything else are ignored. Nothing here is evaluated.
 */
import { isReviewerName, MAX_REVIEWERS } from "./fix-conventions.js";

/** Where GitHub looks for the file, in its order of precedence. */
export const CODEOWNERS_PATHS = [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"] as const;
const MAX_LINES = 5000;
const MAX_PATTERN_CHARS = 300;

/** Compiles one CODEOWNERS pattern (gitignore style) to a test on a repository-relative path. */
function matcher(pattern: string): ((path: string) => boolean) | undefined {
  if (!pattern || pattern.length > MAX_PATTERN_CHARS || pattern.startsWith("!") || /[\\\[\]]/.test(pattern)) return undefined;
  const anchored = pattern.startsWith("/") || pattern.slice(0, -1).includes("/");
  const directory = pattern.endsWith("/");
  const body = pattern.replace(/^\//, "").replace(/\/$/, "");
  if (!body) return undefined;
  let source = "";
  for (let i = 0; i < body.length; i++) {
    const c = body[i]!;
    if (c === "*" && body[i + 1] === "*") {
      const slashBefore = i === 0 || body[i - 1] === "/";
      const slashAfter = body[i + 2] === "/";
      if (slashBefore && slashAfter) { source += "(?:.*/)?"; i += 2; } else { source += ".*"; i += 1; }
    } else if (c === "*") source += "[^/]*";
    else if (c === "?") source += "[^/]";
    else source += c.replace(/[.+^${}()|]/g, "\\$&");
  }
  // A pattern also owns everything under a directory it names, but a wildcard in the last part names files only.
  const lastPart = body.slice(body.lastIndexOf("/") + 1);
  const tail = directory ? "/.*" : /[*?]/.test(lastPart) ? "" : "(?:/.*)?";
  const expression = new RegExp(`^${anchored ? "" : "(?:.*/)?"}${source}${tail}$`);
  return path => expression.test(path);
}

/** The owners of the last rule that matches `path`; empty when none does. Later lines win, as on GitHub. */
export function codeownersFor(text: string, path: string): string[] {
  const target = path.replace(/^\.?\//, "");
  let owners: string[] = [];
  for (const raw of text.split("\n").slice(0, MAX_LINES)) {
    const line = raw.replace(/\r$/, "").replace(/(^|\s)#.*$/, "").trim();
    if (!line || line.startsWith("[")) continue;
    const [pattern, ...rest] = line.split(/\s+/);
    const test = pattern ? matcher(pattern) : undefined;
    if (test?.(target)) owners = rest;
  }
  return owners;
}

/** User names and org/team slugs of the owners that can be asked for a review. */
export function reviewersFromCodeowners(text: string, path: string): string[] {
  const names = codeownersFor(text, path)
    .filter(owner => owner.startsWith("@"))
    .map(owner => owner.slice(1))
    .filter(isReviewerName);
  return [...new Set(names)].slice(0, MAX_REVIEWERS);
}
