/** A small .gitignore reader: enough of the format to skip what a repository ignores, with no git process. */
export interface IgnoreRule { negate: boolean; dirOnly: boolean; pattern: GlobPattern; /** Directory (relative, no trailing slash) that holds the .gitignore the rule came from. */ base: string }

/**
 * One compiled glob. A .gitignore comes from the repository being scanned, so a pattern such as `*a*a*a*a*a*a*b` must not be
 * able to stall the walk: a backtracking regular expression takes exponential time on it, and this matcher runs the pattern as
 * a set of states over the path, which takes time proportional to the path length times the pattern length.
 */
export interface GlobPattern { test(path: string): boolean }

type Token =
  | { kind: "char"; char: string }
  | { kind: "one" } // `?`: one character other than `/`
  | { kind: "class"; re: RegExp } // `[...]`: one character
  | { kind: "star" } // `*`: any run of characters other than `/`
  | { kind: "any" } // `**`: any run of characters
  | { kind: "dirs" }; // `**/`: nothing, or any run of characters that ends in `/`

/** Patterns longer than this are skipped: no real .gitignore needs one, and each costs time on every path the walk visits. */
const MAX_PATTERN = 1024;

function tokenize(glob: string, anchored: boolean): Token[] {
  const tokens: Token[] = anchored ? [] : [{ kind: "dirs" }];
  const push = (token: Token): void => {
    const last = tokens[tokens.length - 1];
    // Adjacent stars match what one of them matches, so a run of them costs no more than one.
    if (token.kind === "star" && (last?.kind === "star" || last?.kind === "any")) return;
    if (token.kind === "any" && last?.kind === "star") { tokens[tokens.length - 1] = token; return; }
    if (token.kind === "any" && last?.kind === "any") return;
    tokens.push(token);
  };
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === "*") {
      if (glob[i + 1] === "*") {
        i++;
        if (glob[i + 1] === "/") { i++; push({ kind: "dirs" }); } else push({ kind: "any" });
      } else push({ kind: "star" });
    } else if (c === "?") push({ kind: "one" });
    else if (c === "[") {
      const end = glob.indexOf("]", i + 1);
      if (end > i + 1) { push({ kind: "class", re: new RegExp(`^[${glob.slice(i + 1, end).replace(/^!/, "^").replace(/\\/g, "\\\\")}]$`) }); i = end; } else push({ kind: "char", char: "[" });
    } else push({ kind: "char", char: c });
  }
  return tokens;
}

function compileGlob(glob: string, anchored: boolean): GlobPattern {
  const tokens = tokenize(glob, anchored);
  const size = tokens.length;
  // at[i]: the match can stand before token i. inside[i]: it is partway through the run that a `**/` token i consumes.
  let at = new Uint8Array(size + 1), inside = new Uint8Array(size);
  let nextAt = new Uint8Array(size + 1), nextInside = new Uint8Array(size);
  /** Tokens that can match nothing let the match move past them without reading a character. */
  const skipEmpty = (states: Uint8Array): void => {
    for (let i = 0; i < size; i++) { const kind = tokens[i]!.kind; if (states[i] && (kind === "star" || kind === "any" || kind === "dirs")) states[i + 1] = 1; }
  };
  return {
    test(path: string): boolean {
      at.fill(0); inside.fill(0);
      at[0] = 1; skipEmpty(at);
      for (let p = 0; p < path.length; p++) {
        const ch = path[p]!;
        nextAt.fill(0); nextInside.fill(0);
        let live = false;
        for (let i = 0; i < size; i++) {
          const token = tokens[i]!;
          if (inside[i]) { nextInside[i] = 1; if (ch === "/") nextAt[i + 1] = 1; live = true; }
          if (!at[i]) continue;
          switch (token.kind) {
            case "char": if (ch === token.char) { nextAt[i + 1] = 1; live = true; } break;
            case "one": if (ch !== "/") { nextAt[i + 1] = 1; live = true; } break;
            case "class": if (token.re.test(ch)) { nextAt[i + 1] = 1; live = true; } break;
            case "star": if (ch !== "/") { nextAt[i] = 1; live = true; } break;
            case "any": nextAt[i] = 1; live = true; break;
            case "dirs": nextInside[i] = 1; if (ch === "/") nextAt[i + 1] = 1; live = true; break;
          }
        }
        if (!live) return false;
        skipEmpty(nextAt);
        [at, nextAt] = [nextAt, at];
        [inside, nextInside] = [nextInside, inside];
      }
      return at[size] === 1;
    },
  };
}

/** `line` without trailing whitespace, keeping one space or tab that a backslash escapes. Linear, unlike a regex with `\s+$`. */
function trimTrailing(line: string): string {
  let end = line.length;
  while (end > 0 && /\s/.test(line[end - 1]!)) end--;
  if (end < line.length && end > 0 && line[end - 1] === "\\") end++;
  return line.slice(0, end);
}

/** The rules in one .gitignore file, with `base` the folder that holds it. */
export function parseGitignore(text: string, base = ""): IgnoreRule[] {
  const rules: IgnoreRule[] = [];
  for (const raw of text.split(/\r?\n/)) {
    let line = trimTrailing(raw);
    if (!line || line.startsWith("#") || line.length > MAX_PATTERN) continue;
    let negate = false;
    if (line.startsWith("!")) { negate = true; line = line.slice(1); }
    line = line.replace(/^\\(?=[#!])/, "");
    let dirOnly = false;
    if (line.endsWith("/")) { dirOnly = true; line = line.slice(0, -1); }
    if (!line) continue;
    const anchored = line.includes("/");
    line = line.replace(/^\//, "");
    try { rules.push({ negate, dirOnly, pattern: compileGlob(line, anchored), base }); } catch { /* an unreadable pattern is skipped */ }
  }
  return rules;
}

/** Whether `path` (relative to the scan root, forward slashes) is ignored: the last rule that matches decides. */
export function isIgnored(rules: readonly IgnoreRule[], path: string, isDir: boolean): boolean {
  let ignored = false;
  for (const rule of rules) {
    if (rule.dirOnly && !isDir) continue;
    let relative = path;
    if (rule.base) { if (!path.startsWith(`${rule.base}/`)) continue; relative = path.slice(rule.base.length + 1); }
    if (rule.pattern.test(relative)) ignored = !rule.negate;
  }
  return ignored;
}
