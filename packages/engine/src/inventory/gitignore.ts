/** A small .gitignore reader: enough of the format to skip what a repository ignores, with no git process. */
export interface IgnoreRule { negate: boolean; dirOnly: boolean; regex: RegExp; /** Directory (relative, no trailing slash) that holds the .gitignore the rule came from. */ base: string }

function globToRegex(glob: string, anchored: boolean): RegExp {
  let out = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === "*") {
      if (glob[i + 1] === "*") {
        i++;
        if (glob[i + 1] === "/") { i++; out += "(?:.*/)?"; } else out += ".*";
      } else out += "[^/]*";
    } else if (c === "?") out += "[^/]";
    else if (c === "[") {
      const end = glob.indexOf("]", i + 1);
      if (end > i + 1) { out += `[${glob.slice(i + 1, end).replace(/^!/, "^").replace(/\\/g, "\\\\")}]`; i = end; } else out += "\\[";
    } else out += c.replace(/[.+^${}()|\\]/g, "\\$&");
  }
  return new RegExp(`${anchored ? "^" : "^(?:.*/)?"}${out}$`);
}

/** The rules in one .gitignore file, with `base` the folder that holds it. */
export function parseGitignore(text: string, base = ""): IgnoreRule[] {
  const rules: IgnoreRule[] = [];
  for (const raw of text.split(/\r?\n/)) {
    let line = raw.replace(/(?<!\\)\s+$/, "");
    if (!line || line.startsWith("#")) continue;
    let negate = false;
    if (line.startsWith("!")) { negate = true; line = line.slice(1); }
    line = line.replace(/^\\(?=[#!])/, "");
    let dirOnly = false;
    if (line.endsWith("/")) { dirOnly = true; line = line.slice(0, -1); }
    if (!line) continue;
    const anchored = line.includes("/");
    line = line.replace(/^\//, "");
    try { rules.push({ negate, dirOnly, regex: globToRegex(line, anchored), base }); } catch { /* an unreadable pattern is skipped */ }
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
    if (rule.regex.test(relative)) ignored = !rule.negate;
  }
  return ignored;
}
