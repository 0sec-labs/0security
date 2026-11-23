/**
 * Which source files a scan thread opened. The model does not open every file, and a file it never opened was not reviewed.
 * The check reads the thread's tool calls (the inputs only, not what came back, so a listing does not count as opening):
 * the shell commands that read a file (`cat`, `sed`, `head`, `grep file`, a `python` one-liner with `open()`), a read tool
 * with a path, a shell glob, a bulk read such as `find ... | xargs cat`, and a task handed to a worker thread that names the file. It is a heuristic and errs towards "opened",
 * so a thread is not asked again about a file it did read in a way the check does not know.
 */
import { closeSync, openSync, readSync, statSync } from "node:fs";
import { join, posix } from "node:path";
import { buildInventory } from "@0/engine";

export interface ReviewDepth {
  /** Source files the inventory found in the folder (or in the changed files). */
  sourceFiles: number;
  /** How many of them a tool call of the thread named. */
  opened: number;
  /** The source files no tool call named (at most 25). */
  notOpened: string[];
}

type Json = Record<string, unknown>;

/** Files above this size are not part of the review a thread is asked to finish: reading them whole is not expected. */
export const MAX_REVIEW_FILE_BYTES = 200 * 1024;

/** One tool call per line: the tool name, a tab, and the input as JSON (the inputs only, not what came back). */
export function toolCallText(snapshot: Json): string {
  const messages = Array.isArray(snapshot.messages) ? snapshot.messages as Json[] : [];
  const parts: string[] = [];
  for (const message of messages) {
    if (message.role !== "assistant" || !Array.isArray(message.content)) continue;
    for (const block of message.content as Json[]) if (block.type === "tool_use" && block.input !== undefined) parts.push(`${typeof block.name === "string" ? block.name.replace(/\s+/g, "_") : ""}\t${JSON.stringify(block.input)}`);
  }
  return parts.join("\n");
}

const READERS = new Set([
  "cat", "tac", "nl", "head", "tail", "less", "more", "bat", "batcat", "sed", "awk", "gawk", "grep", "egrep", "fgrep", "rg", "ag", "ack", "jq", "yq", "strings", "xxd", "od", "fold", "pr", "view", "vi", "vim", "nano", "highlight", "pygmentize",
]);
const LISTERS_TOOL = /(^|_)(ls|list|glob|find|tree|search_files|file_search|dir)/i;
const SEARCHERS = new Set(["grep", "egrep", "fgrep", "rg", "ag", "ack"]);
const INTERPRETERS = /^(python[\d.]*|node|nodejs|deno|bun|ruby|perl|php)$/;
const READ_CALL = /\bopen\s*\(|read_text|read_bytes|readFileSync|readFile\b|fs\.read|File\.read|file_get_contents|\.read\(\)|readlines|createReadStream|Deno\.readTextFile/;
const WALK_CALL = /os\.walk|rglob|glob\.glob|\.glob\(|readdirSync|readdir\(|walkSync|Dir\.glob|find\.|fs\.glob|opendir/;

/** Split into words, keeping quoted text together and dropping the quotes. Redirections and separators end a word. */
function words(text: string): string[] {
  const out: string[] = [];
  let current = "";
  let quote = "";
  let active = false;
  for (let index = 0; index < text.length; index++) {
    const ch = text[index]!;
    if (quote) { if (ch === quote) quote = ""; else if (ch === "\\" && quote === "\"" && index + 1 < text.length) current += text[++index]; else current += ch; continue; }
    if (ch === "'" || ch === "\"") { quote = ch; active = true; continue; }
    if (ch === "\\" && index + 1 < text.length) { current += text[++index]; active = true; continue; }
    if (/\s/.test(ch)) { if (active) out.push(current); current = ""; active = false; continue; }
    current += ch; active = true;
  }
  if (active) out.push(current);
  return out;
}

/** Break a command line into simple commands at `;`, `&&`, `||`, `|`, newlines, `(`, `)`, `$(` and backticks (outside quotes). */
function segments(command: string): string[] {
  const out: string[] = [];
  let current = "";
  let quote = "";
  for (let index = 0; index < command.length; index++) {
    const ch = command[index]!;
    if (quote) { current += ch; if (ch === quote) quote = ""; else if (ch === "\\" && quote === "\"") current += command[++index] ?? ""; continue; }
    if (ch === "'" || ch === "\"") { quote = ch; current += ch; continue; }
    if (ch === "\\" && index + 1 < command.length) { current += ch + command[++index]!; continue; }
    if (";|&\n()`".includes(ch)) { if (current.trim()) out.push(current.trim()); current = ""; continue; }
    current += ch;
  }
  if (current.trim()) out.push(current.trim());
  return out;
}

function expandBraces(word: string): string[] {
  const match = /\{([^{}]*,[^{}]*)\}/.exec(word);
  if (!match) return [word];
  return match[1]!.split(",").flatMap(option => expandBraces(word.slice(0, match.index) + option + word.slice(match.index + match[0].length)));
}

const hasGlob = (word: string): boolean => /[*?]|\[[^\]]+\]/.test(word);

function globRegExp(glob: string, lenient: boolean): RegExp {
  const source = glob.replace(/[.+^${}()|\\]/g, "\\$&").replace(/\*\*\//g, "\u0000").replace(/\*\*/g, "\u0001").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]").replace(/\u0000/g, "(?:.*/)?").replace(/\u0001/g, ".*");
  return new RegExp(`^${lenient ? "(?:.*/)?" : ""}${source}$`);
}

/** Which scope files an operand names, as a path or a glob, relative to the current directory of the command. */
class Matcher {
  private readonly byBase = new Map<string, string[]>();
  constructor(readonly files: readonly string[], private readonly folder: string | undefined) {
    for (const file of files) { const base = file.slice(file.lastIndexOf("/") + 1); this.byBase.set(base, [...(this.byBase.get(base) ?? []), file]); }
  }

  /** The operand as a path relative to the folder, or undefined when it points outside of it in a way that cannot be read. */
  normalize(operand: string, cwd: string): string {
    let path = operand.replace(/^file:\/\//, "").replace(/[.,;:]+$/, "");
    if (this.folder) {
      const folder = this.folder.replace(/\/+$/, "");
      if (path === folder) return "";
      if (path.startsWith(`${folder}/`)) path = path.slice(folder.length + 1);
      else if (!path.startsWith("/") && !path.startsWith("~")) path = posix.join(cwd, path);
    } else if (!path.startsWith("/")) path = posix.join(cwd, path);
    return posix.normalize(path).replace(/^\.\//, "").replace(/\/+$/, "");
  }

  named(operand: string, cwd: string, into: Set<string>): void {
    if (!operand || operand.startsWith("-") || operand === "." || operand === "..") return;
    for (const word of expandBraces(operand)) {
      if (hasGlob(word)) {
        const path = this.normalize(word, cwd);
        const strict = globRegExp(path, false);
        const loose = path.includes("/") ? globRegExp(path.replace(/^\/+/, ""), true) : strict;
        for (const file of this.files) if (strict.test(file) || loose.test(file)) into.add(file);
        continue;
      }
      const path = this.normalize(word, cwd);
      if (!path) continue;
      // A file by its path from the folder; a longer path (another root for the same folder) or a shorter one (a different
      // current directory) is taken as the same file when one is the end of the other.
      for (const file of this.byBase.get(path.slice(path.lastIndexOf("/") + 1)) ?? []) if (file === path || path.endsWith(`/${file}`) || file.endsWith(`/${path}`)) into.add(file);
    }
  }

  /** The files under a directory, or in it only, that a `find` or `ls` listing would name. */
  under(root: string, cwd: string, recursive: boolean, name?: RegExp[]): string[] {
    const dir = root === "." || root === "" ? cwd : this.normalize(root, cwd);
    const prefix = dir && dir !== "." ? `${dir}/` : "";
    return this.files.filter(file => (prefix === "" || file.startsWith(prefix)) && (recursive || !file.slice(prefix.length).includes("/")) && (!name?.length || name.some(pattern => pattern.test(file.slice(file.lastIndexOf("/") + 1)))));
  }
}

/** The files that the producer commands of a bulk read (`find`, `git ls-files`, `ls`, `rg --files`) list. */
function listedFiles(segment: string[], matcher: Matcher, cwd: string): string[] {
  const command = posix.basename(segment[0] ?? "");
  const rest = segment.slice(1);
  if (command === "find") {
    const roots: string[] = [];
    for (const word of rest) { if (word.startsWith("-") || word === "(" || word === "!") break; roots.push(word); }
    const names: RegExp[] = [];
    for (let index = 0; index < rest.length; index++) if (/^-i?name$/.test(rest[index]!) && rest[index + 1]) names.push(...expandBraces(rest[index + 1]!).map(word => globRegExp(word, false)));
    return (roots.length ? roots : ["."]).flatMap(root => matcher.under(root, cwd, true, names));
  }
  if (command === "git" && rest.includes("ls-files")) {
    const specs = rest.slice(rest.indexOf("ls-files") + 1).filter(word => !word.startsWith("-"));
    if (!specs.length) return matcher.under(".", cwd, true);
    const found = new Set<string>();
    for (const spec of specs) { matcher.named(spec, cwd, found); for (const file of matcher.under(spec, cwd, true)) found.add(file); }
    return [...found];
  }
  if (command === "rg" && rest.includes("--files")) return matcher.under(rest.filter(word => !word.startsWith("-")).at(-1) ?? ".", cwd, true);
  if (command === "ls") {
    const recursive = rest.some(word => /^-[a-zA-Z]*R/.test(word));
    const dirs = rest.filter(word => !word.startsWith("-"));
    return (dirs.length ? dirs : ["."]).flatMap(dir => matcher.under(dir, cwd, recursive));
  }
  return [];
}

const VALUE_FLAGS: Record<string, ReadonlySet<string>> = {
  head: new Set(["-n", "-c"]), tail: new Set(["-n", "-c"]), nl: new Set(["-b", "-n", "-w", "-s", "-v", "-i"]),
  grep: new Set(["-e", "-f", "-m", "-A", "-B", "-C", "-d", "-D"]), egrep: new Set(["-e", "-f", "-m", "-A", "-B", "-C"]), fgrep: new Set(["-e", "-f", "-m", "-A", "-B", "-C"]),
  rg: new Set(["-e", "-f", "-m", "-A", "-B", "-C", "-g", "-t", "-T", "-j", "-M", "--glob", "--type", "--type-not", "--max-count", "--regexp", "--file", "--iglob", "--max-depth", "-d"]),
  ag: new Set(["-G", "-g", "-m", "-A", "-B", "-C", "--ignore"]), ack: new Set(["-A", "-B", "-C", "-m", "--type"]),
  sed: new Set(["-e", "-f", "-l", "--expression", "--file"]), awk: new Set(["-F", "-v", "-f"]), gawk: new Set(["-F", "-v", "-f"]),
  bat: new Set(["-r", "-l", "-H", "--line-range", "--language", "--theme", "--style", "--highlight-line"]), batcat: new Set(["-r", "-l", "-H", "--line-range", "--language", "--theme", "--style"]),
  jq: new Set(["--arg", "--argjson", "-f", "--from-file"]),
};
/** Commands whose first operand is a pattern or a script, unless a flag gives it. */
const PATTERN_FIRST = new Set(["grep", "egrep", "fgrep", "rg", "ag", "ack", "sed", "awk", "gawk", "jq", "yq"]);
const GIVES_PATTERN = new Set(["-e", "-f", "--regexp", "--expression", "--file", "--from-file"]);

/** The file operands of a reader command: its words without flags, flag values and the pattern or script. */
function operands(name: string, args: string[]): string[] {
  const takesValue = VALUE_FLAGS[name] ?? new Set<string>();
  const out: string[] = [];
  let patternGiven = !PATTERN_FIRST.has(name) || args.some(word => GIVES_PATTERN.has(word) || /^-[a-zA-Z]*[ef]$/.test(word));
  for (let index = 0; index < args.length; index++) {
    const word = args[index]!;
    if (word === "--") { out.push(...args.slice(index + 1)); break; }
    if (word.startsWith("-") && word !== "-") { if (takesValue.has(word)) index++; continue; }
    if (!patternGiven) { patternGiven = true; continue; }
    out.push(word);
  }
  return out;
}

/** The source files that one shell command reads. */
function openedByCommand(command: string, matcher: Matcher, into: Set<string>): void {
  const parts = segments(command).map(words);
  let cwd = "";
  const readerWords = (part: string[]): boolean => part.some(word => READERS.has(posix.basename(word)));
  const bulkFeeds = /(?:\bxargs\b|-exec(?:dir)?\b|\bwhile\s+read\b|\$\(|`)/.test(command) && parts.some(readerWords);
  for (const part of parts) {
    let index = 0;
    while (index < part.length && /^(?:[A-Za-z_][A-Za-z0-9_]*=.*|sudo|env|command|time|nice|exec|builtin)$/.test(part[index]!)) index++;
    const head = part.slice(index);
    const name = posix.basename(head[0] ?? "");
    if (name === "cd") { const target = head[1]; if (target && !target.startsWith("-")) { const to = matcher.normalize(target, cwd); cwd = to === "." ? "" : to; } continue; }
    if (name === "for") {
      // for f in routes/*.js app.js; do cat "$f"; done: the list is what the loop reads.
      const at = head.indexOf("in");
      if (at > 0 && parts.some(readerWords)) for (const word of head.slice(at + 1)) if (word !== "do") matcher.named(word, cwd, into);
      continue;
    }
    if (READERS.has(name)) {
      // A recursive search over a directory is a search, not a read: only named files and globs count.
      for (const word of operands(name, head.slice(1))) matcher.named(word, cwd, into);
      if (SEARCHERS.has(name)) continue;
    } else if (name === "xargs" || name === "git" || INTERPRETERS.test(name)) {
      // `xargs cat file-list`, `git show REV:path`: the paths it names are read.
      if (name === "xargs" && head.slice(1).some(word => READERS.has(posix.basename(word)))) for (const word of head.slice(1)) matcher.named(word, cwd, into);
      if (name === "git") for (const word of head.slice(1)) { const at = word.indexOf(":"); if (at > 0 && /^(show|cat-file)$/.test(head[1] ?? "")) matcher.named(word.slice(at + 1), cwd, into); }
    }
    if (bulkFeeds) for (const file of listedFiles(head, matcher, cwd)) into.add(file);
  }
  // An interpreter that opens files: every quoted path it names was opened, and a walk with a read opens the tree.
  if (parts.some(part => INTERPRETERS.test(posix.basename(part[0] ?? ""))) && READ_CALL.test(command)) {
    for (const match of command.matchAll(/[\w.@+~/-]*[./][\w.@+~/-]*/g)) matcher.named(match[0], cwd, into);
    if (WALK_CALL.test(command)) for (const file of matcher.files) into.add(file);
  }
}

/** The paths a tool's own input names, for a tool that reads a file by path (a read or view tool). */
function pathsOfInput(input: Json, tool: string, matcher: Matcher, into: Set<string>): void {
  if (LISTERS_TOOL.test(tool) && !/read|view|cat|open/i.test(tool)) return;
  for (const key of ["path", "file", "file_path", "filePath", "filepath", "filename", "target", "uri"]) {
    const value = input[key];
    if (typeof value === "string") matcher.named(value, "", into);
  }
  for (const key of ["paths", "files", "file_paths"]) {
    const value = input[key];
    if (Array.isArray(value)) for (const item of value) if (typeof item === "string") matcher.named(item, "", into);
  }
}

/** Which of `scopeFiles` the tool calls opened. `calls` is `toolCallText` output, or plain shell commands one per line. */
export function openedFiles(scopeFiles: readonly string[], calls: string, folder?: string): Set<string> {
  const matcher = new Matcher(scopeFiles, folder);
  const opened = new Set<string>();
  for (const line of calls.split("\n")) {
    if (!line.trim()) continue;
    const tab = line.indexOf("\t");
    const tool = tab > 0 && /^[\w.:-]*$/.test(line.slice(0, tab)) ? line.slice(0, tab) : "";
    const body = tab > 0 && tool !== "" || tab === 0 ? line.slice(tab + 1) : line;
    let input: unknown;
    try { input = JSON.parse(body); } catch { input = undefined; }
    // A task handed to a worker thread: the worker reads the files the task names, so they count as reviewed.
    if (/spawn|agent|worker|delegate/i.test(tool) && input && typeof input === "object") {
      for (const match of body.replace(/\\"/g, " ").matchAll(/[\w.@+~/-]*[./][\w.@+~/-]*/g)) matcher.named(match[0], "", opened);
      continue;
    }
    if (typeof input === "string") openedByCommand(input, matcher, opened);
    else if (input && typeof input === "object") {
      const json = input as Json;
      let ran = false;
      for (const key of ["command", "cmd", "script", "code"]) if (typeof json[key] === "string") { openedByCommand(json[key] as string, matcher, opened); ran = true; }
      if (Array.isArray(json.command) && json.command.every(item => typeof item === "string")) { openedByCommand((json.command as string[]).map(word => /[\s"'$*?]/.test(word) ? `'${word.replace(/'/g, "'\\''")}'` : word).join(" "), matcher, opened); ran = true; }
      if (!ran || typeof json.path === "string") pathsOfInput(json, tool, matcher, opened);
    } else openedByCommand(body, matcher, opened);
  }
  return opened;
}

/** The files in `scopeFiles` that no tool call opened, sorted. */
export function unopenedFiles(scopeFiles: readonly string[], calls: string, folder?: string): string[] {
  const opened = openedFiles(scopeFiles, calls, folder);
  return [...scopeFiles].filter(file => !opened.has(file)).sort();
}

const isText = (path: string): boolean => {
  try {
    const buffer = Buffer.alloc(4096);
    const fd = openSync(path, "r");
    try { return !buffer.subarray(0, readSync(fd, buffer, 0, buffer.length, 0)).includes(0); } finally { closeSync(fd); }
  } catch { return false; }
};

/**
 * The files a thread is expected to open: the inventory's source files (it already leaves out vendored, generated and ignored
 * files) minus files over 200 KB and binary files, which a model cannot be expected to read whole.
 */
export function reviewScopeFiles(folder: string, scope?: readonly string[]): string[] {
  const inventory = buildInventory(folder, scope ? { only: new Set(scope) } : {});
  const files = new Set<string>();
  for (const unit of inventory.units) { if (unit.files) for (const file of unit.files) files.add(file); else files.add(unit.path); }
  return [...files].sort().filter(file => {
    try { const full = join(folder, file); return statSync(full).size <= MAX_REVIEW_FILE_BYTES && isText(full); } catch { return false; }
  });
}

/** Which source files of `folder` the tool calls named, or undefined when the folder has no source files. */
export function reviewDepth(folder: string, calls: string, scope?: readonly string[]): ReviewDepth | undefined {
  const files = reviewScopeFiles(folder, scope);
  if (!files.length) return undefined;
  const notOpened = unopenedFiles(files, calls, folder);
  return { sourceFiles: files.length, opened: files.length - notOpened.length, notOpened: notOpened.slice(0, 25) };
}

/** The follow-up message that names the files a thread did not open. At most `limit` are named; the rest are counted. */
export function followUpText(unopened: readonly string[], limit = 40): string {
  const shown = unopened.slice(0, limit);
  return `You did not open these files:\n${shown.map(file => `- ${file}`).join("\n")}${unopened.length > shown.length ? `\n- and ${unopened.length - shown.length} more` : ""}\nOpen and review each one now, then add any findings and update your summary.`;
}

/** The warning for a scan that found nothing and did not open every source file, or undefined when it did. */
export function shallowReviewWarning(depth: ReviewDepth | undefined): string | undefined {
  if (!depth || !depth.notOpened.length) return undefined;
  const unopened = depth.sourceFiles - depth.opened;
  return `Shallow review: no findings, and the scan opened ${depth.opened} of ${depth.sourceFiles} source file${depth.sourceFiles === 1 ? "" : "s"}. Not opened: ${depth.notOpened.join(", ")}${unopened > depth.notOpened.length ? `, and ${unopened - depth.notOpened.length} more` : ""}. A scan that did not open the code says nothing about it; run it again or use --passes 2.`;
}
