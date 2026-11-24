/**
 * Text analysis for the protected-paths decider. Pure apart from the injected `real` function (symlink resolution).
 *
 * Question answered: does this command text, run in `cwd`, name anything under the 0 state directory that holds
 * approvals, enablement, grants, audit, settings or the database? Covered as far as TEXT analysis allows:
 * absolute paths, `~`, `$HOME`, `${HOME}`, `cd`/`pushd` followed by relative paths, `..` segments, redirects, tee,
 * cp/mv/ln, `sed -i`, paths inside quoted python/node one-liners, glob segments (`ext*`), and symlinks that exist
 * when the check runs.
 *
 * NOT covered (documented limit, the sandbox is the boundary): paths assembled at run time (string concatenation,
 * base64, `printf` into a variable, `eval`), symlinks created and used inside the same command, and anything read
 * from a file the command itself writes. See docs/design/command-hook-architecture.md.
 */
import { isAbsolute, join, resolve, sep } from "node:path";

/** First segments under `<home>/.0` that must not be touched by an agent. `0.db*` is matched by prefix. */
export const PROTECTED_STATE_NAMES: readonly string[] = [
  "extensions", "plugins", "plugin-enablement", "executable-plugins", "harness-trust", "evolution-authority",
  "tui-settings.json", "workbench.json", "workbench", "backends.json", "engines.json", "engines", "workers",
  "github-webhook-secret.json", "findings-api-access", "teams", "team-configs", "chatgpt-plan", "web-connections.json",
  "credentials.json", "access-upgrade.json", "access-token", "cloud.env", "AGENTS.md", "workspaces",
  "console-sessions", "skills-library", "engagements",
];
const isProtectedName = (name: string, caseInsensitive = false): boolean => {
  const n = caseInsensitive ? name.toLowerCase() : name;
  return PROTECTED_STATE_NAMES.some(entry => (caseInsensitive ? entry.toLowerCase() : entry) === n) || n === "0.db" || n.startsWith("0.db.");
};

export interface ProtectedPathContext {
  readonly home: string;
  readonly cwd: string;
  /** Resolve symlinks of the deepest existing ancestor; identity in pure tests. */
  readonly real?: (path: string) => string;
  /** One extension's own folder (an approved extension starting its own server): paths inside it, symlinks resolved, are not state. */
  readonly exemptDir?: string;
  /** Commands (not file writes) may name files inside an installed extension revision to run or read them. */
  readonly extensionFilesReadable?: boolean;
  /** Override filesystem case sensitivity for protected-state checks (defaults to true on win32/darwin). */
  readonly caseInsensitive?: boolean;
}

export interface ProtectedHit { readonly path: string; readonly reason: string }

const OPERATORS = new Set([";", "&", "|", "(", ")", "<", ">", "\n"]);
const ANSI_ESCAPES: Record<string, string> = { a: "\x07", b: "\b", e: "\x1b", E: "\x1b", f: "\f", n: "\n", r: "\r", t: "\t", v: "\v", "\\": "\\", "'": "'", '"': '"', "?": "?" };

function decodeAnsiC(command: string, start: number): { value: string; nextIndex: number } {
  let out = "";
  let i = start;
  while (i < command.length) {
    const ch = command[i]!;
    if (ch === "'") return { value: out, nextIndex: i + 1 };
    if (ch !== "\\" || i + 1 >= command.length) { out += ch; i++; continue; }
    const esc = command[i + 1]!;
    if (esc in ANSI_ESCAPES) { out += ANSI_ESCAPES[esc]!; i += 2; continue; }
    if (esc === "x" || esc === "u" || esc === "U") {
      const maxDigits = esc === "x" ? 2 : esc === "u" ? 4 : 8;
      const hex = new RegExp(`^[0-9A-Fa-f]{1,${maxDigits}}`).exec(command.slice(i + 2))?.[0];
      if (hex) {
        const cp = parseInt(hex, 16);
        out += cp <= 0x10ffff ? String.fromCodePoint(cp) : "";
        i += 2 + hex.length;
        continue;
      }
    }
    const oct = /^[0-7]{1,3}/.exec(command.slice(i + 1))?.[0];
    if (oct) { out += String.fromCharCode(parseInt(oct, 8) & 0xff); i += 1 + oct.length; continue; }
    out += esc;
    i += 2;
  }
  return { value: out, nextIndex: command.length };
}

/** Split a shell-ish command into words (quotes and escapes removed) and operator marks. No expansion. */
export function tokenize(command: string): Array<{ word: string } | { op: string }> {
  const out: Array<{ word: string } | { op: string }> = [];
  let cur = ""; let has = false; let i = 0;
  const flush = () => { if (has) out.push({ word: cur }); cur = ""; has = false; };
  while (i < command.length) {
    const c = command[i]!;
    if (c === "$" && command[i + 1] === "'") {
      const decoded = decodeAnsiC(command, i + 2);
      cur += decoded.value; has = true; i = decoded.nextIndex; continue;
    }
    if (c === "'") { const end = command.indexOf("'", i + 1); const stop = end < 0 ? command.length : end; cur += command.slice(i + 1, stop); has = true; i = stop + 1; continue; }
    if (c === '"') {
      i++; has = true;
      while (i < command.length && command[i] !== '"') { if (command[i] === "\\" && i + 1 < command.length) { cur += command[i + 1]; i += 2; } else cur += command[i++]; }
      i++; continue;
    }
    if (c === "\\" && i + 1 < command.length) { cur += command[i + 1]; has = true; i += 2; continue; }
    if (c === " " || c === "\t" || c === "\r") { flush(); i++; continue; }
    if (c === ">" && (command[i + 1] === "|" || command[i + 1] === ">")) { flush(); out.push({ op: c + command[i + 1]! }); i += 2; continue; }
    if (c === "<" && command[i + 1] === ">") { flush(); out.push({ op: "<>" }); i += 2; continue; }
    if (OPERATORS.has(c)) { flush(); out.push({ op: c }); i++; continue; }
    cur += c; has = true; i++;
  }
  flush();
  return out;
}

const expandHome = (text: string, home: string): string =>
  text.replace(/\$\{HOME\}|\$HOME(?![A-Za-z0-9_])/g, home).replace(/(^|[=:,'"(\s])~(?=\/|$)/g, (_m, pre: string) => `${pre}${home}`);

const GLOB = /[*?[]/;
const globRegex = (segment: string, caseInsensitive = false): RegExp => {
  const body = (text: string) => text.replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]");
  const flags = caseInsensitive ? "i" : "";
  try { return new RegExp(`^${body(segment.replace(/[.+^${}()|\\]/g, "\\$&"))}$`, flags); }
  // An unbalanced `[` is not a valid class; match it as text rather than fail.
  catch { return new RegExp(`^${body(segment.replace(/[.+^${}()|\\[\]]/g, "\\$&"))}$`, flags); }
};

function realOf(path: string, real: (p: string) => string): string {
  try { return real(path); } catch { return path; }
}

/** Is `path` (absolute, normalised, may contain glob segments) inside or equal to a protected location? */
function protectedReason(path: string, states: readonly string[], allowExtensionFiles = false, caseInsensitive = false): string | null {
  const segs = path.split(sep).filter(Boolean);
  for (const state of states) {
    const base = state.split(sep).filter(Boolean);
    if (segs.length <= base.length) continue;
    let prefixMatches = true;
    for (let i = 0; i < base.length; i++) {
      const s = segs[i]!;
      const b = base[i]!;
      if (caseInsensitive ? s.toLowerCase() === b.toLowerCase() : s === b) continue;
      if (GLOB.test(s) && globRegex(s, caseInsensitive).test(b)) continue;
      prefixMatches = false; break;
    }
    if (!prefixMatches) continue;
    const first = segs[base.length]!;
    // `extensions/<name>/<revision>/<file>`: a file inside one installed revision. Running or reading it is how an
    // enabled extension's script is used; approvals live in the root files (state.json, audit.jsonl, connections.json), and
    // an edited revision no longer matches its pin, so it is refused at load time.
    const isExtDir = caseInsensitive ? first.toLowerCase() === "extensions" : first === "extensions";
    if (allowExtensionFiles && isExtDir && segs.length >= base.length + 4) {
      const name = segs[base.length + 1]!;
      const rootMatched = caseInsensitive
        ? [...EXTENSION_ROOT_FILES].some(f => f.toLowerCase() === name.toLowerCase())
        : EXTENSION_ROOT_FILES.has(name);
      if (!name.startsWith(".") && !GLOB.test(name) && !rootMatched) continue;
    }
    if (GLOB.test(first)) {
      const re = globRegex(first, caseInsensitive);
      if ([...PROTECTED_STATE_NAMES, "0.db"].some(name => re.test(name))) return `${state}${sep}${first}`;
    } else if (isProtectedName(first, caseInsensitive)) return `${state}${sep}${first}`;
  }
  return null;
}

const EXTENSION_ROOT_FILES = new Set(["state.json", "audit.jsonl", "connections.json"]);
const WRITING_VERBS = /^(tee|sed|install|dd|touch)$/;
const DESTRUCTIVE = /^(rm|mv|chmod|chown|ln|cp|rsync|tar|find|truncate|shred|unlink|rmdir)$/;
const WRITE_OPS = new Set([">", ">>", ">|", "<>"]);

/** Find the first protected location the command names, or null. */
export function findProtectedPathUse(command: string, extraPaths: readonly string[], ctx: ProtectedPathContext): ProtectedHit | null {
  const real = ctx.real ?? (p => p);
  const caseInsensitive = ctx.caseInsensitive ?? (process.platform === "win32" || process.platform === "darwin");
  const baseState = resolve(ctx.home, ".0");
  const states = [...new Set([baseState, realOf(baseState, real)])];
  const exempt = ctx.exemptDir ? [...new Set([resolve(ctx.exemptDir), realOf(resolve(ctx.exemptDir), real)])] : [];
  const inside = (path: string, dir: string) => {
    const p = caseInsensitive ? path.toLowerCase() : path;
    const d = caseInsensitive ? dir.toLowerCase() : dir;
    return p === d || p.startsWith(d + sep);
  };
  const check = (candidate: string, cwd: string, readOnly = false): ProtectedHit | null => {
    if (!candidate) return null;
    const expanded = expandHome(candidate, ctx.home);
    const abs = isAbsolute(expanded) ? resolve(expanded) : resolve(cwd, expanded);
    if (exempt.length && exempt.some(dir => inside(abs, dir)) && exempt.some(dir => inside(realOf(abs, real), dir))) return null;
    for (const variant of new Set([abs, realOf(abs, real)])) {
      const why = protectedReason(variant, states, readOnly && ctx.extensionFilesReadable === true, caseInsensitive);
      if (why) return { path: abs, reason: `touches ${why}` };
    }
    return null;
  };
  let cwd = ctx.cwd;
  for (const p of extraPaths) { const hit = check(p, cwd); if (hit) return hit; }
  const tokens = tokenize(command);
  let atStart = true; let verb = ""; let afterWriteOp = false;
  let cdSeenDashDash = false; let cdApplied = false;
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]!;
    if ("op" in t) {
      afterWriteOp = WRITE_OPS.has(t.op);
      if (!afterWriteOp && t.op !== "<") {
        atStart = true;
        cdSeenDashDash = false;
        cdApplied = false;
      }
      continue;
    }
    const wasWriteOp = afterWriteOp;
    if (atStart && !wasWriteOp) { verb = t.word.replace(/^.*\//, ""); atStart = false; cdSeenDashDash = false; cdApplied = false; }
    const word = expandHome(t.word, ctx.home);
    // The word itself, then every path-like piece inside it (python -c "open('~/.0/extensions/x')").
    const pieces = new Set<string>([word, ...word.split(/[\s'"`=:,;()[\]{}<>|&!]+/).filter(p => p.length > 0)]);
    const readOnly = !wasWriteOp && !DESTRUCTIVE.test(verb) && !WRITING_VERBS.test(verb);
    afterWriteOp = false;
    for (const piece of pieces) {
      const hit = check(piece, cwd, readOnly && piece === word); if (hit) return hit;
      // `$(...)`/backtick pieces and ${VAR} remain unresolved text; nothing more can be said here.
    }
    if ((verb === "cd" || verb === "pushd") && !wasWriteOp && !cdApplied && t.word !== verb) {
      if (!cdSeenDashDash && t.word === "--") { cdSeenDashDash = true; }
      else if (cdSeenDashDash || !t.word.startsWith("-") || t.word === "-") {
        cwd = word === "-" ? cwd : isAbsolute(word) ? resolve(word) : resolve(cwd, word);
        cdApplied = true;
      }
    }
    // `rm -rf ~/.0` style: the state directory itself, only for verbs that destroy or rewrite.
    if (DESTRUCTIVE.test(verb)) {
      const abs = isAbsolute(word) ? resolve(word) : resolve(cwd, word);
      const matchState = (candidate: string) =>
        states.some(s => (caseInsensitive ? s.toLowerCase() === candidate.toLowerCase() : s === candidate));
      if (matchState(abs) || matchState(realOf(abs, real))) return { path: abs, reason: `${verb} on the 0 state directory ${abs}` };
    }
  }
  return null;
}

/** Commands that grant an approval or change enablement. An agent must never run these; the operator does. */
const APPROVAL_SUBCOMMANDS = new Set(["add", "enable", "disable", "update", "import", "link", "remove", "delete", "install", "uninstall"]);
const SKILLS_APPROVAL_SUBCOMMANDS = new Set(["add", "import", "link", "remove", "delete", "edit", "copy"]);

const WRAPPERS = new Set(["env", "sudo", "command", "exec", "nohup", "time"]);
/** Options of env/sudo/exec that consume the next word (`env -u NAME`, `sudo -u user`, `exec -a NAME`). */
const WRAPPER_FLAG_VALUE = new Set(["-u", "--unset", "-C", "--chdir", "-g", "--group", "-h", "--host", "-p", "--prompt", "-r", "--role", "-t", "--type", "-U", "--other-user", "-S", "--split-string"]);
/** Runtime flags (node/bun) that consume a separate following argument before the script path. */
const RUNTIME_FLAG_VALUE = new Set(["-r", "--require", "--import", "--preload", "-e", "--eval", "-p", "--print", "-C", "--conditions", "--env-file", "--loader", "--experimental-loader", "--max-old-space-size", "--tsconfig-override"]);

export function findApprovalCommand(command: string): string | null {
  const segments: string[][] = []; let cur: string[] = [];
  for (const t of tokenize(command)) { if ("op" in t) { if (cur.length) segments.push(cur); cur = []; } else cur.push(t.word); }
  if (cur.length) segments.push(cur);
  for (const raw of segments) {
    let words = raw;
    while (words.length) {
      const first = words[0]!;
      const wrapperBase = first.replace(/^.*\//, "");
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(first)) { words = words.slice(1); continue; }
      if (!WRAPPERS.has(wrapperBase)) break;
      words = words.slice(1);
      // `env -u ZERO_AGENT_SESSION node ...`: skip the wrapper's own options (and inspect `-S`/`--split-string`).
      while (words.length && words[0]!.startsWith("-") && words[0] !== "--") {
        const flag = words[0]!; words = words.slice(1);
        if (flag === "-S" || flag === "--split-string") {
          if (words.length) { const nested = findApprovalCommand(words[0]!); if (nested) return nested; words = words.slice(1); }
        } else if (flag.startsWith("--split-string=") || (flag.startsWith("-S") && flag.length > 2)) {
          const payload = flag.startsWith("--split-string=") ? flag.slice("--split-string=".length) : flag.slice(2);
          const nested = findApprovalCommand(payload);
          if (nested) return nested;
        } else if (((wrapperBase === "exec" && flag === "-a") || WRAPPER_FLAG_VALUE.has(flag)) && words.length) {
          words = words.slice(1);
        }
      }
      if (words[0] === "--") words = words.slice(1);
    }
    const exe = (words[0] ?? "").replace(/^.*\//, "");
    if (!["0", "0security", "zero", "node", "bun"].includes(exe) && !/^0(security)?(\.js)?$/.test(exe)) continue;
    let tail = words.slice(1);
    if (exe === "node" || exe === "bun") {
      // Skip runtime flags (including `--flag val`) and the entry script argument (`0.js` / `index.js`).
      let idx = 0;
      while (idx < tail.length && tail[idx]!.startsWith("-")) {
        const flag = tail[idx++]!;
        if (flag === "--") break;
        if (RUNTIME_FLAG_VALUE.has(flag) && idx < tail.length) idx++;
      }
      if (idx < tail.length && !tail[idx]!.startsWith("-")) idx++;
      tail = tail.slice(idx);
    }
    const rest = tail.filter(w => !w.startsWith("-"));
    const [group, sub, sub2] = rest;
    if (group === "skills" && sub && SKILLS_APPROVAL_SUBCOMMANDS.has(sub)) return `0 skills ${sub}`;
    if (group === "skills" && sub === "list" && tail.some(w => w === "--enable" || w === "--disable" || w === "--mcp-remove")) return "0 skills list";
    if (group === "skills" && sub === "extensions" && sub2 && APPROVAL_SUBCOMMANDS.has(sub2)) return `0 skills extensions ${sub2}`;
    if (group === "skills" && words.includes("--yes")) return "0 skills ... --yes";
    if (group === "plugin" && sub && APPROVAL_SUBCOMMANDS.has(sub)) return `0 plugin ${sub}`;
    if (group === "plugins" && sub && APPROVAL_SUBCOMMANDS.has(sub)) return `0 plugins ${sub}`;
  }
  return null;
}
