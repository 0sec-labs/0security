/**
 * Finds the real program behind a launcher, so node's permission layer is applied or the run is refused. It is never
 * skipped silently.
 *
 *   - `env` is unwrapped when every part of the call is understood: NAME=value, -i, -u NAME, --, -S 'split string'.
 *     Any other env option is refused.
 *   - Launchers that start another program (command, exec, nice, nohup, timeout, sudo, xargs, arch, ...) and shells
 *     with -c are refused when the program they start may be node.
 *   - Package runners and version managers (npx, pnpm, yarn, volta, fnm, ...) choose node themselves, so they are
 *     always refused.
 *   - A shell script, python or any other program that does not name node is not a launcher here. It gets no node layer.
 */
import path from "node:path";

export type EnvOp = { op: "clear" } | { op: "unset"; name: string } | { op: "set"; name: string; value: string };

const NAME = (p: string): string => (p.replace(/^["']+|["']+$/g, "").split(/[\\/]/).pop() ?? "").replace(/\.(?:exe|cmd|bat)$/i, "").toLowerCase();

/** Package runners and version managers: they pick the node binary, so the layer cannot be applied to it. */
const NODE_CHOOSERS = new Set(["npx", "pnpx", "bunx", "npm", "pnpm", "yarn", "corepack", "volta", "fnm", "nvm", "n", "nodenv", "asdf", "mise", "rtx", "direnv", "nodeenv"]);
/** Launchers that run the program in their arguments. Refused when those arguments may name node. */
const WRAPPERS = new Set(["command", "exec", "nice", "nohup", "timeout", "sudo", "doas", "setsid", "stdbuf", "ionice", "chroot", "time", "xargs", "nsenter", "unshare", "taskset", "chrt", "flock", "caffeinate", "arch", "watch", "script", "su", "runuser", "busybox", "builtin", "eval", "sg", "newgrp", "systemd-run", "firejail", "proot", "setpriv", "prlimit"]);
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "csh", "tcsh", "nu", "nushell", "xonsh", "elvish", "rc", "es", "yash", "oksh", "pdksh"]);
/** Windows shells have a command syntax 0 does not read. Any use of them is refused. */
const WINDOWS_SHELLS = new Set(["cmd", "powershell", "pwsh"]);
/** `node` or `nodejs` as a word in a command or a shell string. `node-x`, `node_modules` and `/node/dir` do not match. */
const MENTIONS_NODE = /(?:^|[\s/;&|()'"`=<>{}!$])node(?:js)?(?:\.exe)?(?=$|[\s;&|()'"`<>{}])/i;

/** What env searches when PATH is unset. */
const DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin";
/** Interpreters that run a code string from the command line, and the flags that carry it. */
const INLINE_INTERPRETERS: ReadonlyArray<readonly [RegExp, RegExp]> = [
  [/^python[\d.]*$/, /^-[a-zA-Z]*c[a-zA-Z]*$/],
  [/^perl[\d.]*$/, /^-[a-zA-Z]*[eE][a-zA-Z]*$/],
  [/^ruby[\d.]*$/, /^-[a-zA-Z]*e[a-zA-Z]*$/],
  [/^php[\d.]*$/, /^-[a-zA-Z]*r[a-zA-Z]*$/],
  [/^lua[\d.]*$/, /^-[a-zA-Z]*e[a-zA-Z]*$/],
  [/^(?:bun|deno)$/, /^(?:-[a-zA-Z]*[ep][a-zA-Z]*|--eval|--print|eval)$/],
  [/^osascript$/, /^-[a-zA-Z]*e[a-zA-Z]*$/],
];
/** A flag that makes a shell run a command string: -c, -lc, -ec, --command, --commands, /c, /k, -Command. cmd, powershell and pwsh are refused with any argument. */
const SHELL_COMMAND_FLAG = /^(?:-[a-zA-Z]*[cC][a-zA-Z]*|--command[a-z]*(?:=.*)?)$/;
/** True when `name` is a shell or an interpreter and `rest` gives it a code string, which 0 cannot read. */
const runsInlineCode = (name: string, rest: readonly string[]): boolean =>
  (SHELLS.has(name) && rest.some(a => SHELL_COMMAND_FLAG.test(a))) || INLINE_INTERPRETERS.some(([n, f]) => n.test(name) && rest.some(a => f.test(a)));
/** A word that is node, another launcher or a shell, or that names node, or an interpreter given code. It could start node, so a wrapper with it is refused. */
const riskyWord = (a: string): boolean => { const n = NAME(a); return n === "node" || WINDOWS_SHELLS.has(n) || n === "nodejs" || n === "env" || SHELLS.has(n) || WRAPPERS.has(n) || NODE_CHOOSERS.has(n) || MENTIONS_NODE.test(a); };
const hidesInline = (args: readonly string[]): boolean => args.some((a, i) => runsInlineCode(NAME(a).toLowerCase(), args.slice(i + 1)));

export interface LaunchResolved { ok: true; unwrapped: boolean; program: string; args: string[]; env: Record<string, string> }
export interface LaunchRefused { ok: false; error: string }

/** Splits an `env -S` string with GNU env's rules. Anything with a meaning we do not reproduce exactly is refused. */
export function splitEnvString(s: string): { ok: true; words: string[] } | { ok: false; error: string } {
  const bad = (error: string): { ok: false; error: string } => ({ ok: false, error: `env -S: ${error}` });
  const words: string[] = [];
  let cur = ""; let has = false; let quote: "'" | '"' | null = null;
  const escapes: Record<string, string> = { n: "\n", t: "\t", r: "\r", f: "\f", v: "\v" };
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === "\0") return bad("a null byte");
    if (c === "\\") {
      const n = s[++i];
      if (n === undefined) return bad("a trailing backslash");
      if (quote === "'") { if (n === "'" || n === "\\") { cur += n; continue; } return bad(`the escape \\${n} inside single quotes`); }
      if (n === "c") return bad("the escape \\c");
      if (n === "_") { if (quote) cur += " "; else { if (has) words.push(cur); cur = ""; has = false; } continue; }
      if (n in escapes) { cur += escapes[n]; has = true; continue; }
      if (n === "\\" || n === '"' || n === "$" || (!quote && (n === "'" || n === "#"))) { cur += n; has = true; continue; }
      return bad(`the escape \\${n}`);
    }
    if (quote) { if (c === quote) { quote = null; continue; } if (quote === '"' && c === "$") return bad("a $ variable"); cur += c; has = true; continue; }
    if (c === "'" || c === '"') { quote = c; has = true; continue; }
    if (c === "$") return bad("a $ variable");
    if (c === "#" && !has) return bad("a # comment");
    if (/\s/.test(c)) { if (has) words.push(cur); cur = ""; has = false; continue; }
    cur += c; has = true;
  }
  if (quote) return bad("a quote that is not closed");
  if (has) words.push(cur);
  return { ok: true, words };
}

/** Parses what follows `env`. Returns the changes to the environment and the program with its arguments. */
export function parseEnvCall(args: readonly string[]): { ok: true; ops: EnvOp[]; rest: string[] } | { ok: false; error: string } {
  const q = [...args]; const ops: EnvOp[] = [];
  const bad = (error: string): { ok: false; error: string } => ({ ok: false, error });
  let splits = 0;
  while (q.length) {
    const a = q[0]!;
    if (a === "--") { q.shift(); break; }
    if (a === "-") { q.shift(); ops.push({ op: "clear" }); continue; }
    if (!a.startsWith("-")) break;
    q.shift();
    if (a.startsWith("--")) {
      const eq = a.indexOf("="); const key = eq < 0 ? a : a.slice(0, eq);
      const value = (): string | undefined => (eq >= 0 ? a.slice(eq + 1) : q.shift());
      if (key === "--ignore-environment" && eq < 0) { ops.push({ op: "clear" }); continue; }
      if (key === "--debug" && eq < 0) continue;
      if (key === "--unset") { const v = value(); if (!v || v.includes("=")) return bad(`env: cannot read the name after ${key}`); ops.push({ op: "unset", name: v }); continue; }
      if (key === "--split-string") { const v = value(); if (v === undefined) return bad("env: --split-string needs a string"); const r = splitEnvString(v); if (!r.ok) return r; if (++splits > 4) return bad("env: -S nested too deeply"); q.unshift(...r.words); continue; }
      return bad(`env: the option ${a.slice(0, 40)} is not understood`);
    }
    for (let i = 1; i < a.length; i++) {
      const c = a[i]!; const tail = a.slice(i + 1);
      if (c === "i") { ops.push({ op: "clear" }); continue; }
      if (c === "v") continue;
      if (c === "u" || c === "S") {
        const v = tail || q.shift();
        if (v === undefined || v === "") return bad(`env: -${c} needs a value`);
        if (c === "u") { if (v.includes("=")) return bad("env: -u needs a plain name"); ops.push({ op: "unset", name: v }); }
        else { const r = splitEnvString(v); if (!r.ok) return r; if (++splits > 4) return bad("env: -S nested too deeply"); q.unshift(...r.words); }
        break;
      }
      return bad(`env: the option -${c} is not understood`);
    }
  }
  while (q.length && q[0]!.includes("=")) {
    const a = q.shift()!; const eq = a.indexOf("=");
    if (eq === 0) return bad("env: an assignment has no name");
    ops.push({ op: "set", name: a.slice(0, eq), value: a.slice(eq + 1) });
  }
  if (!q.length) return bad("env: no program to run");
  return { ok: true, ops, rest: q };
}

export function applyEnvOps(base: Readonly<Record<string, string>>, ops: readonly EnvOp[]): Record<string, string> {
  let out: Record<string, string> = { ...base };
  for (const o of ops) { if (o.op === "clear") out = {}; else if (o.op === "unset") delete out[o.name]; else out[o.name] = o.value; }
  return out;
}

export interface LaunchHost {
  /** Turns a program name into a path using the given PATH. */
  resolve(name: string, pathEnv: string): string;
  real(p: string): string;
  isNode(program: string): boolean;
}

/**
 * Looks through `env`, and refuses launchers that could hide node. When it unwraps, `program` and `args` are what node
 * runs and `env` is the environment after the env call. When it does not, they are the request unchanged.
 */
export function resolveLaunch(argv: readonly string[], env: Readonly<Record<string, string>>, host: LaunchHost, label: string): LaunchResolved | LaunchRefused {
  let args = [...argv]; let cur: Record<string, string> = { ...env }; let unwrapped = false;
  const refuse = (why: string): LaunchRefused => ({ ok: false, error: `cannot start ${label} in a sandbox: ${why}. Start node directly, or set ZERO_SANDBOX_NODE_PERMISSION=off to run it without the node layer` });
  for (let depth = 0; depth < 5; depth++) {
    const first = args[0] ?? "";
    // After an env call the PATH is the one env passes on. env finds programs in it, so it must be one we can search the same way.
    if (unwrapped) {
      const entries = (cur.PATH ?? DEFAULT_PATH).split(path.delimiter);
      if (entries.some(d => !path.isAbsolute(d))) return refuse("the PATH after env has a relative or empty entry, so 0 cannot tell which program env would start");
    }
    const program = host.resolve(first, unwrapped ? cur.PATH ?? DEFAULT_PATH : env.PATH ?? "");
    if (unwrapped && !path.isAbsolute(program)) return refuse(`env would start ${JSON.stringify(first.slice(0, 60))}, which was not found in PATH`);
    const name = NAME(program); const realName = NAME(host.real(program));
    if (host.isNode(program)) return { ok: true, unwrapped, program, args: args.slice(1), env: cur };
    if (name === "env" || realName === "env") {
      const parsed = parseEnvCall(args.slice(1));
      if (!parsed.ok) return refuse(parsed.error);
      cur = applyEnvOps(cur, parsed.ops); args = parsed.rest; unwrapped = true;
      continue;
    }
    const rest = args.slice(1);
    if (NODE_CHOOSERS.has(name) || NODE_CHOOSERS.has(realName)) return refuse(`${name} picks the node program itself`);
    if (WRAPPERS.has(name) || WRAPPERS.has(realName)) { if (rest.some(riskyWord) || hidesInline(rest)) return refuse(`${name} wraps another program and may start node`); }
    if ((WINDOWS_SHELLS.has(name) || WINDOWS_SHELLS.has(realName)) && rest.length) return refuse(`${name} runs a command syntax that 0 cannot read`);
    if (runsInlineCode(name, rest) || runsInlineCode(realName, rest)) return refuse(`${name} runs a code or command string that 0 cannot read, and it could start node`);
    if (unwrapped) return { ok: true, unwrapped: false, program: host.resolve(argv[0] ?? "", env.PATH ?? ""), args: argv.slice(1), env: { ...env } };
    return { ok: true, unwrapped: false, program, args: rest, env: cur };
  }
  return refuse("env calls are nested too deeply");
}
