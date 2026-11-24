/**
 * Scripts of an extension run through the ordinary bash tool. This is the one place that decides what such a run adds to
 * its environment: only the variables the extension declared AND the operator approved, filled from the process
 * environment (for plain declared names) and from the connection's stored secret (for a connector's names). A script of an
 * extension that is not enabled and approved gets nothing, and an extension whose approval does not cover a name it
 * declares is refused outright. The secret values are returned so the caller can mask them in what comes back.
 */
import fs from "node:fs";
import path from "node:path";
import type { ExtensionRunPort } from "../../agent/types.js";
import { BASE_ENV } from "./core/env.js";
import { planSandbox, TRUSTED_INTERPRETER_NAMES, type TrustedInterpreter } from "./sandbox/index.js";
import type { ConnectionSecrets, ExtensionStore } from "./ports.js";
import { loadable, type LoadedExtension } from "./runtime.js";

const SHELL_EXTENSIONS = new Set([".sh", ".bash", ".zsh"]);
const PYTHON_EXTENSIONS = new Set([".py"]);
const NODE_EXTENSIONS = new Set([".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"]);
const BUN_EXTENSIONS = new Set([...NODE_EXTENSIONS, ".jsx", ".tsx"]);

const INTERPRETER_EXTENSIONS: Readonly<Record<string, ReadonlySet<string>>> & Record<TrustedInterpreter, ReadonlySet<string>> = {
  sh: SHELL_EXTENSIONS,
  bash: SHELL_EXTENSIONS,
  zsh: SHELL_EXTENSIONS,
  python: PYTHON_EXTENSIONS,
  python3: PYTHON_EXTENSIONS,
  node: NODE_EXTENSIONS,
  bun: BUN_EXTENSIONS,
};

const TRUSTED_ENV_PATHS = new Set(["env", "/usr/bin/env", "/bin/env"]);
const TRUSTED_INTERPRETER_PREFIXES = ["/bin/", "/usr/bin/", "/usr/local/bin/", "/opt/homebrew/bin/"];

/**
 * Resolve an interpreter token to its canonical interpreter name if and only if
 * it is a bare known interpreter name, the active Node executable, or lives directly
 * inside a trusted system binary directory. Fails closed (`null`) otherwise.
 */
function resolveTrustedInterpreter(prog: string): string | null {
  if (prog === process.execPath) return "node";
  if (!prog.includes("/") && !prog.includes("\\")) {
    return Object.hasOwn(INTERPRETER_EXTENSIONS, prog) ? prog : null;
  }
  for (const prefix of TRUSTED_INTERPRETER_PREFIXES) {
    if (!prog.startsWith(prefix)) continue;
    const base = path.posix.basename(prog);
    if (prog === prefix + base && Object.hasOwn(INTERPRETER_EXTENSIONS, base)) {
      return base;
    }
  }
  return null;
}

/**
 * Tokenize a single-command shell invocation. Rejects shell compounding (`;`, `&&`, `||`, `|`, `&`, `\n`, `\r`),
 * parameter/command expansion (`$...`, `$(...)`, `$'...'`, backticks), redirection (`<`, `>`),
 * subshell grouping (`(`, `)`), and shell comments (`#`).
 * Fails closed (`null`) if any ambiguous, compound, or non-single-command construct is encountered.
 */
function parseShellCommand(command: string): string[] | null {
  if (command.includes("\0")) return null;
  const tokens: string[] = [];
  let current = "";
  let inSingle = false;
  let inDouble = false;
  let hasToken = false;

  for (let i = 0; i < command.length; i++) {
    const ch = command[i];

    if (inSingle) {
      if (ch === "'") {
        inSingle = false;
      } else {
        current += ch;
        hasToken = true;
      }
      continue;
    }

    if (inDouble) {
      if (ch === '"') {
        inDouble = false;
      } else if (ch === "\\") {
        const next = command[i + 1];
        if (next === "\n" || next === "\r") return null;
        if (next === '"' || next === "\\" || next === "$" || next === "`") {
          current += next;
          i++;
        } else {
          current += ch;
        }
        hasToken = true;
      } else if (ch === "`" || ch === "$") {
        return null;
      } else {
        current += ch;
        hasToken = true;
      }
      continue;
    }

    if (ch === "\\") {
      const next = command[i + 1];
      if (next === "\n" || next === "\r") return null;
      if (next !== undefined) {
        current += next;
        i++;
        hasToken = true;
      }
    } else if (ch === "'") {
      inSingle = true;
      hasToken = true;
    } else if (ch === '"') {
      inDouble = true;
      hasToken = true;
    } else if (ch === " " || ch === "\t") {
      if (hasToken) {
        tokens.push(current);
        current = "";
        hasToken = false;
      }
    } else if (ch === "\n" || ch === "\r") {
      return null;
    } else if (ch === ";" || ch === "&" || ch === "|" || ch === "<" || ch === ">" || ch === "(" || ch === ")" || ch === "`") {
      return null;
    } else if (ch === "$") {
      return null;
    } else if (ch === "#") {
      return null;
    } else {
      current += ch;
      hasToken = true;
    }
  }

  if (inSingle || inDouble) return null;
  if (hasToken) tokens.push(current);
  return tokens;
}

/**
 * Extract the script file path candidate and optional trusted interpreter from tokenized arguments.
 * Rejects flags passed to interpreters and untrusted interpreter or `env` binary paths.
 */
function extractScriptCandidate(tokens: string[]): { candidate: string; index: number; interpreter: string | null } | null {
  if (tokens.length === 0) return null;

  let idx = 0;
  if (TRUSTED_ENV_PATHS.has(tokens[0])) {
    idx++;
    if (idx >= tokens.length) return null;
    const interpreter = resolveTrustedInterpreter(tokens[idx]);
    if (!interpreter) return null;
    idx++;
    if (idx >= tokens.length || tokens[idx].startsWith("-")) return null;
    return { candidate: tokens[idx], index: idx, interpreter };
  }

  const interpreter = resolveTrustedInterpreter(tokens[idx]);
  if (interpreter) {
    idx++;
    if (idx >= tokens.length || tokens[idx].startsWith("-")) return null;
    return { candidate: tokens[idx], index: idx, interpreter };
  }

  return { candidate: tokens[0], index: 0, interpreter: null };
}

/**
 * Validate that candidate script path resolves to a real script declared in the manifest
 * of an active extension and strictly contained within the extension revision directory.
 */
function findAuthorizedExtension(
  candidate: string,
  loadedExtensions: LoadedExtension[],
  cwd: string = process.cwd()
): { ext: LoadedExtension; relScript: string } | null {
  let canonicalScript: string;
  try {
    const resolved = path.resolve(cwd, candidate);
    canonicalScript = fs.realpathSync(resolved);
  } catch {
    return null;
  }

  for (const ext of loadedExtensions) {
    let canonicalExtDir: string;
    try {
      canonicalExtDir = fs.realpathSync(ext.dir);
    } catch {
      continue;
    }

    const prefix = canonicalExtDir.endsWith(path.sep) ? canonicalExtDir : canonicalExtDir + path.sep;
    if (!canonicalScript.startsWith(prefix)) {
      continue;
    }

    const relScript = path.relative(canonicalExtDir, canonicalScript).split(path.sep).join("/");
    if (ext.manifest.scripts.includes(relScript)) {
      return { ext, relScript };
    }
  }

  return null;
}

export function createScriptRuns(options: {
  store: ExtensionStore;
  secrets: ConnectionSecrets;
  projectKey: string | null;
  parentEnv?: () => Readonly<Record<string, string | undefined>>;
  cwd?: string | (() => string | undefined);
}): ExtensionRunPort {
  return {
    prepare(command, context) {
      const state = options.store.read();
      if (!state.ok) return null;

      const tokens = parseShellCommand(command);
      if (!tokens || tokens.length === 0) return null;

      const extracted = extractScriptCandidate(tokens);
      if (!extracted) return null;

      const { extensions } = loadable(options.store, options.projectKey, options.secrets);
      if (!extensions.length) return null;

      const effectiveCwd = context?.cwd ?? (typeof options.cwd === "function" ? options.cwd() : options.cwd) ?? process.cwd();
      const match = findAuthorizedExtension(extracted.candidate, extensions, effectiveCwd);
      if (!match) return null;

      if (extracted.interpreter) {
        const scriptExt = path.posix.extname(match.relScript).toLowerCase();
        const allowedExts = INTERPRETER_EXTENSIONS[extracted.interpreter];
        if (scriptExt && (!allowedExts || !allowedExts.has(scriptExt))) {
          return null;
        }
      }

      const { ext } = match;
      if (ext.unapprovedEnv.length) {
        return {
          ok: false,
          error: `extension ${ext.name} declares ${ext.unapprovedEnv.join(", ")} but the approval does not cover it: approve it again with \`0security skills extensions enable ${ext.name} --yes\``,
        };
      }

      const env: Record<string, string> = {};
      const secrets: string[] = [];
      for (const [name, value] of Object.entries(ext.env((options.parentEnv ?? (() => process.env))()))) {
        env[name] = value;
        if (!BASE_ENV.includes(name) && !name.startsWith("ZERO_EXTENSION_")) secrets.push(value);
      }

      // OS sandbox (ZERO_SANDBOX): the script's program is started directly, with the canonical path of the script.
      const parent = (options.parentEnv ?? (() => process.env))();
      const argv = [...tokens];
      let canonicalDir: string;
      try { canonicalDir = fs.realpathSync(ext.dir); } catch { return { ok: false, error: `extension ${ext.name}: its folder cannot be resolved` }; }
      argv[extracted.index] = path.join(canonicalDir, match.relScript);
      const plan = planSandbox({
        decl: ext.manifest.sandbox, extensionDir: ext.dir, workspace: effectiveCwd, argv, interpreters: TRUSTED_INTERPRETER_NAMES,
        env: { PATH: parent.PATH ?? process.env.PATH ?? "" }, cwd: effectiveCwd, label: `script ${match.relScript} of extension ${ext.name}`,
      }, { env: parent });
      if (plan.kind === "refused") return { ok: false, error: plan.error };
      if (plan.kind === "unsandboxed") return { ok: true, env, secrets, status: plan.status };
      return { ok: true, env: { ...env, TMPDIR: plan.env.TMPDIR ?? "", ZERO_SANDBOX_ACTIVE: "1" }, secrets, spawn: { file: plan.file, args: plan.args, cwd: plan.cwd }, status: plan.status, cleanup: plan.cleanup };
    },
  };
}
