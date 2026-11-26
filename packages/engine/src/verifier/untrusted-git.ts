/**
 * Read a Git checkout without letting its own configuration run programs.
 *
 * A folder handed to 0 (an unpacked archive, a downloaded checkout, a scan target) can carry its own `.git/config`,
 * and Git runs commands that config names during ordinary read-only porcelain:
 *   - `core.fsmonitor` runs on every command that reads the index (`status`, `diff`, `ls-files`);
 *   - a `filter.<name>.clean` / `.process` driver runs whenever `status` or `diff` re-hashes a file, and
 *     `.smudge` runs on `checkout-index`. Which files use a driver is set by `.gitattributes` or by
 *     `.git/info/attributes`, which `GIT_ATTR_SOURCE` does not cover, so the drivers themselves are switched off.
 *
 * `-c` on the command line outranks every config file, so the arguments below win over the repository. Filter
 * drivers defined by the system or the user (Git LFS, for example) stay as they are: those files belong to the
 * person running 0, not to the folder. Anything defined in the repository (local or worktree scope, including files
 * it pulls in with `include.path`) is overridden with an empty command.
 */
import { execFileSync } from "node:child_process";

/** Overrides that apply to every checkout, whatever its config says. */
export const UNTRUSTED_GIT_BASE_CONFIG: readonly string[] = Object.freeze(["-c", "core.fsmonitor=false"]);

const DRIVER_KEYS = ["clean", "smudge", "process"] as const;
const REPOSITORY_SCOPES = new Set(["local", "worktree"]);

export class UntrustedGitConfigError extends Error {
  constructor(message: string) { super(message); this.name = "UntrustedGitConfigError"; }
}

/** Runs `git` with these arguments and returns stdout. Throws with `status` set when git exits non-zero. */
export type GitConfigReader = (args: string[]) => string;

const defaultReader: GitConfigReader = (args) => execFileSync("git", args, {
  encoding: "utf8", timeout: 10_000, maxBuffer: 1024 * 1024, stdio: ["ignore", "pipe", "ignore"],
  env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_OPTIONAL_LOCKS: "0" },
});

function readFilterKeys(repo: string, read: GitConfigReader, withScope: boolean): string {
  try {
    // Reading config runs nothing: it does not touch the index or any driver.
    return read(["-C", repo, ...UNTRUSTED_GIT_BASE_CONFIG, "config", "--null", ...(withScope ? ["--show-scope"] : []), "--name-only", "--get-regexp", "^filter\\."]);
  } catch (error) {
    if ((error as { status?: unknown }).status === 1) return ""; // no filter keys at all
    throw error;
  }
}

/** The driver names a `filter.<name>.<key>` listing defines, keeping only repository scopes when scopes are known. */
function driverNames(listing: string, withScope: boolean): Set<string> {
  const fields = listing.split("\0");
  if (fields.at(-1) === "") fields.pop();
  const names = new Set<string>();
  const step = withScope ? 2 : 1;
  for (let i = 0; i + step - 1 < fields.length; i += step) {
    const scope = withScope ? fields[i]! : "local";
    const key = fields[i + step - 1]!;
    if (!REPOSITORY_SCOPES.has(scope)) continue;
    // section "filter", then the subsection (it may itself contain dots), then the variable.
    const last = key.lastIndexOf(".");
    if (!key.startsWith("filter.") || last <= "filter.".length) continue;
    names.add(key.slice("filter.".length, last));
  }
  return names;
}

/**
 * The `-c` arguments to put before any read-only Git command run in `repo`. Throws `UntrustedGitConfigError` when the
 * repository defines a filter driver that cannot be named on a command line, so the caller can skip Git instead of
 * running it with the driver live.
 */
export function untrustedGitConfig(repo: string, read: GitConfigReader = defaultReader): string[] {
  let withScope = true;
  let listing: string;
  try { listing = readFilterKeys(repo, read, true); }
  catch (error) {
    // `--show-scope` is Git 2.26+. On an older Git every filter driver is switched off, the user's own included.
    if ((error as { status?: unknown }).status !== 129) throw error;
    withScope = false;
    listing = readFilterKeys(repo, read, false);
  }
  const args = [...UNTRUSTED_GIT_BASE_CONFIG];
  for (const name of driverNames(listing, withScope)) {
    // `-c key=value` splits at the first "=", and a newline cannot be passed through GIT_CONFIG_PARAMETERS intact.
    if (/[=\n\r\0]/.test(name)) throw new UntrustedGitConfigError("The repository defines a Git filter driver whose name cannot be overridden safely.");
    for (const key of DRIVER_KEYS) args.push("-c", `filter.${name}.${key}=`);
    args.push("-c", `filter.${name}.required=false`);
  }
  return args;
}
