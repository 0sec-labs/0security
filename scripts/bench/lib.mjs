// Pieces the bench scripts share: an isolated HOME for the CLI, number formatting, and a process runner.
import { spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const benchDir = dirname(fileURLToPath(import.meta.url));
export const repoRoot = resolve(benchDir, "../..");
export const defaultCli = join(repoRoot, "packages/cli/dist/index.js");

/** Environment that keeps a run away from the operator's own databases, settings and caches. */
export function isolatedEnv(home, base = process.env) {
  mkdirSync(home, { recursive: true });
  return { ...base, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, "config"), XDG_DATA_HOME: join(home, "data"), XDG_CACHE_HOME: join(home, "cache") };
}

export const pct = (x) => (x === null || x === undefined ? "n/a" : `${(x * 100).toFixed(0)}%`);
export const usd = (x) => (x === null || x === undefined ? "n/a" : `$${x.toFixed(4)}`);
export const range = (r, f) => (r ? (r[0] === r[1] ? f(r[0]) : `${f(r[0])}-${f(r[1])}`) : "n/a");

/** Run a program without a shell. Never throws; the caller reads status, stdout and stderr. */
export function run(command, args, { cwd, env, timeoutSeconds = 600 } = {}) {
  const proc = spawnSync(command, args, { cwd, env, encoding: "utf8", timeout: timeoutSeconds * 1000, maxBuffer: 64 * 1024 * 1024 });
  return { status: proc.status ?? (proc.signal ? 124 : 1), stdout: proc.stdout ?? "", stderr: proc.stderr ?? "", timedOut: proc.error?.code === "ETIMEDOUT" };
}

export const git = (cwd, args, opts = {}) => run("git", ["-C", cwd, "-c", "user.name=bench", "-c", "user.email=bench@example.test", ...args], opts);

export const isMain = (metaUrl) => Boolean(process.argv[1]) && metaUrl === pathToFileURL(resolve(process.argv[1])).href;
