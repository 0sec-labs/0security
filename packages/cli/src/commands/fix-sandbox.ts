/**
 * Run a check command of `0 findings fix` inside a Docker container instead of on the host (`--sandbox docker`).
 *
 * What the container gets: a copy of the fix work tree without its `.git` (so the check cannot touch the host's work tree
 * or git data), no network unless the operator asks, memory, CPU and process limits, no Linux capabilities, no host
 * environment variables, a time limit and a bounded output. What it does not give: protection from a flaw in Docker
 * itself, and no limit on disk use inside the container.
 */
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, closeSync, constants, cpSync, mkdirSync, mkdtempSync, openSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";

export interface SandboxSpec {
  image: string;
  network: boolean;
  /** A host folder shared by the setup step and the checks, mounted at /cache and used as HOME, so downloaded dependencies (~/.m2, ~/.gradle) survive between containers. */
  cache?: string;
}
export interface SandboxResult { command: string; code: number; output: string; sandbox: string }

export const SANDBOX_TIMEOUT_MS = 10 * 60 * 1000;
export const SANDBOX_MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
const PROBE = ".0-sandbox-probe";
/** Fails with a clear message when the container cannot see the copied work tree (a Docker VM that does not share the folder), instead of running the command in an empty folder. */
const guarded = (command: string): string => `[ -e /work/${PROBE} ] || { echo "The work tree is not visible inside the container: the Docker VM must share the folder it was started from." >&2; exit 125; }\n${command}`;

export const SANDBOX_LIMITS = { memory: "4g", cpus: "2", pids: "1024" } as const;

/** A registry reference such as `maven:3-eclipse-temurin-21` or `ghcr.io/org/app@sha256:...`: one word, never an option. */
const IMAGE = /^[A-Za-z0-9][A-Za-z0-9._\-/:@]{0,255}$/;
export function validateSandboxImage(image: string): string {
  if (!IMAGE.test(image)) throw new Error(`'${image}' is not an image reference. Use a name such as maven:3-eclipse-temurin-21.`);
  return image;
}

/** An image named by its content digest, which cannot change under the same name. */
export function isPinnedImage(image: string): boolean { return /@sha256:[0-9a-f]{64}$/.test(image); }

/**
 * Proof that a container started with `--network none` really has no network: the only interface in /sys/class/net is the
 * loopback. It runs in the same image, with the same flags, as the checks. Needs a Linux image with `ls` (every common JDK image has it).
 */
export function networkCanary(interfaces = "/sys/class/net"): string {
  return `[ -d ${interfaces} ] || { echo "cannot check the network: ${interfaces} does not exist in this image" >&2; exit 1; }; bad=$(ls ${interfaces} 2>/dev/null | grep -v '^lo$' | head -1); if [ -n "$bad" ]; then echo "network interface $bad is present" >&2; exit 1; fi; echo 'network-off canary: only the loopback interface exists'`;
}
export const NETWORK_CANARY = networkCanary();

/** A fresh cache folder (world-writable, because the container runs as your user id) under the sandbox parent. Remove it with rmSync when the run ends. */
export function makeSandboxCache(): string {
  const chosen = process.env["ZERO_SANDBOX_DIR"]?.trim();
  const parent = chosen ? resolve(chosen) : process.platform === "linux" ? tmpdir() : join(homedir(), ".0", "sandbox");
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  const cache = mkdtempSync(join(parent, "cache-"));
  mkdirSync(join(cache, "home"), { mode: 0o777 });
  chmodSync(join(cache, "home"), 0o777);
  return cache;
}

/** The text written in the pull request: which image, and whether the network was on. */
export function sandboxLabel(spec: SandboxSpec): string { return `${spec.image}, network ${spec.network ? "on" : "off"}`; }

/** The `docker run` arguments for one check. An argument array: the host never parses `command`; the shell inside the container does. */
export function dockerRunArgs(spec: SandboxSpec, name: string, dir: string, command: string, ids?: { uid: number; gid: number }): string[] {
  return [
    "run", "--rm", "--name", name,
    ...(spec.network ? [] : ["--network", "none"]),
    "--memory", SANDBOX_LIMITS.memory, "--cpus", SANDBOX_LIMITS.cpus, "--pids-limit", SANDBOX_LIMITS.pids,
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
    ...(ids ? ["--user", `${ids.uid}:${ids.gid}`] : []),
    "-e", spec.cache ? "HOME=/cache/home" : "HOME=/tmp", "-e", "CI=true",
    "-v", `${dir}:/work`, ...(spec.cache ? ["-v", `${spec.cache}:/cache`] : []), "-w", "/work",
    "--entrypoint", "/bin/sh", spec.image, "-c", guarded(command),
  ];
}

function run(tool: "docker", args: string[], env: NodeJS.ProcessEnv, timeout: number): Promise<{ code: number; output: string; timedOut: boolean; missing: boolean; overflow: boolean }> {
  return new Promise(resolve => {
    execFile(tool, args, { env, timeout, maxBuffer: SANDBOX_MAX_OUTPUT_BYTES, encoding: "utf8", windowsHide: true }, (error, stdout, stderr) => {
      const output = `${stdout}${stderr}`;
      if (!error) return resolve({ code: 0, output, timedOut: false, missing: false, overflow: false });
      const failure = error as NodeJS.ErrnoException & { killed?: boolean; signal?: string; stdout?: string; stderr?: string };
      const partial = `${failure.stdout ?? stdout}${failure.stderr ?? stderr}`;
      resolve({
        code: typeof failure.code === "number" ? failure.code : failure.killed ? 124 : 1,
        output: partial, timedOut: Boolean(failure.killed || failure.signal === "SIGTERM"), missing: failure.code === "ENOENT", overflow: failure.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER",
      });
    });
  });
}

/**
 * Run one command in the container. Never throws for a failing command. A Docker problem (no `docker`, no daemon, an image that
 * cannot be pulled) is a failed check with the reason in its output, never a pass.
 */
export async function runInSandbox(cwd: string, command: string, spec: SandboxSpec, options: { env?: NodeJS.ProcessEnv; timeoutMs?: number } = {}): Promise<SandboxResult> {
  const sandbox = sandboxLabel(spec);
  const fail = (code: number, output: string): SandboxResult => ({ command, code, output, sandbox });
  // Docker on macOS and Windows runs in a VM that shares the home folder, not the system temp folder. ZERO_SANDBOX_DIR names another shared folder.
  const chosen = process.env["ZERO_SANDBOX_DIR"]?.trim();
  const parent = chosen ? resolve(chosen) : process.platform === "linux" ? tmpdir() : join(homedir(), ".0", "sandbox");
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  const scratch = mkdtempSync(join(parent, "run-"));
  const copy = join(scratch, "work");
  const name = `0-fix-${randomBytes(6).toString("hex")}`;
  // Only PATH and the Docker client settings: the host's other variables, such as API keys, stay out of the docker process too.
  const source = options.env ?? process.env;
  const env: NodeJS.ProcessEnv = {};
  for (const key of ["PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "XDG_RUNTIME_DIR"]) if (source[key] !== undefined) env[key] = source[key];
  try {
    cpSync(cwd, copy, { recursive: true, verbatimSymlinks: true, filter: path => !/(^|[\\/])\.git$/.test(path) });
    const probePath = join(copy, PROBE);
    // Remove any pre-existing file, directory, or symlink without following it, then create the probe exclusively.
    rmSync(probePath, { recursive: true, force: true });
    const fd = openSync(
      probePath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    closeSync(fd);
    const ids = typeof process.getuid === "function" && typeof process.getgid === "function" ? { uid: process.getuid(), gid: process.getgid() } : undefined;
    const timeout = options.timeoutMs ?? SANDBOX_TIMEOUT_MS;
    const result = await run("docker", dockerRunArgs(spec, name, copy, command, ids), env, timeout);
    if (result.missing) return fail(127, "docker is not installed (or not on PATH). Install Docker, or run the check without --sandbox.");
    if (result.timedOut) {
      await run("docker", ["kill", name], env, 30_000);
      return fail(124, `${result.output}\nStopped: the command did not finish within ${Math.round(timeout / 1000)} seconds.`);
    }
    if (result.overflow) return fail(1, `${result.output}\nStopped: the command printed more than ${SANDBOX_MAX_OUTPUT_BYTES / 1024 / 1024} MB.`);
    // 125 is Docker itself failing (no daemon, image not found), not the command.
    if (result.code === 125) return fail(125, `docker could not start the container:\n${result.output}`);
    return fail(result.code, result.output);
  } catch (error) {
    return fail(1, `The sandbox could not be prepared: ${error instanceof Error ? error.message : String(error)}`);
  } finally { rmSync(scratch, { recursive: true, force: true }); }
}
