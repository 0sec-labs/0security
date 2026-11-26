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
import { chmodSync, closeSync, constants, cpSync, fstatSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

export interface SandboxSpec {
  image: string;
  network: boolean;
  /** A host folder shared by the setup step and the checks, mounted at /cache and used as HOME, so downloaded dependencies (~/.m2, ~/.gradle) survive between containers. */
  cache?: string;
  /** Explicit short-lived Maven settings, mounted for setup only. Never included in labels or reports. */
  mavenSettingsFile?: string;
}
/** Official Docker Library Maven OCI index, verified from registry-1.docker.io on 2026-11-25.
 * Tag: 3.9.11-eclipse-temurin-21. The index includes Linux amd64 and arm64; no mutable tag is executed.
 */
export const JAVA_VERIFIER_IMAGE = "docker.io/library/maven@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237";
export interface JavaSandboxOptions { sandboxProfile?: string; sandbox?: string; sandboxImage?: string; sandboxNetwork?: boolean; sandboxSetup?: string[]; sandboxMavenSettings?: string; test?: string[] }
/** Explicit opt-in only. No repository file can select a verifier or grant network access. */
export function applySandboxProfile<T extends JavaSandboxOptions>(options: T): T & JavaSandboxOptions {
  if (!options.sandboxProfile) return options;
  if (options.sandboxProfile !== "java") throw new Error("--sandbox-profile must be java.");
  if (options.sandbox && options.sandbox !== "docker") throw new Error("The java verifier needs --sandbox docker.");
  if (options.sandboxImage || options.sandboxNetwork) throw new Error("The java verifier uses its pinned image and offline checks; do not combine it with --sandbox-image or --sandbox-network.");
  const settings = options.sandboxMavenSettings ? " -s /run/secrets/maven-settings.xml" : "";
  return { ...options, sandbox: "docker", sandboxImage: JAVA_VERIFIER_IMAGE,
    sandboxSetup: options.sandboxSetup?.length ? options.sandboxSetup : [`mvn -B -ntp${settings} -Dmaven.repo.local=/cache/m2 dependency:go-offline verify`],
    test: options.test?.length ? options.test : ["mvn -o -B -ntp -Dmaven.repo.local=/cache/m2 verify"],
  };
}

/** An operator-owned, owner-only regular file; never a symlink or a file from the repository under fix. */
export function validateMavenSettingsFile(path: string, repo?: string): string {
  const absolute = resolve(path);
  const info = lstatSync(absolute);
  if (!info.isFile() || info.isSymbolicLink() || info.size > 64 * 1024 || (process.platform !== "win32" && (info.mode & 0o077))) throw new Error("Maven settings must be an owner-only regular file of at most 64 KiB, not a symlink.");
  if (typeof process.getuid === "function" && info.uid !== process.getuid()) throw new Error("Maven settings must be owned by the current operator.");
  if (repo) {
    const inside = relative(realpathSync(repo), realpathSync(absolute));
    if (!inside || (inside !== ".." && !inside.startsWith(`..${sep}`) && !isAbsolute(inside))) throw new Error("Keep Maven credentials outside the repository under fix.");
  }
  return absolute;
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
    ...(spec.mavenSettingsFile ? ["-v", `${spec.mavenSettingsFile}:/run/secrets/maven-settings.xml:ro`] : []),
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
  const fail = (code: number, output: string): SandboxResult => ({ command, code, output: spec.mavenSettingsFile ? `Credentialed setup output withheld (exit ${code}); rerun without credentials for diagnostic output.` : output, sandbox });
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
    let prepared = spec;
    if (spec.mavenSettingsFile) {
      if (!spec.network) throw new Error("Maven credentials may be mounted only for an explicit online setup step.");
      const sourceFile = validateMavenSettingsFile(spec.mavenSettingsFile, cwd);
      const fd = openSync(sourceFile, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      try {
        const info = fstatSync(fd);
        if (!info.isFile() || info.size > 64 * 1024 || (process.platform !== "win32" && (info.mode & 0o077)) || (typeof process.getuid === "function" && info.uid !== process.getuid())) throw new Error("Maven settings changed while opening them.");
        const secret = join(scratch, "maven-settings.xml");
        writeFileSync(secret, readFileSync(fd), { mode: 0o400, flag: "wx" });
        prepared = { ...spec, mavenSettingsFile: secret };
      } finally { closeSync(fd); }
    }
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
    const result = await run("docker", dockerRunArgs(prepared, name, copy, command, ids), env, timeout);
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
