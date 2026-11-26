/**
 * Docker/podman adapter for the ContainerRunner port. The snapshot is copied
 * into the container (`cp`), never bind-mounted, so the host tree is not
 * writable from inside and it works with remote daemons such as colima.
 * Capabilities are dropped; the network is off for the whole run unless a
 * setup step is declared, in which case it is disconnected after setup.
 */
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import type { Readable } from "node:stream";
import type { ContainerRunner, Probe, StepOutcome, StepRequest } from "./port.js";
import { exec } from "./process.js";

type Exec = typeof exec;

/** The message of the refusal when a writable-storage cap cannot be applied. */
export const STORAGE_LIMIT_UNAVAILABLE = "storage limit unavailable: reproduction refused";

/** Where the snapshot lives when the root file system is read-only: a tmpfs, with a writable parent beside the app folder. */
export const READ_ONLY_SANDBOX = "/sandbox";
export const READ_ONLY_WORKDIR = `${READ_ONLY_SANDBOX}/app`;
const DEFAULT_SANDBOX_SIZE = "256m";

/** The working folder inside the container for a request. */
export function workdirFor(request: StepRequest): string { return request.limits?.readOnlyRoot ? READ_ONLY_WORKDIR : "/work"; }

/** Tar the snapshot to a stream, without macOS metadata. The exit code settles when tar ends. */
function packDir(dir: string): { stream: Readable; code: Promise<number | null>; kill(): void } {
  const child = spawn("tar", ["-cf", "-", "-C", dir, "."], { stdio: ["ignore", "pipe", "ignore"], env: { ...process.env, COPYFILE_DISABLE: "1" } });
  const code = new Promise<number | null>((resolve) => { child.on("error", () => resolve(null)); child.on("close", resolve); });
  return { stream: child.stdout, code, kill: () => { child.stdout.destroy(); child.kill("SIGKILL"); } };
}

/** The `create` argument list for one step. Pure, so the limits can be tested without a container runtime. */
export function buildCreateArgs(name: string, request: StepRequest, options: { storage?: boolean } = {}): string[] {
  const withSetup = Boolean(request.setup) && request.network === "none";
  const limits = request.limits;
  const readOnly = Boolean(limits?.readOnlyRoot);
  return [
    "create", "--name", name, "--label", "0.verify=1", "--cap-drop", "ALL", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER", "--security-opt", "no-new-privileges",
    "--pids-limit", String(limits?.pidsLimit ?? 512), "--memory", limits?.memory ?? "2g", "--workdir", workdirFor(request),
    ...(limits?.memory ? ["--memory-swap", limits.memory] : []),
    ...(limits?.cpus ? ["--cpus", limits.cpus] : []),
    ...(readOnly ? ["--read-only", "--tmpfs", `${READ_ONLY_SANDBOX}:rw,size=${limits?.storageSize ?? DEFAULT_SANDBOX_SIZE},noexec,nosuid,mode=755`] : []),
    ...(limits?.tmpfs ?? []).flatMap((mount) => ["--tmpfs", mount]),
    ...(limits?.storageSize && !readOnly && options.storage !== false ? ["--storage-opt", `size=${limits.storageSize}`] : []),
    ...(request.network === "none" && !withSetup ? ["--network", "none"] : []),
    "--entrypoint", "sh", request.image ?? "",
    "-c", withSetup || request.setup || readOnly ? "sleep 86400" : request.command,
  ];
}

export interface OciRunnerOptions {
  /** Candidate binaries in order of preference. */
  binaries?: string[];
  exec?: Exec;
}

export class OciRunner implements ContainerRunner {
  readonly isolation = "container" as const;
  #bin: string | undefined;
  readonly #binaries: string[];
  readonly #exec: Exec;

  constructor(options: OciRunnerOptions = {}) {
    this.#binaries = options.binaries ?? ["docker", "podman"];
    this.#exec = options.exec ?? exec;
  }

  async probe(): Promise<Probe> {
    for (const bin of this.#binaries) {
      const r = await this.#exec(bin, ["info", "--format", "{{.ServerVersion}}"], { timeoutMs: 10_000 });
      if (!r.spawnError && r.code === 0 && !r.timedOut) { this.#bin = bin; return { ok: true, runtime: bin }; }
    }
    return { ok: false, reason: `no container runtime responded (tried ${this.#binaries.join(", ")})` };
  }

  async run(request: StepRequest): Promise<StepOutcome> {
    const started = Date.now();
    const notApplied: string[] = [];
    const out = (partial: Partial<StepOutcome>): StepOutcome => ({ exitCode: null, output: "", timedOut: false, durationMs: Date.now() - started, ...(notApplied.length ? { limitsNotApplied: notApplied } : {}), ...partial });
    if (!request.image) return out({ infraError: "no image declared for this step" });
    if (!this.#bin) { const probe = await this.probe(); if (!probe.ok) return out({ infraError: probe.reason }); }
    const bin = this.#bin!;
    const name = `0-verify-${randomBytes(6).toString("hex")}`;
    const remaining = () => Math.max(1000, request.timeoutMs - (Date.now() - started));
    const run = (args: string[], timeoutMs = remaining()) => this.#exec(bin, args, { timeoutMs, ...(request.signal ? { signal: request.signal } : {}) });
    try {
      let created = await run(buildCreateArgs(name, request), Math.max(remaining(), 300_000)); // first use may pull the image
      if (created.code !== 0 && request.limits?.storageSize && /storage-opt|storage option|quota/i.test(created.output)) {
        // The storage driver cannot cap the writable layer. Fail closed: refuse to run uncapped unless the caller opted out.
        await this.#exec(bin, ["rm", "-f", name], { timeoutMs: 20_000 });
        if (!request.limits.allowUnboundedStorage) return out({ infraError: STORAGE_LIMIT_UNAVAILABLE });
        notApplied.push("storage-size");
        created = await run(buildCreateArgs(name, request, { storage: false }), Math.max(remaining(), 300_000));
      }
      if (created.code !== 0) return out({ infraError: `could not create container: ${created.output.trim().split("\n").pop() ?? ""}` });
      const streamed = Boolean(request.limits?.readOnlyRoot);
      const workdir = workdirFor(request);
      if (!streamed) {
        const copied = await run(["cp", `${request.dir}/.`, `${name}:/work`]);
        if (copied.code !== 0) return out({ infraError: `could not copy the snapshot: ${copied.output.trim().split("\n").pop() ?? ""}` });
        if (!request.setup) {
          const r = await run(["start", "-a", name]);
          return out({ exitCode: r.code, output: r.output, timedOut: r.timedOut, ...(r.spawnError ? { infraError: r.spawnError } : {}) });
        }
      }
      const started2 = await run(["start", name]);
      if (started2.code !== 0) return out({ infraError: `could not start container: ${started2.output.trim().split("\n").pop() ?? ""}` });
      if (streamed) {
        // `docker cp` refuses a read-only root, so the snapshot goes in as a tar stream into the tmpfs.
        const pack = packDir(request.dir);
        const unpacked = await this.#exec(bin, ["exec", "-i", name, "sh", "-c", `mkdir -p ${workdir} && cd ${workdir} && tar -xof -`], { timeoutMs: remaining(), stdin: pack.stream, ...(request.signal ? { signal: request.signal } : {}) });
        if (unpacked.code !== 0) pack.kill();
        if (unpacked.code !== 0 || (await pack.code) !== 0) return out({ infraError: `could not copy the snapshot: ${unpacked.output.trim().split("\n").pop() || "tar failed"}` });
      }
      if (request.setup) {
        const setup = await run(["exec", "-w", workdir, name, "sh", "-c", request.setup]);
        if (setup.timedOut) return out({ timedOut: true, output: setup.output });
        if (setup.code !== 0) return out({ exitCode: setup.code, output: `setup failed\n${setup.output}` });
        if (request.network === "none") {
          const cut = await run(["network", "disconnect", "bridge", name]);
          if (cut.code !== 0) return out({ infraError: "could not cut the network after setup; refusing to run the check" });
        }
      }
      const r = await run(["exec", "-w", workdir, name, "sh", "-c", request.command]);
      return out({ exitCode: r.code, output: r.output, timedOut: r.timedOut, ...(r.spawnError ? { infraError: r.spawnError } : {}) });
    } finally {
      await this.#exec(bin, ["rm", "-f", name], { timeoutMs: 20_000 });
    }
  }
}
