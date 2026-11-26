import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { OciRunner, STORAGE_LIMIT_UNAVAILABLE, buildCreateArgs } from "./docker-runner.js";
import type { ExecResult } from "./process.js";
import type { StepRequest } from "./port.js";

const request = (over: Partial<StepRequest> = {}): StepRequest => ({ image: `node@sha256:${"c".repeat(64)}`, dir: "/snap", command: "echo hi", network: "none", timeoutMs: 60_000, ...over });
const limits = { pidsLimit: 128, memory: "512m", cpus: "1", tmpfs: ["/tmp:rw,size=64m,noexec,nosuid"], storageSize: "256m" };

describe("create arguments", () => {
  it("keep the existing defaults when no limits are given", () => {
    const args = buildCreateArgs("c1", request());
    expect(args).toEqual(expect.arrayContaining(["--pids-limit", "512", "--memory", "2g", "--cap-drop", "ALL", "--network", "none"]));
    expect(args).not.toContain("--storage-opt");
    expect(args).not.toContain("--tmpfs");
    expect(args).not.toContain("--read-only");
  });

  it("apply the process, memory, CPU, tmpfs and storage limits", () => {
    const args = buildCreateArgs("c1", request({ limits }));
    const pair = (flag: string) => args[args.indexOf(flag) + 1];
    expect(pair("--pids-limit")).toBe("128");
    expect(pair("--memory")).toBe("512m");
    expect(pair("--memory-swap")).toBe("512m");
    expect(pair("--cpus")).toBe("1");
    expect(pair("--tmpfs")).toBe("/tmp:rw,size=64m,noexec,nosuid");
    expect(pair("--storage-opt")).toBe("size=256m");
    expect(pair("--network")).toBe("none");
    expect(args).toEqual(expect.arrayContaining(["--cap-drop", "ALL", "--security-opt", "no-new-privileges"]));
  });

  it("mounts the root read-only with a size-capped tmpfs work folder, and leaves out the storage cap", () => {
    const args = buildCreateArgs("c1", request({ limits: { ...limits, readOnlyRoot: true } }));
    const mounts = args.flatMap((a, i) => (args[i - 1] === "--tmpfs" ? [a] : []));
    expect(args).toContain("--read-only");
    expect(mounts).toEqual(["/sandbox:rw,size=256m,noexec,nosuid,mode=755", "/tmp:rw,size=64m,noexec,nosuid"]);
    expect(args[args.indexOf("--workdir") + 1]).toBe("/sandbox/app");
    expect(args).not.toContain("--storage-opt");
    expect(args.slice(-3)).toEqual([expect.any(String), "-c", "sleep 86400"]);
  });

  it("can leave out the storage cap on request", () => {
    expect(buildCreateArgs("c1", request({ limits }), { storage: false })).not.toContain("--storage-opt");
  });
});

const snapshot = () => { const d = mkdtempSync(join(tmpdir(), "oci-unit-")); writeFileSync(join(d, "a.txt"), "x"); return d; };

describe("OciRunner with a read-only root", () => {
  it("starts first, streams the snapshot in over stdin, and never calls cp", async () => {
    const calls: Array<{ args: string[]; stdin: boolean }> = [];
    const exec = async (_f: string, args: string[], options: { stdin?: unknown }): Promise<ExecResult> => {
      calls.push({ args, stdin: Boolean(options.stdin) });
      (options.stdin as { resume?: () => void } | undefined)?.resume?.();
      await new Promise((r) => setTimeout(r, 50));
      return { code: 0, output: args[0] === "exec" && args.includes("-i") ? "" : "done", timedOut: false };
    };
    const runner = new OciRunner({ exec: exec as never, binaries: ["docker"] });
    const outcome = await runner.run(request({ dir: snapshot(), limits: { ...limits, readOnlyRoot: true } }));
    const verbs = calls.map((c) => c.args[0]);
    expect(verbs).toEqual(["info", "create", "start", "exec", "exec", "rm"]);
    expect(calls[3]).toMatchObject({ stdin: true });
    expect(calls[3]!.args).toEqual(expect.arrayContaining(["-i", "sh", "-c"]));
    expect(calls[4]!.args.slice(0, 4)).toEqual(["exec", "-w", "/sandbox/app", expect.any(String)]);
    expect(outcome).toMatchObject({ exitCode: 0, output: "done" });
  });

  it("reports a failed unpack as an infrastructure error and runs nothing", async () => {
    const exec = async (_f: string, args: string[]): Promise<ExecResult> => (args[0] === "exec" && args.includes("-i") ? { code: 1, output: "tar: no space left", timedOut: false } : { code: 0, output: "", timedOut: false });
    const outcome = await new OciRunner({ exec: exec as never, binaries: ["docker"] }).run(request({ dir: snapshot(), limits: { ...limits, readOnlyRoot: true } }));
    expect(outcome.infraError).toBe("could not copy the snapshot: tar: no space left");
  });
});

describe("OciRunner with limits", () => {
  const scripted = (refuseStorage: boolean) => {
    const calls: string[][] = [];
    const exec = async (_file: string, args: string[]): Promise<ExecResult> => {
      calls.push(args);
      if (args[0] === "info") return { code: 0, output: "27", timedOut: false };
      if (args[0] === "create" && refuseStorage && args.includes("--storage-opt")) return { code: 1, output: "Error: --storage-opt is supported only for overlay over xfs with 'pquota' mount option", timedOut: false };
      if (args[0] === "start") return { code: 0, output: "ok", timedOut: false };
      return { code: 0, output: "", timedOut: false };
    };
    return { calls, runner: new OciRunner({ exec: exec as never, binaries: ["docker"] }) };
  };

  it("passes the limits to docker create", async () => {
    const { calls, runner } = scripted(false);
    const outcome = await runner.run(request({ limits }));
    const create = calls.find((c) => c[0] === "create")!;
    expect(create).toEqual(expect.arrayContaining(["--storage-opt", "size=256m", "--pids-limit", "128", "--cpus", "1"]));
    expect(outcome.limitsNotApplied).toBeUndefined();
  });

  it("fails closed when the driver refuses the storage cap: no retry, no start, nothing runs", async () => {
    const { calls, runner } = scripted(true);
    const outcome = await runner.run(request({ limits }));
    expect(outcome.infraError).toBe(STORAGE_LIMIT_UNAVAILABLE);
    expect(outcome.infraError).toBe("storage limit unavailable: reproduction refused");
    expect(calls.filter((c) => c[0] === "create")).toHaveLength(1);
    expect(calls.some((c) => c[0] === "start" || c[0] === "cp" || c[0] === "exec")).toBe(false);
    expect(calls.at(-1)?.slice(0, 2)).toEqual(["rm", "-f"]);
  });

  it("retries without the storage cap only when the caller opted out, and says so", async () => {
    const { calls, runner } = scripted(true);
    const outcome = await runner.run(request({ limits: { ...limits, allowUnboundedStorage: true } }));
    const creates = calls.filter((c) => c[0] === "create");
    expect(creates).toHaveLength(2);
    expect(creates[1]).not.toContain("--storage-opt");
    expect(creates[1]).toEqual(expect.arrayContaining(["--pids-limit", "128", "--memory", "512m", "--tmpfs", "/tmp:rw,size=64m,noexec,nosuid"]));
    expect(outcome.limitsNotApplied).toEqual(["storage-size"]);
    expect(outcome.exitCode).toBe(0);
  });

  it("does not turn another create failure into an opt-out retry", async () => {
    const exec = async (_f: string, args: string[]) => (args[0] === "create" ? { code: 1, output: "pull access denied", timedOut: false } : { code: 0, output: "27", timedOut: false });
    const outcome = await new OciRunner({ exec: exec as never, binaries: ["docker"] }).run(request({ limits: { ...limits, allowUnboundedStorage: true } }));
    expect(outcome.infraError).toMatch(/could not create container: pull access denied/);
    expect(outcome.limitsNotApplied).toBeUndefined();
  });

  it("always removes the container", async () => {
    const { calls, runner } = scripted(false);
    await runner.run(request({ limits }));
    expect(calls.at(-1)?.slice(0, 2)).toEqual(["rm", "-f"]);
  });
});
