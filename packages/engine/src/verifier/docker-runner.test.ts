import { describe, expect, it } from "vitest";
import { OciRunner, buildCreateArgs } from "./docker-runner.js";
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

  it("can mount the root file system read-only, and leave out the storage cap on request", () => {
    expect(buildCreateArgs("c1", request({ limits: { readOnlyRoot: true } }))).toContain("--read-only");
    expect(buildCreateArgs("c1", request({ limits }), { storage: false })).not.toContain("--storage-opt");
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

  it("retries without the storage cap when the driver refuses it, and says so", async () => {
    const { calls, runner } = scripted(true);
    const outcome = await runner.run(request({ limits }));
    const creates = calls.filter((c) => c[0] === "create");
    expect(creates).toHaveLength(2);
    expect(creates[1]).not.toContain("--storage-opt");
    expect(creates[1]).toEqual(expect.arrayContaining(["--pids-limit", "128", "--memory", "512m"]));
    expect(outcome.limitsNotApplied).toEqual(["storage-size"]);
    expect(outcome.exitCode).toBe(0);
  });

  it("always removes the container", async () => {
    const { calls, runner } = scripted(false);
    await runner.run(request({ limits }));
    expect(calls.at(-1)?.slice(0, 2)).toEqual(["rm", "-f"]);
  });
});
