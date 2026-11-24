import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { planSandbox, type SandboxStatus } from "../sandbox/backend.js";
import { detectNodePermission, isNodeProgram, nodePermissionArgs, type NodePermissionSupport } from "../sandbox/node-permission.js";
import type { ResolvedSandbox, SandboxDecl } from "../sandbox/policy.js";

const run = promisify(execFile);
const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "nodeperm-test-")));
const ext = path.join(tmp, "ext"); const outside = path.join(tmp, "outside"); const data = path.join(ext, "data");
beforeAll(() => { for (const d of [ext, outside, data]) fs.mkdirSync(d, { recursive: true }); fs.writeFileSync(path.join(outside, "secret.txt"), "outside-secret"); fs.writeFileSync(path.join(ext, "in.txt"), "own-data"); });
afterAll(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

const decl = (over: Partial<SandboxDecl> = {}): SandboxDecl => ({ network: false, process: false, readPaths: [], writePaths: [], ...over });
const policy = (over: Partial<ResolvedSandbox> = {}): ResolvedSandbox => ({ extensionDir: "/e", scratchDir: "/s", workspace: null, network: false, process: false, readPaths: [], writePaths: [], execAllow: [], limits: {}, ...over });
const supported: NodePermissionSupport = { supported: true, flag: "--permission", detail: "node --permission" };
const noOs: SandboxStatus = { platform: "linux", seatbelt: { present: false, detail: "" }, bwrap: { present: false, detail: "bwrap not found in PATH" }, docker: { present: false, detail: "" }, backend: null, reason: "bwrap not found in PATH" };
const osStatus: SandboxStatus = { ...noOs, backend: "bwrap", bwrap: { present: true, path: "/usr/bin/bwrap", usable: true, detail: "works" } };

describe("node permission flags", () => {
  it("allows reads of the extension folder and scratch, writes of scratch only, no child programs", () => {
    const r = nodePermissionArgs(policy(), supported);
    expect(r).toEqual({ ok: true, args: ["--permission", "--allow-fs-read=/e", "--allow-fs-read=/s", "--allow-fs-write=/s"] });
  });
  it("adds declared read and write paths and child programs only with process", () => {
    const r = nodePermissionArgs(policy({ readPaths: ["/e/r"], writePaths: ["/e/w"], process: true }), supported);
    expect(r).toEqual({ ok: true, args: ["--permission", "--allow-fs-read=/e", "--allow-fs-read=/s", "--allow-fs-read=/e/r", "--allow-fs-read=/e/w", "--allow-fs-write=/s", "--allow-fs-write=/e/w", "--allow-child-process"] });
    expect(JSON.stringify(r)).not.toContain("allow-worker");
  });
  it("uses the experimental flag on older node and fails when there is none", () => {
    expect(nodePermissionArgs(policy(), { supported: true, flag: "--experimental-permission", detail: "" })).toMatchObject({ ok: true, args: [expect.stringMatching(/^--experimental-permission$/), ...Array(3).fill(expect.any(String))] });
    expect(nodePermissionArgs(policy(), { supported: false, detail: "old" })).toEqual({ ok: false, error: "old" });
  });
  it("refuses a path node would read as a wildcard", () => { expect(nodePermissionArgs(policy({ readPaths: ["/e/*"] }), supported).ok).toBe(false); });
  it("probes each flag in order", () => {
    const seen: string[] = [];
    const probe = (_f: string, a: string[]) => { seen.push(a[0]!); return { status: a[0] === "--experimental-permission" ? 0 : 1 }; };
    expect(detectNodePermission("/n", probe)).toEqual({ supported: true, flag: "--experimental-permission", detail: "node --experimental-permission" });
    expect(seen).toEqual(["--permission", "--experimental-permission"]);
    expect(detectNodePermission("/n", () => ({ status: 1 })).supported).toBe(false);
  });
  it("knows node by name", () => { expect(isNodeProgram("/usr/bin/node")).toBe(true); expect(isNodeProgram("/usr/bin/bash")).toBe(false); expect(isNodeProgram("/x/link", "/opt/node")).toBe(true); });
});

describe("planning with node permission", () => {
  const nodePath = process.execPath;
  const req = (d: SandboxDecl | null, argv = [nodePath, path.join(ext, "run.mjs")]) => ({ decl: d, extensionDir: ext, workspace: null, argv, interpreters: ["node"], env: { PATH: path.dirname(nodePath) }, cwd: tmp, label: "script run.mjs of ext" });
  it("is the only layer where no OS sandbox exists, and says the network is not restricted", () => {
    const p = planSandbox(req(decl()), { env: {}, status: noOs, nodeSupport: supported });
    expect(p.kind).toBe("sandboxed");
    if (p.kind === "sandboxed") { p.cleanup(); expect(p.file).toBe(nodePath); expect(p.args[0]).toBe("--permission"); expect(p.status).toMatch(/NOT restricted/); expect(p.status).not.toMatch(/network off/); }
  });
  it("is layered inside an OS sandbox when one exists", () => {
    const p = planSandbox(req(decl()), { env: {}, status: osStatus, nodeSupport: supported });
    expect(p.kind).toBe("sandboxed");
    if (p.kind === "sandboxed") { p.cleanup(); const i = p.args.lastIndexOf(nodePath); expect(p.file).toBe("/usr/bin/bwrap"); expect(p.args[i + 1]).toBe("--permission"); expect(p.status).toMatch(/network off.*--permission/); }
  });
  it("does not touch a program that is not node", () => {
    const p = planSandbox(req(decl(), ["/bin/sh", path.join(ext, "x.sh")]), { env: {}, status: noOs, nodeSupport: supported });
    expect(p.kind).toBe("unsandboxed");
  });
  it("ZERO_SANDBOX_NODE_PERMISSION=off leaves the flags out", () => {
    expect(planSandbox(req(decl()), { env: { ZERO_SANDBOX_NODE_PERMISSION: "off" }, status: noOs, nodeSupport: supported }).kind).toBe("unsandboxed");
  });
  it("require refuses without an OS sandbox, since node cannot hold the network off, unless the network is declared", () => {
    expect(planSandbox(req(decl()), { env: { ZERO_SANDBOX: "require" }, status: noOs, nodeSupport: supported }).kind).toBe("refused");
    const p = planSandbox(req(decl({ network: true })), { env: { ZERO_SANDBOX: "require" }, status: noOs, nodeSupport: supported });
    expect(p.kind).toBe("sandboxed"); if (p.kind === "sandboxed") p.cleanup();
  });
  it("runs unsandboxed with the old note on a node with no permission model", () => {
    expect(planSandbox(req(decl()), { env: {}, status: noOs, nodeSupport: { supported: false, detail: "old" } })).toEqual({ kind: "unsandboxed", status: "sandbox: not available (bwrap not found in PATH); ran without it" });
  });
});

const real = detectNodePermission(process.execPath);
describe.skipIf(!real.supported)("real node --permission", () => {
  const exec = async (body: string, d: SandboxDecl) => {
    fs.writeFileSync(path.join(ext, "run.mjs"), body);
    const plan = planSandbox({ decl: d, extensionDir: ext, workspace: null, argv: [process.execPath, path.join(ext, "run.mjs")], interpreters: ["node"], env: { PATH: path.dirname(process.execPath) }, cwd: tmp, label: "script run.mjs of ext" }, { env: {}, status: noOs });
    if (plan.kind !== "sandboxed") throw new Error(`not sandboxed: ${JSON.stringify(plan)}`);
    try { const r = await run(plan.file, plan.args, { cwd: plan.cwd, env: plan.env, timeout: 15_000 }); return { stdout: r.stdout, stderr: r.stderr, plan }; }
    catch (e) { const x = e as { stdout?: string; stderr?: string }; return { stdout: x.stdout ?? "", stderr: x.stderr ?? "", plan }; }
    finally { plan.cleanup(); }
  };
  const probe = `
import fs from "node:fs"; import cp from "node:child_process";
const t = (name, fn) => { try { fn(); console.log(name + ":ALLOWED"); } catch (e) { console.log(name + ":" + (e.code ?? e.name)); } };
t("read-own", () => fs.readFileSync(${JSON.stringify(path.join(ext, "in.txt"))}));
t("read-outside", () => fs.readFileSync(${JSON.stringify(path.join(outside, "secret.txt"))}));
t("read-home-ssh", () => fs.readdirSync(${JSON.stringify(path.join(os.homedir(), ".ssh"))}));
t("write-scratch", () => fs.writeFileSync(process.env.TMPDIR + "/o.txt", "x"));
t("write-outside", () => fs.writeFileSync(${JSON.stringify(path.join(outside, "w.txt"))}, "x"));
t("write-own", () => fs.writeFileSync(${JSON.stringify(path.join(ext, "w.txt"))}, "x"));
t("write-declared", () => fs.writeFileSync(${JSON.stringify(path.join(data, "d.txt"))}, "x"));
t("spawn", () => cp.execFileSync(process.execPath, ["-e", "0"]));
`;
  it("reads its own folder and writes scratch; cannot read outside or ~/.ssh, write outside, or spawn", async () => {
    const r = await exec(probe, decl());
    console.log("[node --permission]", r.stdout.trim().replace(/\n/g, " | "), "| flag:", real.flag);
    const lines = Object.fromEntries(r.stdout.trim().split("\n").map(l => l.split(":") as [string, string]));
    expect(lines["read-own"]).toBe("ALLOWED"); expect(lines["write-scratch"]).toBe("ALLOWED");
    for (const name of ["read-outside", "read-home-ssh", "write-outside", "write-own", "write-declared", "spawn"]) expect(lines[name], name).toBe("ERR_ACCESS_DENIED");
    expect(fs.existsSync(path.join(outside, "w.txt"))).toBe(false);
  });
  it("allows a declared write path and, with process, a child program", async () => {
    const r = await exec(probe, decl({ writePaths: ["data"], process: true }));
    const lines = Object.fromEntries(r.stdout.trim().split("\n").map(l => l.split(":") as [string, string]));
    expect(lines["write-declared"]).toBe("ALLOWED"); expect(lines["spawn"]).toBe("ALLOWED"); expect(lines["write-outside"]).toBe("ERR_ACCESS_DENIED");
  });
});
