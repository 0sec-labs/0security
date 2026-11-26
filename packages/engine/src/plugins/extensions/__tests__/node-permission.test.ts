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
  it("unwraps env node so node --permission still applies", () => {
    const p = planSandbox(req(decl(), ["/usr/bin/env", nodePath, path.join(ext, "run.mjs")]), { env: {}, status: noOs, nodeSupport: supported });
    expect(p.kind).toBe("sandboxed");
    if (p.kind === "sandboxed") { p.cleanup(); expect(p.file).toBe(nodePath); expect(p.args[0]).toBe("--permission"); }
  });
});

describe("launchers that start node", () => {
  const nodePath = process.execPath; const script = path.join(ext, "run.mjs");
  const plan = (argv: string[], envVars: Record<string, string> = {}) => planSandbox({ decl: decl(), extensionDir: ext, workspace: null, argv, interpreters: ["node"], env: { PATH: path.dirname(nodePath), ...envVars }, cwd: tmp, label: "MCP server s of extension x" }, { env: {}, status: noOs, nodeSupport: supported });
  type Row = { name: string; argv: string[]; env?: Record<string, string>; outcome: "applied" | "unsandboxed" | "refused"; reason?: RegExp; childEnv?: Record<string, string | undefined> };
  const ENV = "/usr/bin/env";
  const rows: Row[] = [
    { name: "node directly", argv: [nodePath, script], outcome: "applied" },
    { name: "env node", argv: [ENV, nodePath, script], outcome: "applied" },
    { name: "env found through PATH", argv: [ENV, "node", script], outcome: "applied" },
    { name: "env with an assignment", argv: [ENV, "FOO=1", nodePath, script], outcome: "applied", childEnv: { FOO: "1" } },
    { name: "env with several assignments", argv: [ENV, "A=1", "B=two words", nodePath, script], outcome: "applied", childEnv: { A: "1", B: "two words" } },
    { name: "env -i", argv: [ENV, "-i", nodePath, script], outcome: "applied", childEnv: { PATH: undefined } },
    { name: "env - (same as -i)", argv: [ENV, "-", "X=1", nodePath, script], outcome: "applied", childEnv: { PATH: undefined, X: "1" } },
    { name: "env --ignore-environment", argv: [ENV, "--ignore-environment", nodePath, script], outcome: "applied", childEnv: { PATH: undefined } },
    { name: "env -u NAME", argv: [ENV, "-u", "SECRET", nodePath, script], env: { SECRET: "s" }, outcome: "applied", childEnv: { SECRET: undefined } },
    { name: "env -uNAME", argv: [ENV, "-uSECRET", nodePath, script], env: { SECRET: "s" }, outcome: "applied", childEnv: { SECRET: undefined } },
    { name: "env --unset=NAME", argv: [ENV, "--unset=SECRET", nodePath, script], env: { SECRET: "s" }, outcome: "applied", childEnv: { SECRET: undefined } },
    { name: "env --", argv: [ENV, "--", nodePath, script], outcome: "applied" },
    { name: "env -iu bundle", argv: [ENV, "-iuX", "K=1", nodePath, script], outcome: "applied", childEnv: { K: "1" } },
    { name: "env -S split string", argv: [ENV, "-S", `${nodePath} ${script}`], outcome: "applied" },
    { name: "env -S with quoting", argv: [ENV, "-S", `K='a b' "${nodePath}" "${script}"`], outcome: "applied", childEnv: { K: "a b" } },
    { name: "env -S attached", argv: [ENV, `-S${nodePath} ${script}`], outcome: "applied" },
    { name: "env nested in env", argv: [ENV, "A=1", ENV, "B=2", nodePath, script], outcome: "applied", childEnv: { A: "1", B: "2" } },
    { name: "PATH assignment picks node", argv: [ENV, `PATH=${path.dirname(nodePath)}`, "node", script], env: { PATH: "/nonexistent" }, outcome: "applied" },
    { name: "env running a non-node program", argv: [ENV, "FOO=1", "/bin/sh", "x.sh"], outcome: "unsandboxed" },
    { name: "env -C (cwd change)", argv: [ENV, "-C", "/", nodePath, script], outcome: "refused", reason: /-C is not understood/ },
    { name: "env --chdir", argv: [ENV, "--chdir=/", nodePath, script], outcome: "refused", reason: /not understood/ },
    { name: "env -0", argv: [ENV, "-0", nodePath, script], outcome: "refused", reason: /not understood/ },
    { name: "env with no program", argv: [ENV, "A=1"], outcome: "refused", reason: /no program/ },
    { name: "env -S with a variable", argv: [ENV, "-S", nodePath + " ${X}"], outcome: "refused", reason: /\$ variable/ },
    { name: "env -S with an open quote", argv: [ENV, "-S", `${nodePath} "${script}`], outcome: "refused", reason: /not closed/ },
    { name: "env -S with the c escape", argv: [ENV, "-S", nodePath + " \\c " + script], outcome: "refused", reason: /escape \\c/ },
    { name: "env -S with a comment", argv: [ENV, "-S", `${nodePath} #x`], outcome: "refused", reason: /comment/ },
    { name: "env -u with no name", argv: [ENV, "-u"], outcome: "refused", reason: /needs a value/ },
    { name: "env -S widening flag", argv: [ENV, "-S", `${nodePath} --allow-fs-read=* ${script}`], outcome: "refused", reason: /would change node's permissions/ },
    { name: "env assignment widening NODE_OPTIONS", argv: [ENV, "NODE_OPTIONS=--allow-fs-write=*", nodePath, script], outcome: "refused", reason: /would change node's permissions/ },
    { name: "env assignment with --no-permission", argv: [ENV, "NODE_OPTIONS=--max-old-space-size=64 --no-permission", nodePath, script], outcome: "refused", reason: /--no-permission/ },
    { name: "env assignment with quoted flag", argv: [ENV, 'NODE_OPTIONS="--allow-child-process"', nodePath, script], outcome: "refused", reason: /would change/ },
    { name: "env assignment with --env-file", argv: [ENV, "NODE_OPTIONS=--env-file=x.env", nodePath, script], outcome: "refused", reason: /--env-file/ },
    { name: "lower-case node_options (Windows names are case-insensitive)", argv: [ENV, "node_options=--allow-fs-read=*", nodePath, script], outcome: "refused", reason: /would change node's permissions/ },
    { name: "lower-case ld_preload", argv: [ENV, "ld_preload=/x/y.so", nodePath, script], outcome: "refused", reason: /ld_preload/ },
    { name: "env -i then a bare node name (PATH unset, found nowhere we can see)", argv: [ENV, "-i", "nosuchprogram-xyz", script], outcome: "refused", reason: /not found in PATH/ },
    { name: "env -u PATH then a bare name", argv: [ENV, "-u", "PATH", "nosuchprogram-xyz", script], outcome: "refused", reason: /not found in PATH/ },
    { name: "env with a relative PATH entry", argv: [ENV, "PATH=bin", "node", script], outcome: "refused", reason: /relative or empty entry/ },
    { name: "env with an empty PATH entry", argv: [ENV, `PATH=${path.dirname(nodePath)}:`, "node", script], outcome: "refused", reason: /relative or empty entry/ },
    { name: "env with a program that is not found", argv: [ENV, "nosuchprogram-xyz", script], outcome: "refused", reason: /not found in PATH/ },
    { name: "cmd /c", argv: ["C:\\Windows\\System32\\cmd.exe", "/c", "node x"], outcome: "refused", reason: /cmd runs a command syntax/ },
    { name: "powershell -Command", argv: ["/usr/bin/pwsh", "-Command", "node x"], outcome: "refused", reason: /pwsh runs a command syntax/ },
    { name: "timeout sh -c with hidden node", argv: ["/usr/bin/timeout", "5", "/bin/sh", "-c", 'n"o"de x'], outcome: "refused", reason: /timeout wraps/ },
    { name: "nice -n 5 sh", argv: ["/usr/bin/nice", "-n", "5", "/bin/bash", "run.sh"], outcome: "refused", reason: /nice wraps/ },
    { name: "env -u clears a widening NODE_OPTIONS", argv: [ENV, "-u", "NODE_OPTIONS", nodePath, script], env: { NODE_OPTIONS: "--allow-fs-read=*" }, outcome: "applied" },
    { name: "env assignment LD_PRELOAD", argv: [ENV, "LD_PRELOAD=/x/y.so", nodePath, script], outcome: "refused", reason: /LD_PRELOAD/ },
    { name: "env assignment DYLD_INSERT_LIBRARIES", argv: [ENV, "DYLD_INSERT_LIBRARIES=/x", nodePath, script], outcome: "refused", reason: /DYLD_INSERT_LIBRARIES/ },
    { name: "NODE_OPTIONS with --import is allowed (node applies permissions first)", argv: [nodePath, script], env: { NODE_OPTIONS: "--import ./hook.mjs --require ./hook.cjs" }, outcome: "applied" },
    { name: "NODE_OPTIONS config file", argv: [nodePath, script], env: { NODE_OPTIONS: "--experimental-config-file=x.json" }, outcome: "refused", reason: /config-file/ },
    ...["command", "exec", "nice", "nohup", "timeout", "sudo", "xargs", "arch", "setsid", "stdbuf", "doas"].map((w): Row => ({ name: `${w} node`, argv: [`/usr/bin/${w}`, ...(w === "timeout" ? ["5"] : []), nodePath, script], outcome: "refused", reason: new RegExp(`${w} wraps another program`) })),
    { name: "timeout with a non-node program", argv: ["/usr/bin/timeout", "5", "/usr/bin/python3", "node_modules/x.py"], outcome: "unsandboxed" },
    { name: "sh script (no node layer, documented)", argv: ["/bin/sh", path.join(ext, "x.sh")], outcome: "unsandboxed" },
    ...["sh", "bash", "zsh", "dash", "ash", "ksh", "fish", "csh", "tcsh", "nu", "nushell", "xonsh", "elvish"].flatMap(sh => [
      ["-c", "node x"], ["-c", "echo hi"], ["-lc", "node x"], ["-ec", "node x"], ["--command", "node x"], ["--command=node x"], ["-x", "-c", "n\"o\"de x"], ["-o", "pipefail", "-c", "$(echo node)"], ["--", "-c", "x"],
    ].map((flags): Row => ({ name: `${sh} ${flags.join(" ")}`, argv: [`/usr/bin/${sh}`, ...flags], outcome: "refused", reason: new RegExp(`${sh} runs a code or command string`) }))),
    { name: "shell with .exe suffix", argv: ["C:\\tools\\bash.exe", "-c", "node x"], outcome: "refused", reason: /bash runs/ },
    { name: "shell in upper case (Windows)", argv: ["C:\\TOOLS\\BASH.EXE", "-C", "node x"], outcome: "refused", reason: /bash runs/ },
    { name: "shell with a quoted path", argv: ['"/usr/bin/zsh"', "-c", "node x"], outcome: "refused", reason: /zsh runs/ },
    { name: "env-wrapped shell", argv: [ENV, "A=1", "/bin/sh", "-c", "node x"], outcome: "refused", reason: /sh runs/ },
    { name: "env -S wrapped shell", argv: [ENV, "-S", "/bin/sh -c 'node x'"], outcome: "refused", reason: /sh runs/ },
    { name: "busybox sh -c", argv: ["/bin/busybox", "sh", "-c", "node x"], outcome: "refused", reason: /busybox wraps/ },
    ...["cmd.exe", "CMD.EXE", "powershell.exe", "PowerShell.exe", "pwsh"].flatMap(sh => ["/c", "/k", "/C", "-Command", "-c", "-EncodedCommand", "-File"].map((f): Row => ({ name: `${sh} ${f}`, argv: [`C:\\Windows\\${sh}`, f, "node x"], outcome: "refused", reason: /runs a command syntax/ }))),
    ...[["/usr/bin/python3", "-c", "import os"], ["/usr/bin/python", "-Sc", "x"], ["/usr/bin/perl", "-e", "x"], ["/usr/bin/perl", "-E", "x"], ["/usr/bin/ruby", "-e", "x"], ["/usr/bin/php", "-r", "x"], ["/usr/bin/lua", "-e", "x"], ["/usr/local/bin/bun", "-e", "x"], ["/usr/local/bin/deno", "eval", "x"], ["/usr/bin/osascript", "-e", "x"]].map((argv): Row => ({ name: `${argv.join(" ")} (inline code)`, argv, outcome: "refused", reason: /runs a code or command string/ })),
    { name: "timeout python -c", argv: ["/usr/bin/timeout", "5", "/usr/bin/python3", "-c", "x"], outcome: "refused", reason: /timeout wraps/ },
    { name: "python script file (no node layer, documented)", argv: ["/usr/bin/python3", path.join(ext, "x.py")], outcome: "unsandboxed" },
    { name: "python -m module", argv: ["/usr/bin/python3", "-m", "mymod"], outcome: "unsandboxed" },
    { name: "bash script with flags", argv: ["/bin/bash", "-e", "-u", path.join(ext, "x.sh"), "--flag"], outcome: "unsandboxed" },
    { name: "bash script in /code", argv: ["/bin/bash", "/code/run.sh"], outcome: "unsandboxed" },
    { name: "perl script file", argv: ["/usr/bin/perl", path.join(ext, "x.pl")], outcome: "unsandboxed" },
    ...["npx", "pnpx", "bunx", "npm", "pnpm", "yarn", "volta", "fnm", "nvm", "asdf", "mise", "nodenv", "corepack"].map((w): Row => ({ name: `${w} chooses node`, argv: [`/usr/local/bin/${w}`, "run", "x"], outcome: "refused", reason: new RegExp(`${w} picks the node program itself`) })),
    { name: "volta run node", argv: ["/usr/local/bin/volta", "run", "node", script], outcome: "refused", reason: /volta picks/ },
    { name: "fnm exec", argv: ["/usr/local/bin/fnm", "exec", "--using=20", "node", script], outcome: "refused", reason: /fnm picks/ },
    { name: "env npx", argv: [ENV, "A=1", "/usr/local/bin/npx", "server"], outcome: "refused", reason: /npx picks/ },
    { name: "env timeout node", argv: [ENV, "A=1", "/usr/bin/timeout", "5", nodePath, script], outcome: "refused", reason: /timeout wraps/ },
  ];
  it.each(rows)("$name -> $outcome", row => {
    const p = plan(row.argv, row.env);
    if (row.outcome === "refused") {
      expect(p.kind).toBe("refused");
      if (p.kind === "refused") { expect(p.error).toMatch(row.reason!); expect(p.error).toContain("MCP server s of extension x"); }
      return;
    }
    if (row.outcome === "unsandboxed") { expect(p.kind).toBe("unsandboxed"); return; }
    expect(p.kind).toBe("sandboxed");
    if (p.kind !== "sandboxed") return;
    p.cleanup();
    expect(p.file).toBe(nodePath);
    expect(p.args[0]).toBe("--permission");
    expect(p.args.at(-1)).toBe(script);
    expect(p.args).not.toContain(ENV);
    for (const [k, v] of Object.entries(row.childEnv ?? {})) expect(p.env[k]).toBe(v);
  });
  it("keeps the environment of a direct node start unchanged", () => {
    const p = plan([nodePath, script], { KEEP: "1" });
    expect(p.kind).toBe("sandboxed");
    if (p.kind === "sandboxed") { p.cleanup(); expect(p.env.KEEP).toBe("1"); expect(p.env.ZERO_SANDBOX_ACTIVE).toBe("1"); }
  });
  it("ZERO_SANDBOX_NODE_PERMISSION=off is the explicit way past a refused launcher", () => {
    const p = planSandbox({ decl: decl(), extensionDir: ext, workspace: null, argv: ["/usr/bin/timeout", "5", nodePath, script], interpreters: ["node"], env: { PATH: path.dirname(nodePath) }, cwd: tmp, label: "x" }, { env: { ZERO_SANDBOX_NODE_PERMISSION: "off" }, status: noOs, nodeSupport: supported });
    expect(p.kind).toBe("unsandboxed");
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
  it("refuses extension args or NODE_OPTIONS that would widen node's permissions, and keeps ordinary node flags", () => {
    const base = { decl: decl(), extensionDir: ext, workspace: null, interpreters: ["node"], cwd: tmp, label: "MCP server evil of extension evil" };
    for (const arg of ["--allow-fs-read=*", "--allow-fs-write=*", "--allow-child-process", "--allow_fs_read=*", "--no-permission", "--env-file=x.env"]) {
      const plan = planSandbox({ ...base, argv: [process.execPath, arg, path.join(ext, "run.mjs")], env: { PATH: path.dirname(process.execPath) } }, { env: {}, status: noOs, nodeSupport: supported });
      expect(plan.kind).toBe("refused");
    }
    const viaEnv = planSandbox({ ...base, argv: [process.execPath, path.join(ext, "run.mjs")], env: { PATH: path.dirname(process.execPath), NODE_OPTIONS: "--allow-fs-read=*" } }, { env: {}, status: noOs, nodeSupport: supported });
    expect(viaEnv.kind).toBe("refused");
    const ok = planSandbox({ ...base, argv: [process.execPath, "--enable-source-maps", path.join(ext, "run.mjs")], env: { PATH: path.dirname(process.execPath), NODE_OPTIONS: "--max-old-space-size=256" } }, { env: {}, status: noOs, nodeSupport: supported });
    expect(ok.kind).toBe("sandboxed");
    if (ok.kind === "sandboxed") { ok.cleanup(); expect(ok.args).toContain("--enable-source-maps"); expect(ok.args).not.toContain("--"); }
  });
});
