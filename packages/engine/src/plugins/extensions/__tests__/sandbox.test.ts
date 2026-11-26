import { execFile } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { capabilitiesOf, capabilityKey, capabilityLines } from "../core/capabilities.js";
import type { FolderFile } from "../core/files.js";
import { parseManifest } from "../core/manifest.js";
import { bwrapArgs, type HostLayout } from "../sandbox/bwrap.js";
import { detectSandbox, planSandbox, sandboxMode, whichIn, withLimits, type DetectHost, type SandboxStatus } from "../sandbox/backend.js";
import { parseSandboxDecl, resolveDeclaredPath, resolveSandbox, WORKSPACE_TOKEN, type ResolvedSandbox, type SandboxDecl } from "../sandbox/policy.js";
import { seatbeltArgs, seatbeltProfile } from "../sandbox/seatbelt.js";

const run = promisify(execFile);
const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sbx-test-")));
const ext = path.join(tmp, "ext"); const scratch = path.join(tmp, "scratch"); const outside = path.join(tmp, "outside");
beforeAll(() => { for (const d of [ext, scratch, outside, path.join(ext, "data"), path.join(ext, "scripts")]) fs.mkdirSync(d, { recursive: true }); fs.writeFileSync(path.join(outside, "secret.txt"), "top-secret"); fs.writeFileSync(path.join(ext, "data", "in.txt"), "own-data"); });
afterAll(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

const policy = (over: Partial<ResolvedSandbox> = {}): ResolvedSandbox => ({ extensionDir: ext, scratchDir: scratch, workspace: null, network: false, process: false, programs: [], readPaths: [], writePaths: [], execAllow: ["/bin/sh", "/usr/bin/env"], limits: {}, ...over });
const decl = (over: Partial<SandboxDecl> = {}): SandboxDecl => ({ network: false, process: false, programs: [], readPaths: [], writePaths: [], ...over });

describe("sandbox declaration", () => {
  it("defaults to everything off and strict keys", () => {
    expect(parseSandboxDecl({})).toEqual({ ok: true, value: { network: false, process: false, programs: [], readPaths: [], writePaths: [] } });
    expect(parseSandboxDecl({ network: true, hosts: ["x"] }).ok).toBe(false);
    expect(parseSandboxDecl({ network: "yes" }).ok).toBe(false);
  });
  it("normalises, de-duplicates and sorts paths", () => {
    const r = parseSandboxDecl({ readPaths: ["./data/", "data", "c//d", WORKSPACE_TOKEN] });
    expect(r).toEqual({ ok: true, value: { network: false, process: false, programs: [], readPaths: ["$WORKSPACE", "c/d", "data"], writePaths: [] } });
  });
  it.each(["../x", "a/../../x", "/etc/passwd", "~/.ssh", "C:\\x", "a\\b", "..", ".", "a\0b", 'a"b', "b/../c", ""])("rejects path %j", p => {
    expect(parseSandboxDecl({ readPaths: [p] }).ok).toBe(false);
  });
  it("rejects too many paths", () => { expect(parseSandboxDecl({ readPaths: Array.from({ length: 17 }, (_, i) => `p${i}`) }).ok).toBe(false); });
});

describe("path resolution", () => {
  it("resolves a path inside the extension folder", () => {
    expect(resolveDeclaredPath("data", ext, null)).toEqual({ ok: true, path: path.join(ext, "data") });
  });
  it("refuses a missing path", () => { expect(resolveDeclaredPath("nope", ext, null).ok).toBe(false); });
  it("refuses traversal even if it reaches a real folder", () => {
    const r = resolveDeclaredPath("../outside", ext, null); expect(r.ok).toBe(false);
  });
  it("refuses a symlink that leaves the extension folder", () => {
    fs.symlinkSync(outside, path.join(ext, "link-out"));
    const r = resolveDeclaredPath("link-out", ext, null); expect(r.ok).toBe(false); if (!r.ok) expect(r.error).toMatch(/symlink that leaves/);
  });
  it("refuses a symlinked parent that leaves the extension folder", () => {
    fs.symlinkSync(outside, path.join(ext, "link-parent"));
    expect(resolveDeclaredPath("link-parent/secret.txt", ext, null).ok).toBe(false);
  });
  it("allows a symlink that stays inside", () => {
    fs.symlinkSync(path.join(ext, "data"), path.join(ext, "link-in"));
    expect(resolveDeclaredPath("link-in", ext, null)).toEqual({ ok: true, path: path.join(ext, "data") });
  });
  it("needs a workspace for the workspace token", () => {
    expect(resolveDeclaredPath(WORKSPACE_TOKEN, ext, null).ok).toBe(false);
    expect(resolveDeclaredPath(WORKSPACE_TOKEN, ext, outside)).toEqual({ ok: true, path: outside });
  });
  it("resolveSandbox stops at the first bad path", () => {
    const r = resolveSandbox({ decl: decl({ readPaths: ["data", "nope"] }), extensionDir: ext, scratchDir: scratch, workspace: null, execAllow: [] });
    expect(r.ok).toBe(false);
  });
});

describe("Seatbelt profile", () => {
  it("has no network rule when the network is off, and no home access", () => {
    const { profile, params } = seatbeltProfile(policy());
    expect(profile).toContain("(deny default)");
    expect(profile).not.toMatch(/network/);
    expect(profile).not.toMatch(/\/Users|\/home[/"]|\.ssh|\.aws|\.0\b/);
    expect(Object.values(params).some(v => v.startsWith(os.homedir() + path.sep))).toBe(false);
  });
  it("hides the existence of home files except the folders that lead to allowed paths", () => {
    const home = "/Users/someone"; const extIn = `${home}/.0/extensions/demo/rev`;
    const { profile, params } = seatbeltProfile(policy({ home, extensionDir: extIn }));
    expect(profile).toContain('(deny file-read-metadata (subpath (param "HOME")))');
    expect(Object.values(params)).toEqual(expect.arrayContaining([home, `${home}/.0`, `${home}/.0/extensions`, `${home}/.0/extensions/demo`]));
    expect(Object.values(params)).not.toContain(`${home}/.ssh`);
    expect(profile.indexOf("deny file-read-metadata")).toBeLessThan(profile.indexOf("(allow file-read* (subpath (param \"EXT_DIR\"))"));
  });
  it("adds a network rule only when allowed", () => { expect(seatbeltProfile(policy({ network: true })).profile).toContain("(allow network*)"); });
  it("writes only to scratch, /dev/null and declared write paths", () => {
    const writeRules = (p: ResolvedSandbox) => seatbeltProfile(p).profile.split("\n").filter(l => l.startsWith("(allow file-write"));
    expect(writeRules(policy())).toEqual(['(allow file-write* (subpath (param "SCRATCH")) (literal "/dev/null") )']);
    expect(writeRules(policy({ writePaths: [path.join(ext, "data")] }))[0]).toContain('(param "WRITE0")');
  });
  it("passes every policy path as a parameter, never in the profile text", () => {
    const evil = `${ext}/a") (allow network*) ("`;
    const { profile, params } = seatbeltProfile(policy({ readPaths: [evil], execAllow: [evil] }));
    expect(profile).not.toContain("a\")");
    expect(Object.values(params)).toContain(evil);
    expect(profile).not.toContain("(allow network*)");
    expect(seatbeltArgs({ profile, params })).toContain(`READ0=${evil}`);
  });
  it("allows system program folders only with process", () => {
    expect(seatbeltProfile(policy()).profile).not.toContain('"/usr/bin"');
    expect(seatbeltProfile(policy({ process: true })).profile).toContain('(subpath "/usr/bin")');
  });
});

describe("bubblewrap arguments", () => {
  const layout = (links: Record<string, string>, dirs: string[]): HostLayout => ({ kind: p => (p in links ? "symlink" : dirs.includes(p) ? "dir" : null), readlink: p => links[p] ?? null });
  const merged = layout({ "/bin": "usr/bin", "/sbin": "usr/sbin", "/lib": "usr/lib", "/lib64": "usr/lib64" }, ["/usr", "/usr/lib", "/usr/lib64", "/usr/bin/bash", "/etc/ssl", "/etc/ld.so.cache", "/etc/resolv.conf"]);
  const args = (p: ResolvedSandbox, cwd = ext) => bwrapArgs(p, { cwd, layout: merged });
  const binds = (a: string[], flag: string) => a.flatMap((x, i) => (x === flag ? [[a[i + 1]!, a[i + 2]!]] : []));
  it("unshares everything, drops capabilities and has no network by default", () => {
    const a = args(policy());
    expect(a).toContain("--unshare-all"); expect(a).not.toContain("--share-net");
    expect(a.join(" ")).toContain("--cap-drop ALL"); expect(a.at(-1)).toBe("--");
    expect(a).toContain("--die-with-parent");
  });
  it("shares the network only when allowed and mounts resolver files then", () => {
    expect(args(policy({ network: true }))).toContain("--share-net");
    expect(binds(args(policy({ network: true })), "--ro-bind").map(b => b[0])).toContain("/etc/resolv.conf");
    expect(binds(args(policy()), "--ro-bind").map(b => b[0])).not.toContain("/etc/resolv.conf");
  });
  it("mounts no home, no /etc wholesale, and only scratch plus declared paths writable", () => {
    const a = args(policy({ writePaths: [path.join(ext, "data")] }));
    expect(a.join(" ")).not.toContain(os.homedir());
    expect(binds(a, "--bind")).toEqual([[scratch, scratch], [path.join(ext, "data"), path.join(ext, "data")]]);
    expect(binds(a, "--ro-bind").map(b => b[0])).not.toContain("/etc");
    expect(binds(a, "--ro-bind").map(b => b[0])).not.toContain("/");
    expect(binds(a, "--ro-bind").map(b => b[0])).toContain(ext);
  });
  it("mounts only the allowlisted program files without process, whole program folders with it", () => {
    const strict = binds(args(policy({ execAllow: ["/usr/bin/bash"] })), "--ro-bind").map(b => b[0]);
    expect(strict).toContain("/usr/bin/bash"); expect(strict).not.toContain("/usr"); expect(strict).toContain("/usr/lib");
    const open = args(policy({ process: true }));
    expect(binds(open, "--ro-bind").map(b => b[0])).toContain("/usr");
    expect(open).toContain("--symlink"); expect(open.join(" ")).toContain("--symlink usr/bin /bin");
  });
  it("starts in the given folder", () => { const a = args(policy(), scratch); expect(a.slice(a.indexOf("--chdir"), a.indexOf("--chdir") + 2)).toEqual(["--chdir", scratch]); });
});

describe("mode and backend selection", () => {
  const none: SandboxStatus = { platform: "linux", seatbelt: { present: false, detail: "" }, bwrap: { present: false, detail: "bwrap not found in PATH" }, docker: { present: false, detail: "" }, backend: null, reason: "bwrap not found in PATH" };
  const req = (d: SandboxDecl | null) => ({ decl: d, extensionDir: ext, workspace: null, argv: ["/bin/sh", path.join(ext, "scripts", "x.sh")], interpreters: ["sh"], env: { PATH: "/usr/bin:/bin" }, cwd: tmp, label: "script x of extension demo" });
  it("parses ZERO_SANDBOX", () => {
    expect(sandboxMode({})).toEqual({ ok: true, mode: "auto" });
    expect(sandboxMode({ ZERO_SANDBOX: "REQUIRE" })).toEqual({ ok: true, mode: "require" });
    expect(sandboxMode({ ZERO_SANDBOX: "requre" }).ok).toBe(false);
  });
  it("require refuses to run when no backend exists", () => {
    const p = planSandbox(req(decl()), { env: { ZERO_SANDBOX: "require" }, status: none });
    expect(p.kind).toBe("refused"); if (p.kind === "refused") expect(p.error).toMatch(/ZERO_SANDBOX=require but no sandbox is available \(bwrap not found/);
  });
  it("require refuses even an extension with no block", () => { expect(planSandbox(req(null), { env: { ZERO_SANDBOX: "require" }, status: none }).kind).toBe("refused"); });
  it("auto runs unsandboxed with a note when no backend exists", () => {
    const p = planSandbox(req(decl()), { env: {}, status: none });
    expect(p).toEqual({ kind: "unsandboxed", status: "sandbox: not available (bwrap not found in PATH); ran without it" });
  });
  it("auto leaves an extension with no block alone; off never sandboxes", () => {
    const ok: SandboxStatus = { ...none, backend: "bwrap", bwrap: { present: true, path: "/usr/bin/bwrap", usable: true, detail: "works" } };
    const p = planSandbox(req(null), { env: {}, status: ok }); expect(p.kind).toBe("unsandboxed"); if (p.kind === "unsandboxed") expect(p.status).toMatch(/declares no sandbox block/);
    expect(planSandbox(req(decl()), { env: { ZERO_SANDBOX: "off" }, status: ok })).toEqual({ kind: "unsandboxed", status: "sandbox: not applied (ZERO_SANDBOX=off)" });
  });
  it("an invalid ZERO_SANDBOX refuses instead of running unsandboxed", () => { expect(planSandbox(req(decl()), { env: { ZERO_SANDBOX: "yes" }, status: none }).kind).toBe("refused"); });
  it("a declared path that escapes the folder refuses the run and leaves no scratch folder", () => {
    const ok: SandboxStatus = { ...none, backend: "bwrap", bwrap: { present: true, path: "/usr/bin/bwrap", usable: true, detail: "works" } };
    const root = fs.mkdtempSync(path.join(tmp, "scratch-root-"));
    const p = planSandbox(req(decl({ readPaths: ["missing"] })), { env: {}, status: ok, scratchRoot: root });
    expect(p.kind).toBe("refused"); expect(fs.readdirSync(root)).toEqual([]);
  });
  it("detects backends from the host without running anything real", () => {
    const host = (platform: NodeJS.Platform, present: string[], ok: boolean): DetectHost => ({ platform, pathEnv: "/usr/bin", exists: f => present.includes(f), probe: () => (ok ? { ok: true, detail: "works" } : { ok: false, detail: "Operation not permitted" }) });
    expect(detectSandbox(host("darwin", ["/usr/bin/sandbox-exec"], true)).backend).toBe("seatbelt");
    const denied = detectSandbox(host("darwin", ["/usr/bin/sandbox-exec"], false)); expect(denied.backend).toBeNull(); expect(denied.reason).toMatch(/not usable here/);
    expect(detectSandbox(host("linux", ["/usr/bin/bwrap", "/usr/bin/true", "/usr/bin/docker"], true))).toMatchObject({ backend: "bwrap", docker: { present: true } });
    expect(detectSandbox(host("linux", [], true)).reason).toMatch(/bwrap not found/);
    expect(detectSandbox(host("win32", [], true)).reason).toMatch(/Windows/);
  });
  it("finds programs in PATH only through absolute directories", () => { expect(whichIn("sh", "relative:/bin")).toBe("/bin/sh"); expect(whichIn("sh", "relative")).toBeNull(); });
  it("wraps a program in a ulimit step only when a limit is set", () => {
    expect(withLimits("/bin/echo", ["a"], {})).toEqual({ file: "/bin/echo", args: ["a"] });
    const w = withLimits("/bin/echo", ["a"], { cpuSeconds: 5 }); expect(w.file).toBe("/bin/sh"); expect(w.args.slice(-5)).toEqual(["sh", "5", "0", "/bin/echo", "a"]);
  });
});

describe("manifest and approval", () => {
  const f = (files: Record<string, string>): FolderFile[] => Object.entries(files).map(([p, c]) => { const bytes = Buffer.from(c); return { path: p, size: bytes.length, executable: false, bytes }; });
  const parse = (sandbox: unknown) => parseManifest(f({ "extension.json": JSON.stringify({ name: "demo", version: "1.0.0", sandbox }), "scripts/run.sh": "echo hi" }));
  it("reads a sandbox block from extension.json and from the 0 block", () => {
    const a = parse({ network: true, readPaths: ["data"] }); expect(a.ok && a.value.sandbox).toEqual({ network: true, process: false, programs: [], readPaths: ["data"], writePaths: [] });
    const b = parseManifest(f({ "plugin.json": JSON.stringify({ name: "demo", "0": { sandbox: { writePaths: ["out"] } } }) })); expect(b.ok).toBe(true);
  });
  it("is null when absent and rejects an invalid block", () => {
    const none = parseManifest(f({ "extension.json": JSON.stringify({ name: "demo" }) })); expect(none.ok && none.value.sandbox).toBeNull();
    for (const bad of [{ network: "yes" }, { readPaths: ["../x"] }, { readPaths: ["/etc"] }, { extra: 1 }, "on", []]) { const r = parse(bad); expect(r.ok, JSON.stringify(bad)).toBe(false); if (!r.ok) expect(r.error.message).toMatch(/sandbox/); }
  });
  it("puts the block in the capability lines, so a change asks again", () => {
    const key = (s: unknown) => { const r = parse(s); if (!r.ok) throw new Error(r.error.message); return capabilityKey(capabilitiesOf(r.value)); };
    const base = key({ network: false }); expect(key({ network: false })).toBe(base);
    expect(key({ network: true })).not.toBe(base); expect(key({ readPaths: ["data"] })).not.toBe(base); expect(key({ process: true })).not.toBe(base);
    const r = parse({ network: true }); if (r.ok) expect(capabilityLines(capabilitiesOf(r.value))).toContain("sandbox: network ON, programs interpreters only, read -, write -");
  });
  it("leaves the capability key of an extension with no block unchanged", () => {
    const r = parseManifest(f({ "extension.json": JSON.stringify({ name: "demo", version: "1.0.0" }) })); expect(r.ok && capabilityLines(capabilitiesOf(r.value)).some(l => l.startsWith("sandbox"))).toBe(false);
  });
});

const status = detectSandbox();
const macReal = process.platform === "darwin" && status.backend === "seatbelt";
describe.skipIf(!macReal)("real macOS sandbox-exec", () => {
  const homeFile = path.join(os.homedir(), `.0-sandbox-test-${process.pid}`);
  /** A real file in ~/.ssh when there is one (so the denial is not just "file missing"); otherwise the home file stands in. */
  const sshDir = path.join(os.homedir(), ".ssh");
  const sshFile = (() => { try { const n = fs.readdirSync(sshDir).find(x => fs.statSync(path.join(sshDir, x)).isFile()); if (n) { fs.accessSync(path.join(sshDir, n), fs.constants.R_OK); return path.join(sshDir, n); } } catch { /* none */ } return homeFile; })();
  const script = (name: string, body: string) => { const p = path.join(ext, "scripts", name); fs.writeFileSync(p, body, { mode: 0o755 }); return p; };
  const exec = async (script: string, d: SandboxDecl, env: Record<string, string> = {}, argvPrefix = ["/bin/sh"]) => {
    const plan = planSandbox({ decl: d, extensionDir: ext, workspace: null, argv: [...argvPrefix, script], interpreters: ["sh", "bash", "node"], env: { PATH: "/usr/bin:/bin", HOME: os.homedir(), ...env }, cwd: tmp, label: "test script" }, { env: {}, status });
    if (plan.kind !== "sandboxed") throw new Error(`not sandboxed: ${JSON.stringify(plan)}`);
    try { const r = await run(plan.file, plan.args, { cwd: plan.cwd, env: plan.env, timeout: 15_000 }).then(x => ({ code: 0, ...x }), (e: { code?: number; stdout?: string; stderr?: string }) => ({ code: e.code ?? 1, stdout: e.stdout ?? "", stderr: e.stderr ?? "" })); return { ...r, plan }; } finally { plan.cleanup(); }
  };
  beforeAll(() => { fs.writeFileSync(homeFile, "home-secret"); });
  afterAll(() => { fs.rmSync(homeFile, { force: true }); });

  it("reads its own folder and writes to scratch", async () => {
    const s = script("ok.sh", `read -r a < "${ext}/data/in.txt"; echo "own:$a"; echo w > "$TMPDIR/out.txt" && echo scratch-write-ok; read -r b < "$TMPDIR/out.txt"; echo "scratch-read:$b"`);
    const r = await exec(s, decl()); console.log("[macOS] own dir + scratch:", r.stdout.trim().replace(/\n/g, " | "), "| status:", r.plan.status);
    expect(r.stdout).toContain("own:own-data"); expect(r.stdout).toContain("scratch-write-ok"); expect(r.stdout).toContain("scratch-read:w");
  });
  it("cannot read a file in the home folder or ~/.ssh", async () => {
    const s = script("home.sh", `if read -r a < "${homeFile}"; then echo "LEAK:$a"; else echo home-read-denied; fi; if read -r b < "${sshFile}"; then echo "LEAK-SSH:$b"; else echo ssh-read-denied; fi; if read -r c < "${outside}/secret.txt"; then echo "LEAK-OTHER:$c"; else echo other-read-denied; fi`);
    const r = await exec(s, decl()); console.log("[macOS] home/ssh/other:", r.stdout.trim().replace(/\n/g, " | "));
    expect(r.stdout).toContain("home-read-denied"); expect(r.stdout).toContain("ssh-read-denied"); expect(r.stdout).toContain("other-read-denied"); expect(r.stdout).not.toContain("LEAK");
  });
  it("cannot even see that a home file exists", async () => {
    const s = script("exists.sh", `if [ -e "${homeFile}" ]; then echo HOME-FILE-VISIBLE; else echo home-file-hidden; fi; if [ -e "${ext}/data/in.txt" ]; then echo own-visible; else echo OWN-HIDDEN; fi`);
    const r = await exec(s, decl()); console.log("[macOS] existence of home file:", r.stdout.trim().replace(/\n/g, " | "));
    expect(r.stdout).toContain("home-file-hidden"); expect(r.stdout).toContain("own-visible");
  });
  it("cannot write outside scratch, not even in its own folder", async () => {
    const target = path.join(outside, "written.txt");
    const s = script("write.sh", `if echo x > "${target}"; then echo "LEAK-WRITE"; else echo outside-write-denied; fi; if echo x > "${ext}/data/new.txt"; then echo "LEAK-OWN"; else echo own-dir-write-denied; fi; if echo x > "$HOME/.0-sandbox-written"; then echo "LEAK-HOME"; else echo home-write-denied; fi`);
    const r = await exec(s, decl()); console.log("[macOS] writes outside scratch:", r.stdout.trim().replace(/\n/g, " | "));
    expect(r.stdout).toContain("outside-write-denied"); expect(r.stdout).toContain("own-dir-write-denied"); expect(r.stdout).toContain("home-write-denied");
    expect(fs.existsSync(target)).toBe(false); expect(fs.existsSync(path.join(ext, "data", "new.txt"))).toBe(false); expect(fs.existsSync(path.join(os.homedir(), ".0-sandbox-written"))).toBe(false);
  });
  it("can write to a declared write path and read a declared read path", async () => {
    const s = script("declared.sh", `echo y > "${ext}/data/declared.txt" && echo declared-write-ok`);
    const r = await exec(s, decl({ writePaths: ["data"] })); expect(r.stdout).toContain("declared-write-ok"); expect(fs.readFileSync(path.join(ext, "data", "declared.txt"), "utf8")).toBe("y\n");
  });
  it("cannot start a program outside the interpreter set, can with process", async () => {
    const s = script("exec.sh", `/bin/ls / > /dev/null 2>&1 && echo LEAK-EXEC || echo exec-denied`);
    const strict = await exec(s, decl()); console.log("[macOS] exec ls without process:", strict.stdout.trim());
    expect(strict.stdout).toContain("exec-denied");
    const s2 = script("exec2.sh", `/bin/ls / > /dev/null 2>&1 && echo exec-ok || echo exec-denied`);
    expect((await exec(s2, decl({ process: true }))).stdout).toContain("exec-ok");
  });
  it("cannot open a network connection; the same request works outside the sandbox", async () => {
    const server = http.createServer((_q, res) => res.end("pong")); await new Promise<void>(r => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as AddressInfo).port; const url = `http://127.0.0.1:${port}/`;
    try {
      const outsideRun = await run("/usr/bin/curl", ["-s", "--max-time", "3", url]); console.log("[macOS] curl outside sandbox:", JSON.stringify(outsideRun.stdout));
      expect(outsideRun.stdout).toBe("pong");
      const s = script("net.sh", `/usr/bin/curl -s --max-time 3 "${url}" && echo NET-OK || echo net-blocked`);
      const off = await exec(s, decl({ process: true })); console.log("[macOS] curl inside sandbox, network off:", JSON.stringify(off.stdout.trim()));
      expect(off.stdout).toContain("net-blocked"); expect(off.stdout).not.toContain("pong");
      const on = await exec(s, decl({ process: true, network: true })); console.log("[macOS] curl inside sandbox, network declared:", JSON.stringify(on.stdout.trim()));
      expect(on.stdout).toContain("pong");
    } finally { server.close(); }
  });
  it("runs node inside the sandbox and node cannot read the home file either", async () => {
    const js = path.join(ext, "scripts", "n.js"); fs.writeFileSync(js, `const fs=require("fs");console.log("own="+fs.readFileSync(${JSON.stringify(path.join(ext, "data", "in.txt"))},"utf8"));try{fs.readFileSync(${JSON.stringify(homeFile)});console.log("LEAK")}catch(e){console.log("node-home-denied "+e.code)}`);
    const r = await exec(js, decl(), { PATH: `${path.dirname(process.execPath)}:/usr/bin:/bin` }, [process.execPath]);
    console.log("[macOS] node:", r.stdout.trim().replace(/\n/g, " | "), r.stderr.slice(0, 200));
    expect(r.stdout).toContain("own=own-data"); expect(r.stdout).toContain("node-home-denied"); expect(r.stdout).not.toContain("LEAK");
  });
});

describe("per-binary program allowlist and host filtering", () => {
  const ok: SandboxStatus = { platform: "linux", seatbelt: { present: false, detail: "" }, bwrap: { present: true, path: "/usr/bin/bwrap", usable: true, detail: "works" }, docker: { present: false, detail: "" }, backend: "bwrap", reason: "" };
  const noOs: SandboxStatus = { ...ok, backend: null, bwrap: { present: false, detail: "none" }, reason: "none" };
  const bin = path.join(tmp, "bin");
  const fake = (name: string) => { fs.mkdirSync(bin, { recursive: true }); const f = path.join(bin, name); fs.writeFileSync(f, "#!/bin/sh\n", { mode: 0o755 }); return fs.realpathSync(f); };
  const req = (d: SandboxDecl, argv: string[] = ["/bin/sh", path.join(ext, "scripts", "x.sh")]) => ({ decl: d, extensionDir: ext, workspace: null, argv, interpreters: ["sh"], env: { PATH: `${bin}:/usr/bin:/bin` }, cwd: tmp, label: "script x of extension demo" });

  it("parses, sorts and dedupes program names, and rejects paths", () => {
    expect(parseSandboxDecl({ programs: ["jq", "curl", "jq"] })).toMatchObject({ ok: true, value: { programs: ["curl", "jq"] } });
    for (const bad of ["/usr/bin/curl", "../curl", "a b", "", "-x"]) expect(parseSandboxDecl({ programs: [bad] }).ok, bad).toBe(false);
  });
  it("puts the programs in the approval, so naming one more asks again", () => {
    const key = (programs: string[]) => { const r = parseManifest([{ path: "extension.json", size: 1, executable: false, bytes: Buffer.from(JSON.stringify({ name: "demo", version: "1.0.0", sandbox: { programs } })) }]); if (!r.ok) throw new Error(r.error.message); return capabilityKey(capabilitiesOf(r.value)); };
    expect(key(["curl"])).not.toBe(key([])); expect(key(["curl"])).not.toBe(key(["curl", "jq"])); expect(key(["jq", "curl"])).toBe(key(["curl", "jq"]));
  });
  it("refuses to filter the network by host, in every spelling, and says why", () => {
    for (const bad of [{ network: ["example.com"] }, { network: { hosts: ["example.com"] } }, { hosts: ["example.com"] }, { allowedHosts: ["example.com"] }, { network: true, domains: ["example.com"] }]) {
      const r = parseSandboxDecl(bad); expect(r.ok, JSON.stringify(bad)).toBe(false);
      if (!r.ok) expect(r.error).toMatch(/by host is not supported.*true or false/);
    }
    expect(parseSandboxDecl({ network: true }).ok).toBe(true);
  });
  it("mounts only the named program besides interpreters (bubblewrap)", () => {
    const jq = fake("jq"); const p = planSandbox(req(decl({ programs: ["jq"] })), { env: {}, status: ok });
    expect(p.kind).toBe("sandboxed");
    if (p.kind === "sandboxed") { p.cleanup(); expect(p.args).toContain(jq); expect(p.args.join(" ")).not.toMatch(/--ro-bind \/usr \/usr/); }
  });
  it("allows exec of the named program in the Seatbelt profile and nothing wider", () => {
    const jq = fake("jq"); const { profile, params } = seatbeltProfile(policy({ programs: ["jq"], execAllow: ["/bin/sh", jq] }));
    expect(Object.values(params)).toContain(jq); expect(profile).not.toContain('(subpath "/usr/bin")');
  });
  it("refuses a run that names a program that is not on PATH", () => {
    const p = planSandbox(req(decl({ programs: ["no-such-tool-xyz"] })), { env: {}, status: ok });
    expect(p.kind).toBe("refused"); if (p.kind === "refused") expect(p.error).toMatch(/declares the program "no-such-tool-xyz".*not found in PATH/);
  });
  it("refuses a node run with named programs when only node's layer exists, because it cannot limit programs by name", () => {
    fake("jq");
    const p = planSandbox(req(decl({ programs: ["jq"] }), [process.execPath, path.join(ext, "scripts", "x.mjs")]), { env: {}, status: noOs, nodeSupport: { supported: true, flag: "--permission", detail: "" } });
    expect(p.kind).toBe("refused"); if (p.kind === "refused") expect(p.error).toMatch(/needs an OS sandbox/);
  });
  it("lets node start children only when programs are named, with the OS layer limiting which", () => {
    fake("jq");
    const p = planSandbox(req(decl({ programs: ["jq"] }), [process.execPath, path.join(ext, "scripts", "x.mjs")]), { env: {}, status: ok, nodeSupport: { supported: true, flag: "--permission", detail: "" } });
    expect(p.kind).toBe("sandboxed"); if (p.kind === "sandboxed") { p.cleanup(); expect(p.args).toContain("--allow-child-process"); }
  });
});
