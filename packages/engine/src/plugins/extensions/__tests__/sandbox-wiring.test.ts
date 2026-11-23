import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { sanitizedEnv } from "../../../agent/sanitized-env.js";
import { runBashWithWallclock } from "../../../agent/tools/exec-helpers.js";
import { McpHost, parseMcpConfig } from "../../../agent/mcp-host.js";
import { createExtensionService, unwrap } from "../index.js";
import type { McpConnector, McpLaunch } from "../mcp/ports.js";
import { detectSandbox, resetSandboxDetection } from "../sandbox/index.js";
import { approve, cleanup, makeRepo, tmp } from "./fixtures.js";
import { loaded, makeHost } from "./mcp-fixtures.js";

const dirs: string[] = [];
const saved = process.env.ZERO_SANDBOX;
beforeEach(() => { resetSandboxDetection(); });
afterEach(() => { cleanup(...dirs.splice(0)); if (saved === undefined) delete process.env.ZERO_SANDBOX; else process.env.ZERO_SANDBOX = saved; });
const backend = detectSandbox().backend;

const SCRIPT = "#!/bin/sh\nif [ -e \"$PROBE_FILE\" ]; then echo probe-visible; else echo probe-hidden; fi\n";
async function install(extra: Record<string, unknown>) {
  const home = tmp("home"); const repo = makeRepo([{
    "extension.json": JSON.stringify({ name: "sbx-demo", version: "1.0.0", description: "Script with a sandbox block.", ...extra }),
    "scripts/probe.sh": { content: SCRIPT, exec: true },
  }]); dirs.push(home, repo.dir);
  const svc = createExtensionService({ home });
  unwrap(approve(svc, unwrap(await svc.installer.prepare(`${repo.dir}@${repo.shas[0]}`)), { enable: { scope: "global" } }));
  const ext = svc.loadable().extensions.find(e => e.name === "sbx-demo")!;
  return { svc, ext };
}

/** What the bash tool does with the port's answer, including the direct spawn and the cleanup. */
async function bash(svc: ReturnType<typeof createExtensionService>, command: string, probe: string) {
  const prepared = svc.scriptRuns().prepare(command, { cwd: os.tmpdir() });
  if (!prepared) throw new Error("not an extension script");
  if (!prepared.ok) return { refused: prepared.error };
  try {
    const outcome = await runBashWithWallclock(command, { timeoutMs: 20_000, ceilingMs: 20_000, cwd: prepared.spawn?.cwd ?? os.tmpdir(), env: { ...sanitizedEnv(), PROBE_FILE: probe, ...prepared.env }, ...(prepared.spawn ? { spawn: prepared.spawn } : {}) });
    if (outcome.kind !== "exit") throw new Error(JSON.stringify(outcome));
    return { output: outcome.combined, status: prepared.status, sandboxed: Boolean(prepared.spawn) };
  } finally { prepared.cleanup?.(); }
}

describe("script runs and ZERO_SANDBOX", () => {
  it("auto leaves an extension with no sandbox block exactly as before, and says so", async () => {
    delete process.env.ZERO_SANDBOX;
    const { svc, ext } = await install({});
    const probe = path.join(os.tmpdir(), `sbx-probe-${process.pid}`); fs.writeFileSync(probe, "x"); dirs.push(probe);
    const r = await bash(svc, `sh ${ext.dir}/scripts/probe.sh`, probe);
    expect(r).toMatchObject({ sandboxed: false, output: "probe-visible" });
    expect((r as { status: string }).status).toMatch(/not applied.*declares no sandbox block/);
  });
  it("off never sandboxes, even with a block", async () => {
    process.env.ZERO_SANDBOX = "off";
    const { svc, ext } = await install({ sandbox: { network: false } });
    const r = await bash(svc, `sh ${ext.dir}/scripts/probe.sh`, os.tmpdir());
    expect(r).toMatchObject({ sandboxed: false, status: "sandbox: not applied (ZERO_SANDBOX=off)" });
  });
  it("an invalid ZERO_SANDBOX refuses the run", async () => {
    process.env.ZERO_SANDBOX = "maybe";
    const { svc, ext } = await install({ sandbox: {} });
    const r = await bash(svc, `sh ${ext.dir}/scripts/probe.sh`, os.tmpdir());
    expect("refused" in r && r.refused).toMatch(/ZERO_SANDBOX="maybe" is not valid/);
  });
  it.skipIf(backend !== null)("require refuses when this machine has no sandbox", async () => {
    process.env.ZERO_SANDBOX = "require";
    const { svc, ext } = await install({});
    const r = await bash(svc, `sh ${ext.dir}/scripts/probe.sh`, os.tmpdir());
    expect("refused" in r && r.refused).toMatch(/ZERO_SANDBOX=require but no sandbox is available/);
  });
  it.skipIf(backend === null)("a declared block hides files outside the extension; require applies the strict defaults to a block-less extension", async () => {
    const probe = path.join(os.homedir(), `.0-sbx-probe-${process.pid}`); fs.writeFileSync(probe, "x");
    try {
      delete process.env.ZERO_SANDBOX;
      const withBlock = await install({ sandbox: { network: false } });
      const a = await bash(withBlock.svc, `sh ${withBlock.ext.dir}/scripts/probe.sh`, probe);
      console.log("[wiring] auto + block:", JSON.stringify(a));
      expect(a).toMatchObject({ sandboxed: true, output: expect.stringContaining("probe-hidden") });
      expect((a as { status: string }).status).toMatch(/^sandbox: applied \(.*network off/);
      process.env.ZERO_SANDBOX = "require";
      const noBlock = await install({});
      const b = await bash(noBlock.svc, `sh ${noBlock.ext.dir}/scripts/probe.sh`, probe);
      console.log("[wiring] require + no block:", JSON.stringify(b));
      expect(b).toMatchObject({ sandboxed: true, output: expect.stringContaining("probe-hidden") });
    } finally { fs.rmSync(probe, { force: true }); }
  });
  it.skipIf(backend === null)("removes the scratch folder when the run ends", async () => {
    delete process.env.ZERO_SANDBOX;
    const { svc, ext } = await install({ sandbox: {} });
    const before = fs.readdirSync(fs.realpathSync(os.tmpdir())).filter(n => n.startsWith("0-sandbox-")).length;
    await bash(svc, `sh ${ext.dir}/scripts/probe.sh`, os.tmpdir());
    expect(fs.readdirSync(fs.realpathSync(os.tmpdir())).filter(n => n.startsWith("0-sandbox-")).length).toBe(before);
  });
});

describe("extension MCP servers and ZERO_SANDBOX", () => {
  const server = (dir: string, sandbox?: unknown) => loaded("sbx-mcp", { "extension.json": { name: "sbx-mcp", version: "1.0.0", description: "d", "0": { ...(sandbox ? { sandbox } : {}), mcp: { fake: { command: process.execPath, args: ["server.js"], description: "fake" } } } } }, dir);
  class Recorder implements McpConnector { readonly launches: McpLaunch[] = []; async connect(l: McpLaunch): Promise<never> { this.launches.push(l); throw new Error("spawn stopped by the test"); } }
  const folder = () => { const d = tmp("mcp-ext"); dirs.push(d); fs.writeFileSync(path.join(d, "server.js"), ""); return d; };
  const id = "mcp__x-sbx-mcp-fake";

  it("starts an extension server without a block unchanged under auto", async () => {
    const connector = new Recorder(); const { host } = makeHost([server(folder())], { connector: connector as never, parentEnv: { PATH: process.env.PATH } });
    const r = await host.loadServer(id); expect(r.ok).toBe(false);
    expect(connector.launches[0]).toMatchObject({ kind: "stdio", command: process.execPath });
  });
  it.skipIf(backend === null)("wraps the launch in the sandbox when a block is declared, and names the sandbox if the start fails", async () => {
    const connector = new Recorder(); const dir = folder(); const { host } = makeHost([server(dir, { network: false })], { connector: connector as never, parentEnv: { PATH: process.env.PATH } });
    const r = await host.loadServer(id); expect(r.ok).toBe(false);
    const launch = connector.launches[0] as Extract<McpLaunch, { kind: "stdio" }>;
    console.log("[wiring] mcp launch:", launch.command, launch.args.slice(0, 2).join(" ").slice(0, 60));
    expect(launch.command).toMatch(backend === "seatbelt" ? /sandbox-exec$/ : /bwrap$/);
    expect(launch.args).toContain(process.execPath);
    expect(launch.env.TMPDIR).toMatch(/0-sandbox-/);
    expect(!r.ok && r.message).toMatch(/ran in an OS sandbox/);
  });
  it("require with no backend refuses to start the server", async () => {
    if (backend !== null) return;
    const connector = new Recorder(); const { host } = makeHost([server(folder())], { connector: connector as never, parentEnv: { PATH: process.env.PATH, ZERO_SANDBOX: "require" } });
    const r = await host.loadServer(id); expect(r.ok).toBe(false); expect(connector.launches).toEqual([]);
    expect(!r.ok && r.message).toMatch(/ZERO_SANDBOX=require but no sandbox is available/);
  });
});

describe("operator-configured MCP servers", () => {
  it("read sandbox: true or a declaration from ZERO_MCP, and drop an entry whose sandbox value is malformed", () => {
    const parsed = parseMcpConfig(JSON.stringify([
      { id: "a", command: "node", cwd: "/tmp", sandbox: true },
      { id: "b", command: "node", cwd: "/tmp", sandbox: { network: true } },
      { id: "c", command: "node", sandbox: "yes" },
      { id: "d", command: "node", sandbox: { readPaths: ["../x"] } },
      { id: "e", command: "node" },
    ]));
    expect(parsed.map(p => p.id)).toEqual(["a", "b", "e"]);
    expect(parsed[0]).toMatchObject({ sandbox: true });
    expect(parsed[1]).toMatchObject({ sandbox: { network: true, process: false } });
    expect(parsed[2]).not.toHaveProperty("sandbox");
  });
  it("sandbox: true without a cwd is refused, not run unsandboxed", async () => {
    await expect(new McpHost().connectStdio({ id: "x", command: process.execPath, sandbox: true })).rejects.toThrow(/needs a cwd/);
  });
  it.skipIf(backend !== null)("sandbox: true with no backend is refused, not run unsandboxed", async () => {
    await expect(new McpHost().connectStdio({ id: "x", command: process.execPath, cwd: os.tmpdir(), sandbox: true })).rejects.toThrow(/no sandbox is available/);
  });
});
