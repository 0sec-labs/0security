import { afterEach, describe, expect, it } from "vitest";
import { createMockBrain, type MockBrain } from "@0/engine";
import { Command } from "commander";
import { printable, registerRedteamGenerateCommand, runGenerate, type GenerateDeps } from "../redteam-generate.js";
import { UsageError } from "../output.js";

const manifest = JSON.stringify({ tools: [{ name: "send_email", privilege: "network-out", gate: "none" }], sources: [{ kind: "email" }] });
const harness = (env: NodeJS.ProcessEnv = {}, files: Record<string, string> = { "/m.json": manifest }) => {
  const out: string[] = []; const err: string[] = []; const fetched: string[] = [];
  const deps: GenerateDeps = { out: t => out.push(t), err: t => err.push(t), env, readText: path => { if (!(path in files)) throw new Error("no file"); return files[path]!; }, fetch: (url, init) => { fetched.push(url); return fetch(url, init); } };
  return { deps, out, err, fetched };
};

describe("0 redteam generate", () => {
  let mock: MockBrain | undefined;
  afterEach(async () => { await mock?.close(); mock = undefined; });

  it("dry run prints the exact request and sends nothing, even with a URL set", async () => {
    mock = createMockBrain(); const url = await mock.start();
    const h = harness({ ZERO_BRAIN_URL: url });
    expect(await runGenerate({ manifest: "/m.json", dryRun: true, count: "3", framework: "LLM01" }, h.deps)).toBe(0);
    expect(JSON.parse(h.out.join(""))).toEqual({ v: 1, task: "scenarios", manifest: JSON.parse(manifest), framework: "LLM01", count: 3 });
    expect(h.fetched).toHaveLength(0);
    expect(mock.requests).toHaveLength(0);
  });
  it("uses the starter pack with no URL, names the source, and puts the canary in payload and success", async () => {
    const h = harness();
    expect(await runGenerate({ manifest: "/m.json", canary: "CANARY-xyz" }, h.deps)).toBe(0);
    const text = h.out.join("");
    expect(text).toContain("source: starter-pack");
    expect(text).toContain("No brain URL");
    expect(text).toContain("CANARY-xyz");
    expect(text).not.toContain("AGENT-CANARY-0");
    expect(h.fetched).toHaveLength(0);
  });
  it("asks the brain when a URL is given and reports it as the source, as json", async () => {
    mock = createMockBrain({ token: "tk" }); const url = await mock.start();
    const h = harness({ ZERO_BRAIN_TOKEN: "tk" });
    expect(await runGenerate({ manifest: "/m.json", url, format: "json", canary: "CANARY-1", count: 2 }, h.deps)).toBe(0);
    const result = JSON.parse(h.out.join(""));
    expect(result.source).toBe("remote");
    expect(result.scenarios).toHaveLength(2);
    expect(result.scenarios[0].payload).toContain("CANARY-1");
    expect(JSON.stringify(result)).not.toContain("tk\"");
    expect(h.err.join("\n")).not.toContain("Bearer");
    expect(mock.requests).toHaveLength(1);
  });
  it("warns on stderr that remote payloads are hostile, and not for the starter pack", async () => {
    mock = createMockBrain(); const url = await mock.start();
    const remote = harness();
    await runGenerate({ manifest: "/m.json", url }, remote.deps);
    expect(remote.err.filter(line => line.includes("decoy or sandboxed"))).toHaveLength(1);
    const local = harness();
    await runGenerate({ manifest: "/m.json" }, local.deps);
    expect(local.err.join("\n")).not.toContain("decoy or sandboxed");
  });
  it("strips control characters when printing but keeps newline and tab", () => {
    expect(printable("a\u001b[2Jb\u009bc\u0007\nd\te")).toBe("a?[2Jb?c?\nd\te");
  });
  it("does not contact the URL with --offline and says why", async () => {
    mock = createMockBrain(); const url = await mock.start();
    const h = harness({ ZERO_BRAIN_URL: url });
    await runGenerate({ manifest: "/m.json", offline: true }, h.deps);
    expect(h.out.join("")).toContain("Offline");
    expect(mock.requests).toHaveLength(0);
  });
  it("rejects bad input with a UsageError", async () => {
    await expect(runGenerate({}, harness().deps)).rejects.toThrow(UsageError);
    await expect(runGenerate({ manifest: "/missing.json" }, harness().deps)).rejects.toThrow(UsageError);
    await expect(runGenerate({ manifest: "/m.json", count: "99" }, harness().deps)).rejects.toThrow(/--count/);
    await expect(runGenerate({ manifest: "/m.json", format: "xml" }, harness().deps)).rejects.toThrow(/--format/);
    const bad = harness({}, { "/b.json": JSON.stringify({ tools: [{ name: "/etc/passwd", privilege: "exec", gate: "none" }], sources: [] }) });
    await expect(runGenerate({ manifest: "/b.json" }, bad.deps)).rejects.toThrow(UsageError);
    const extra = harness({}, { "/e.json": JSON.stringify({ tools: [], sources: [], cwd: "/home/me" }) });
    await expect(runGenerate({ manifest: "/e.json" }, extra.deps)).rejects.toThrow(/unknown field/);
  });
  it("registers as a subcommand of redteam", async () => {
    const program = new Command(); program.exitOverride();
    const redteam = program.command("redteam");
    const h = harness();
    registerRedteamGenerateCommand(redteam, h.deps);
    await program.parseAsync(["node", "0", "redteam", "generate", "--manifest", "/m.json", "--dry-run"]);
    expect(h.out.join("")).toContain("\"task\": \"scenarios\"");
    process.exitCode = 0;
  });
});
