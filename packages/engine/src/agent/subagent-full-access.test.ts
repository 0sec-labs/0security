import { afterEach, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { NativeRuntime, NativeRuntimeResult } from "../runtime/types.js";
import { eventBus } from "../events/bus.js";
import { ToolExecutor, getToolsForRole } from "./tools.js";
import type { ToolContext } from "./types.js";
import { clearSkillRegistry, loadSkillRegistry } from "./skills/index.js";

afterEach(() => { vi.unstubAllEnvs(); eventBus.clear(); });

const done = (): NativeRuntimeResult => ({ content: [{ type: "text", text: "Child result." }], stopReason: "end_turn", durationMs: 0 });
function child(seen: string[][]): NativeRuntime {
  return { type: "api", isAvailable: async () => true,
    executeNative: async (_system, _messages, tools) => { seen.push(tools.map(tool => tool.name).sort()); return done(); } };
}
function context(folder: string, overrides: Partial<ToolContext> = {}): ToolContext {
  return { target: "", scanId: "full-access", role: "audit", consoleSession: true, scopePath: folder, workspaceRoot: folder,
    findings: [], attackResults: [], targetInfo: {}, ...overrides };
}

it("every tool list is the same whatever the role or folder: one mode", () => {
  const names = getToolsForRole({ webSearchEnabled: true }).map(tool => tool.name).sort();
  expect(names).toEqual(["ask_operator", "bash", "finding", "load_skill", "spawn_agent", "str_replace", "web_search"]);
  expect(getToolsForRole({ webSearchEnabled: false }).map(tool => tool.name)).not.toContain("web_search");
});

it("a child starts with the core tools only and gets the code-index pack only after it loads a declaring skill", async () => {
  const packed = ["callees_of", "callers_of", "routes", "trace_to_sink"];
  expect(getToolsForRole({ webSearchEnabled: true }).map(tool => tool.name)).not.toEqual(expect.arrayContaining(packed));
  clearSkillRegistry(); loadSkillRegistry();
  const folder = mkdtempSync(join(tmpdir(), "0-full-access-"));
  writeFileSync(join(folder, "app.js"), "router.get('/x', (req, res) => { res.send(1); });\n");
  const seen: string[][] = [];
  let lastMessages = "";
  const script = (skill: string): NativeRuntime => ({ type: "api", isAvailable: async () => true,
    executeNative: async (_system, messages, tools) => {
      seen.push(tools.map(tool => tool.name).sort());
      if (seen.length === 3) lastMessages = JSON.stringify(messages);
      return seen.length === 1
        ? { content: [{ type: "tool_use", id: "t1", name: "load_skill", input: { skill_id: skill } }], stopReason: "tool_use", durationMs: 0 }
        : seen.length === 2 ? { content: [{ type: "tool_use", id: "t2", name: "routes", input: {} }], stopReason: "tool_use", durationMs: 0 } : done();
    } });
  const executor = new ToolExecutor(context(folder), null, undefined, async () => script("seedless-depth-review"));
  try {
    const result = await executor.execute({ name: "spawn_agent", arguments: { task: "Audit the folder", wait: true } });
    expect(result.success).toBe(true);
    expect(seen.length).toBeGreaterThanOrEqual(3);
    expect(lastMessages).toContain("auth_signal_missing");
    expect(lastMessages).not.toContain("not available to this delegated agent");
    for (const name of packed) expect(seen[0]).not.toContain(name);
    for (const name of ["bash", "finding", "load_skill", "str_replace", "spawn_agent"]) expect(seen[0]).toContain(name);
    for (const name of packed) expect(seen[1]).toContain(name);
    expect(seen[1]!.filter(name => !packed.includes(name))).toEqual(seen[0]);
  } finally { await executor.cleanup(); clearSkillRegistry(); rmSync(folder, { recursive: true, force: true }); }
});

it("a child spawned in a folder, even with read_only passed, gets bash and every tool", async () => {
  const folder = mkdtempSync(join(tmpdir(), "0-full-access-"));
  const seen: string[][] = [];
  const executor = new ToolExecutor(context(folder), null, undefined, async () => child(seen));
  try {
    const result = await executor.execute({ name: "spawn_agent", arguments: { task: "Read-only audit of the folder", read_only: true, wait: true } });
    expect(result.success).toBe(true);
    expect(seen).toHaveLength(1);
    for (const name of ["bash", "str_replace", "finding", "load_skill", "web_search", "spawn_agent"]) expect(seen[0]).toContain(name);
  } finally { await executor.cleanup(); rmSync(folder, { recursive: true, force: true }); }
});

it("four helpers can run at once in one folder, each with a shell", async () => {
  const folder = mkdtempSync(join(tmpdir(), "0-full-access-"));
  const seen: string[][] = [];
  const executor = new ToolExecutor(context(folder), null, undefined, async () => child(seen));
  try {
    const result = await executor.execute({ name: "spawn_agent", arguments: { wait: true, tasks: [1, 2, 3, 4].map(n => ({ task: `Helper ${n}` })) } });
    expect(result.success).toBe(true);
    expect(result.output).toMatchObject({ spawned: 4, succeeded: 4, failed: 0 });
    expect(seen).toHaveLength(4);
    for (const tools of seen) expect(tools).toContain("bash");
  } finally { await executor.cleanup(); rmSync(folder, { recursive: true, force: true }); }
});

it("a worker at the depth limit has no spawn_agent but keeps its shell", async () => {
  vi.stubEnv("ZERO_SUBAGENT_MAX_DEPTH", "1");
  const folder = mkdtempSync(join(tmpdir(), "0-full-access-"));
  const seen: string[][] = [];
  const executor = new ToolExecutor(context(folder), null, undefined, async () => child(seen));
  try {
    expect((await executor.execute({ name: "spawn_agent", arguments: { task: "Leaf", wait: true } })).success).toBe(true);
    expect(seen[0]).toContain("bash");
    expect(seen[0]).not.toContain("spawn_agent");
  } finally { await executor.cleanup(); rmSync(folder, { recursive: true, force: true }); }
});

it("allowed_tools only narrows, keeps bash, and never leaves a child empty", async () => {
  const folder = mkdtempSync(join(tmpdir(), "0-full-access-"));
  const seen: string[][] = [];
  const executor = new ToolExecutor(context(folder), null, undefined, async () => child(seen));
  try {
    expect((await executor.execute({ name: "spawn_agent", arguments: { task: "Narrow", wait: true, allowed_tools: ["finding"] } })).success).toBe(true);
    expect(seen[0]).toEqual(expect.arrayContaining(["bash", "finding"]));
    expect(seen[0]).not.toContain("web_search");
    const empty = await executor.execute({ name: "spawn_agent", arguments: { task: "None", wait: true, allowed_tools: [] } });
    expect(empty.success).toBe(false);
    expect(empty.error).toMatch(/no tools/);
  } finally { await executor.cleanup(); rmSync(folder, { recursive: true, force: true }); }
});
