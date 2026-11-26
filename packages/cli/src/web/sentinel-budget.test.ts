import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SecurityWorkflowStore, SentinelStore } from "@0/engine/storage";
import { createSecurityWorkflowTemplate } from "@0/engine/shared";
import { WebSentinelService } from "./sentinels.js";
import type { SentinelSessionEvent } from "./sentinel-runner.js";

const T0 = Date.parse("2026-03-02T10:00:00Z");
const MIN = 60_000;
const P = "/api/console/sentinels";
const dirs: string[] = [];

function fixture(persistent: boolean) {
  const dir = mkdtempSync(join(tmpdir(), "zero-sentinel-budget-"));
  dirs.push(dir);
  const dbPath = join(dir, "control.db");
  let counter = 0;
  const live = new Set<string>();
  const listeners = new Map<string, Set<(event: SentinelSessionEvent) => void>>();
  const costs = new Map<string, number>();
  const emit = (id: string, event: SentinelSessionEvent) => { for (const listener of [...(listeners.get(id) ?? [])]) listener(event); };
  const missions = {
    create: vi.fn((_input: Record<string, unknown>) => { const id = `mission-${++counter}`; live.add(id); return { id }; }),
    send: vi.fn(async (id: string, text: string, _author?: unknown, _mode?: "queue", _automated?: boolean) => { emit(id, { type: "user", text }); return {}; }),
    pendingDecisions: vi.fn((_id: string) => 0),
    subscribe: vi.fn((id: string, listener: (event: SentinelSessionEvent) => void) => { const set = listeners.get(id) ?? new Set(); set.add(listener); listeners.set(id, set); return () => set.delete(listener); }),
    cancel: vi.fn(async (_id: string) => ({})),
    usage: vi.fn((id: string) => ({ costUsd: costs.get(id) ?? 0 })),
    exists: vi.fn((id: string) => live.has(id)),
  };
  const service = new WebSentinelService({ dbPath, missions, persistentThread: () => persistent });
  const workflows = new SecurityWorkflowStore(dbPath);
  const store = new SentinelStore(dbPath);
  const call = async (method: string, path: string, body?: unknown) => {
    const url = new URL(`http://localhost${path}`);
    return (await service.handle(url.pathname, method, body, url.searchParams))!;
  };
  async function armed(body: Record<string, unknown> = {}, triggerBody: Record<string, unknown> = {}) {
    const created = (await call("POST", P, { name: "Watcher", skills: ["pr-diff-review"], instructions: "Watch deps.", ...body })).data as { sentinel: { id: string } };
    const id = created.sentinel.id;
    await call("POST", `${P}/${id}/resume`, { acknowledge: true });
    const automation = workflows.save({ ...createSecurityWorkflowTemplate("dependency-review", { target: "." }), ownerSentinelId: id });
    const trigger = await call("POST", `${P}/${id}/triggers`, { automationId: automation.id, kind: "schedule", schedule: { frequency: "minutes", every: 5 }, enabled: true, approval: "enable-reviewed-trigger", ...triggerBody });
    expect(trigger.status).toBe(201);
    return { id, triggerId: (trigger.data as { trigger: { id: string } }).trigger.id };
  }
  const turns = (id: string) => store.listTurns(id);
  return { service, missions, store, call, armed, emit, costs, turns };
}

beforeEach(() => { vi.useFakeTimers({ now: T0 }); });
afterEach(() => { vi.useRealTimers(); for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

describe.each([["a persistent thread", true], ["a thread per run", false]] as const)("budget limits with %s", (_name, persistent) => {
  it("runs while under the daily limit, then refuses with a budget reached record and no thread work", async () => {
    const f = fixture(persistent);
    const { id } = await f.armed({ dailyBudgetUsd: 1 });
    vi.setSystemTime(T0 + 5 * MIN + 1_000);
    await f.service.tick();
    const first = f.missions.send.mock.calls.length;
    expect(first).toBe(1);
    const mission = persistent ? "mission-1" : "mission-2";
    f.costs.set(mission, 1.25);
    f.emit(mission, { type: "usage" });
    f.emit(mission, { type: "turn-complete", stopReason: "end_turn" });
    vi.setSystemTime(T0 + 10 * MIN + 1_000);
    await f.service.tick();
    expect(f.missions.send.mock.calls.length).toBe(first);
    const refused = f.turns(id).find(turn => turn.status === "skipped");
    expect(refused).toMatchObject({ status: "skipped", skippedReason: expect.stringContaining("Budget reached: $1.25 of the $1 daily limit for this Sentinel") });
    const trigger = f.store.listTriggers(id)[0]!;
    expect(trigger.lastError).toContain("Budget reached");
    expect(trigger.lastStatus).not.toBe("running");
  });

  it("starts again on the next UTC day", async () => {
    const f = fixture(persistent);
    const { id } = await f.armed({ dailyBudgetUsd: 1 });
    vi.setSystemTime(T0 + 5 * MIN + 1_000);
    await f.service.tick();
    const mission = persistent ? "mission-1" : "mission-2";
    f.costs.set(mission, 2);
    f.emit(mission, { type: "usage" });
    f.emit(mission, { type: "turn-complete", stopReason: "end_turn" });
    vi.setSystemTime(T0 + 10 * MIN + 1_000);
    await f.service.tick();
    expect(f.turns(id).filter(turn => turn.status === "skipped")).toHaveLength(1);
    const sends = f.missions.send.mock.calls.length;
    // Late on the same day the schedule is still refused; the first occurrence after 00:00 UTC runs.
    vi.setSystemTime(Date.parse("2026-03-02T23:55:00Z"));
    await f.service.tick();
    vi.setSystemTime(Date.parse("2026-03-02T23:59:10Z"));
    await f.service.tick();
    expect(f.missions.send.mock.calls.length).toBe(sends);
    vi.setSystemTime(Date.parse("2026-03-03T00:00:10Z"));
    await f.service.tick();
    expect(f.missions.send.mock.calls.length).toBe(sends + 1);
  });

  it("applies a limit of one trigger to that trigger only", async () => {
    const f = fixture(persistent);
    const { id, triggerId } = await f.armed({}, { dailyBudgetUsd: 0.5 });
    vi.setSystemTime(T0 + 5 * MIN + 1_000);
    await f.service.tick();
    const mission = persistent ? "mission-1" : "mission-2";
    f.costs.set(mission, 0.75);
    f.emit(mission, { type: "usage" });
    f.emit(mission, { type: "turn-complete", stopReason: "end_turn" });
    vi.setSystemTime(T0 + 10 * MIN + 1_000);
    await f.service.tick();
    expect(f.turns(id).find(turn => turn.status === "skipped")?.skippedReason).toContain("daily limit for this trigger");
    expect(f.store.getTrigger(triggerId)?.dailyBudgetUsd).toBe(0.5);
  });
});

describe("a Sentinel with a limit and a run in flight", () => {
  it("does not start a second run beside it", async () => {
    const f = fixture(false);
    const { id } = await f.armed({ dailyBudgetUsd: 100 });
    vi.setSystemTime(T0 + 5 * MIN + 1_000);
    await f.service.tick();
    expect(f.missions.send).toHaveBeenCalledTimes(1);
    vi.setSystemTime(T0 + 10 * MIN + 1_000);
    await f.service.tick();
    expect(f.missions.send).toHaveBeenCalledTimes(1);
    expect(f.store.listTriggers(id)[0]!.lastError).toContain("still in progress");
    f.emit("mission-2", { type: "turn-complete", stopReason: "end_turn" });
    vi.setSystemTime(T0 + 15 * MIN + 1_000);
    await f.service.tick();
    expect(f.missions.send).toHaveBeenCalledTimes(2);
  });
});

describe("a turn that waited in the queue", () => {
  it("is stopped when a limit was reached while it waited", async () => {
    const f = fixture(true);
    const { id } = await f.armed({ dailyBudgetUsd: 1 });
    vi.setSystemTime(T0 + 5 * MIN + 1_000);
    // The thread is busy: the first trigger turn is queued, not started.
    let queuedText = "";
    f.missions.send.mockImplementationOnce(async (_id: string, text: string) => { queuedText = text; return { queuedMessageId: "q1" }; });
    await f.service.tick();
    expect(queuedText).not.toBe("");
    // Meanwhile the Sentinel spends past its limit (a person's message in the same thread).
    const person = f.store.recordUserTurn({ agentId: id, sessionId: "mission-1", nowIso: new Date(T0 + 5 * MIN).toISOString(), ownerPid: 1 });
    f.store.updateTurn(person.id, { status: "completed", costUsd: 1.5 });
    f.emit("mission-1", { type: "user", text: queuedText });
    await vi.advanceTimersByTimeAsync(0);
    expect(f.missions.cancel).toHaveBeenCalledWith("mission-1");
    f.emit("mission-1", { type: "turn-complete", stopReason: "cancelled" });
    expect(f.turns(id).find(turn => turn.origin === "schedule")).toMatchObject({ status: "cancelled", error: expect.stringContaining("Budget reached") });
  });
});

describe("usage endpoint", () => {
  it("reports cost by Sentinel, model and week with refused runs and the spend against the limits", async () => {
    const f = fixture(true);
    const { id } = await f.armed({ dailyBudgetUsd: 1, monthlyBudgetUsd: 20, model: { providerId: "openai", model: "gpt-test" } });
    vi.setSystemTime(T0 + 5 * MIN + 1_000);
    await f.service.tick();
    f.costs.set("mission-1", 1.5);
    f.emit("mission-1", { type: "usage" });
    f.emit("mission-1", { type: "turn-complete", stopReason: "end_turn" });
    vi.setSystemTime(T0 + 10 * MIN + 1_000);
    await f.service.tick();
    const usage = (await f.call("GET", `${P}/usage`)).data as { sentinels: Array<Record<string, unknown>>; models: Array<Record<string, unknown>>; weeks: Array<Record<string, unknown>> };
    expect(usage.sentinels).toEqual([expect.objectContaining({ id, name: "Watcher", runs: 1, refused: 1, costUsd: 1.5, dayUsd: 1.5, monthUsd: 1.5, dailyBudgetUsd: 1, monthlyBudgetUsd: 20 })]);
    expect(usage.models).toEqual([{ model: "gpt-test", runs: 1, refused: 1, costUsd: 1.5 }]);
    expect(usage.weeks).toEqual([{ week: "2026-03-02", runs: 1, refused: 1, costUsd: 1.5 }]);
  });
});
