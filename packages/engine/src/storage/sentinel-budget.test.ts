import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { SentinelStore, SentinelStoreError } from "./sentinels.js";
import { createShimmedDatabase } from "./wasm-shim.js";
import { budgetRefusal, utcDayStart, utcMonthStart } from "../shared/sentinel-budget.js";

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
const status = (fn: () => unknown) => { try { fn(); } catch (error) { return error instanceof SentinelStoreError ? error.statusCode : -1; } return 0; };
const iso = (text: string) => Date.parse(text);

/** A Sentinel with one schedule trigger. `spend` writes a finished activation (and its turn) that started at `at` and cost `cost`. */
function setup(caps: Record<string, number | null> = {}, triggerCaps: Record<string, number> = {}) {
  const store = new SentinelStore(":memory:");
  const sentinel = store.create({ name: "Watcher", ...caps });
  const trigger = store.createTrigger(sentinel.id, { automationId: "auto", kind: "schedule", schedule: { frequency: "minutes", every: 5 }, enabled: true, ...triggerCaps });
  const spend = (at: string, cost: number, triggerId: string | undefined = trigger.id) => {
    const activation = store.createActivation({ sentinelId: sentinel.id, sentinelVersion: 1, trigger: { kind: "schedule", ...(triggerId ? { triggerId } : {}) }, status: "running", skills: [], startedAt: at });
    store.updateActivation(activation.id, { status: "completed", costUsd: cost, finishedAt: at });
  };
  return { store, sentinel, trigger, spend };
}

describe("budget periods", () => {
  it("starts a day and a month at 00:00 UTC", () => {
    expect(utcDayStart(iso("2026-03-31T23:59:59.999Z"))).toBe("2026-03-31T00:00:00.000Z");
    expect(utcMonthStart(iso("2026-03-31T23:59:59.999Z"))).toBe("2026-03-01T00:00:00.000Z");
    expect(utcMonthStart(iso("2026-12-01T00:00:00.000Z"))).toBe("2026-12-01T00:00:00.000Z");
  });
  it("names the limit, the spend and when runs resume", () => {
    expect(budgetRefusal("Sentinel", { dailyBudgetUsd: 2 }, { dayUsd: 2, monthUsd: 2 }, iso("2026-03-31T10:00:00Z"))).toBe("Budget reached: $2 of the $2 daily limit for this Sentinel is spent. It runs again at 2026-04-01 00:00 UTC.");
    expect(budgetRefusal("trigger", { monthlyBudgetUsd: 10 }, { dayUsd: 1, monthUsd: 12.5 }, iso("2026-12-15T10:00:00Z"))).toBe("Budget reached: $12.5 of the $10 monthly limit for this trigger is spent. It runs again at 2027-01-01 00:00 UTC.");
    expect(budgetRefusal("Sentinel", { dailyBudgetUsd: 2 }, { dayUsd: 1.99, monthUsd: 50 }, 0)).toBeUndefined();
    expect(budgetRefusal("Sentinel", {}, { dayUsd: 99, monthUsd: 99 }, 0)).toBeUndefined();
  });
});

describe("Sentinel spend limits", () => {
  it("stores the limits, defaults them to none and rejects bad values", () => {
    const { store, sentinel } = setup({ dailyBudgetUsd: 2, monthlyBudgetUsd: 30 });
    expect(store.get(sentinel.id)).toMatchObject({ dailyBudgetUsd: 2, monthlyBudgetUsd: 30 });
    expect(store.create({ name: "Plain" })).not.toHaveProperty("dailyBudgetUsd");
    expect(status(() => store.create({ name: "Bad", dailyBudgetUsd: 0 }))).toBe(400);
    expect(status(() => store.create({ name: "Bad", monthlyBudgetUsd: -3 }))).toBe(400);
    expect(store.update(sentinel.id, { version: 1, dailyBudgetUsd: null }).dailyBudgetUsd).toBeNull();
  });

  it("reads a Sentinel stored before limits existed as having none", () => {
    const dir = mkdtempSync(join(tmpdir(), "zero-budget-")); dirs.push(dir);
    const path = join(dir, "control.db");
    const first = new SentinelStore(path);
    const sentinel = first.create({ name: "Old" });
    first.close();
    const db = createShimmedDatabase(path);
    const row = db.prepare("SELECT sentinel_json FROM sentinels WHERE id = ?").all(sentinel.id)[0] as { sentinel_json: string };
    const stored = JSON.parse(row.sentinel_json) as Record<string, unknown>;
    delete stored.dailyBudgetUsd; delete stored.monthlyBudgetUsd;
    db.prepare("UPDATE sentinels SET sentinel_json = ? WHERE id = ?").run(JSON.stringify(stored), sentinel.id);
    db.close?.();
    const reopened = new SentinelStore(path);
    expect(reopened.budgetRefusal(sentinel.id, undefined, Date.now())).toBeNull();
    expect(reopened.update(sentinel.id, { version: 1, dailyBudgetUsd: 1 })).toMatchObject({ dailyBudgetUsd: 1 });
    reopened.close();
  });

  it("refuses at the daily limit and counts a day from 00:00 UTC", () => {
    const { store, sentinel, spend } = setup({ dailyBudgetUsd: 2 });
    spend("2026-03-01T23:59:59.999Z", 5);
    spend("2026-03-02T00:00:00.000Z", 1.5);
    expect(store.budgetRefusal(sentinel.id, undefined, iso("2026-03-02T12:00:00Z"))).toBeNull();
    spend("2026-03-02T09:00:00.000Z", 0.5);
    expect(store.budgetRefusal(sentinel.id, undefined, iso("2026-03-02T12:00:00Z"))).toContain("Budget reached: $2 of the $2 daily limit for this Sentinel");
    // The spend at 23:59:59.999 the day before does not count today, and the next day is free again.
    expect(store.budgetRefusal(sentinel.id, undefined, iso("2026-03-03T00:00:00Z"))).toBeNull();
    expect(store.budgetRefusal(sentinel.id, undefined, iso("2026-03-02T23:59:59.999Z"))).not.toBeNull();
  });

  it("refuses at the monthly limit and counts a month from the first at 00:00 UTC", () => {
    const { store, sentinel, spend } = setup({ monthlyBudgetUsd: 10 });
    spend("2026-02-28T23:59:59.999Z", 9);
    spend("2026-03-01T00:00:00.000Z", 6);
    spend("2026-03-20T00:00:00.000Z", 3.99);
    expect(store.budgetRefusal(sentinel.id, undefined, iso("2026-03-25T00:00:00Z"))).toBeNull();
    spend("2026-03-21T00:00:00.000Z", 0.01);
    expect(store.budgetRefusal(sentinel.id, undefined, iso("2026-03-25T00:00:00Z"))).toContain("monthly limit");
    expect(store.budgetRefusal(sentinel.id, undefined, iso("2026-04-01T00:00:00Z"))).toBeNull();
  });

  it("checks the daily limit before the monthly one and ignores a limit that is not set", () => {
    const { store, sentinel, spend } = setup({ dailyBudgetUsd: 1, monthlyBudgetUsd: 1 });
    spend("2026-03-02T01:00:00.000Z", 1);
    expect(store.budgetRefusal(sentinel.id, undefined, iso("2026-03-02T02:00:00Z"))).toContain("daily limit");
    const none = setup();
    none.spend("2026-03-02T01:00:00.000Z", 1000);
    expect(none.store.budgetRefusal(none.sentinel.id, undefined, iso("2026-03-02T02:00:00Z"))).toBeNull();
  });

  it("does not count skipped runs, and counts a person's messages and activations the ledger never saw", () => {
    const { store, sentinel, trigger, spend } = setup({ dailyBudgetUsd: 1 });
    store.recordSkippedTurn({ agentId: sentinel.id, origin: "schedule", detail: {}, triggerId: trigger.id, reason: "Budget reached: earlier", nowIso: "2026-03-02T01:00:00.000Z" });
    expect(store.budgetRefusal(sentinel.id, undefined, iso("2026-03-02T02:00:00Z"))).toBeNull();
    const person = store.recordUserTurn({ agentId: sentinel.id, sessionId: "s", nowIso: "2026-03-02T03:00:00.000Z", ownerPid: 1 });
    store.updateTurn(person.id, { status: "completed", costUsd: 0.6 });
    expect(store.budgetRefusal(sentinel.id, undefined, iso("2026-03-02T04:00:00Z"))).toBeNull();
    spend("2026-03-02T03:30:00.000Z", 0.4);
    expect(store.budgetRefusal(sentinel.id, undefined, iso("2026-03-02T04:00:00Z"))).not.toBeNull();
  });
});

describe("trigger spend limits", () => {
  it("refuses only the trigger that reached its limit", () => {
    const { store, sentinel, trigger, spend } = setup({}, { dailyBudgetUsd: 1 });
    const other = store.createTrigger(sentinel.id, { automationId: "auto", kind: "schedule", schedule: { frequency: "minutes", every: 5 }, enabled: true });
    spend("2026-03-02T01:00:00.000Z", 1.2, trigger.id);
    const now = iso("2026-03-02T02:00:00Z");
    expect(store.budgetRefusal(sentinel.id, trigger.id, now)).toContain("daily limit for this trigger");
    expect(store.budgetRefusal(sentinel.id, other.id, now)).toBeNull();
    expect(store.budgetRefusal(sentinel.id, undefined, now)).toBeNull();
    expect(store.budgetRefusal(sentinel.id, trigger.id, iso("2026-03-03T00:00:00Z"))).toBeNull();
  });

  it("edits the limits of a trigger in place without turning it off", () => {
    const { store, trigger } = setup({}, { dailyBudgetUsd: 1, monthlyBudgetUsd: 5 });
    expect(store.getTrigger(trigger.id)).toMatchObject({ dailyBudgetUsd: 1, monthlyBudgetUsd: 5 });
    const next = store.updateTrigger(trigger.id, { dailyBudgetUsd: null, monthlyBudgetUsd: 8 });
    expect(next.enabled).toBe(true);
    expect(next.dailyBudgetUsd).toBeUndefined();
    expect(next.monthlyBudgetUsd).toBe(8);
    expect(status(() => store.updateTrigger(trigger.id, { dailyBudgetUsd: -1 }))).toBe(400);
  });
});

describe("usage rows", () => {
  it("lists runs and budget refusals since a time, with their cost", () => {
    const { store, sentinel, trigger, spend } = setup();
    spend("2026-03-01T10:00:00.000Z", 0.25);
    spend("2026-03-05T10:00:00.000Z", 0.5);
    store.recordSkippedTurn({ agentId: sentinel.id, origin: "schedule", detail: {}, triggerId: trigger.id, reason: "Budget reached: limit", nowIso: "2026-03-05T11:00:00.000Z" });
    store.recordSkippedTurn({ agentId: sentinel.id, origin: "schedule", detail: {}, triggerId: trigger.id, reason: "Waiting on you", nowIso: "2026-03-05T12:00:00.000Z" });
    const rows = store.usageSince("2026-03-02T00:00:00.000Z");
    expect(rows.map(row => [row.at.slice(0, 10), row.costUsd, row.refused])).toEqual([["2026-03-05", 0.5, false], ["2026-03-05", 0, true]]);
  });
});
