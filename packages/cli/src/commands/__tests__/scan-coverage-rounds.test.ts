import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runScan, type ScanDeps } from "../scan.js";

const dirs: string[] = [];
const temp = () => { const dir = mkdtempSync(join(tmpdir(), "scan-rounds-")); dirs.push(dir); return dir; };
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); process.exitCode = undefined; });

/** `routes` Express files with one route each, and one helper no matcher hits. */
function app(routes: number): string {
  const dir = temp();
  mkdirSync(join(dir, "routes"));
  for (let i = 0; i < routes; i++) writeFileSync(join(dir, "routes", `r${i}.js`), `app.get('/r${i}', (req, res) => res.send('${i}'));\n`);
  mkdirSync(join(dir, "lib"));
  writeFileSync(join(dir, "lib", "util.js"), "exports.noop = () => {};\n");
  return dir;
}

const storedReport = { target: "", scanDepth: "default", startedAt: "", completedAt: "", durationMs: 0, summary: { totalAttacks: 0, totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }, findings: [], warnings: [] };

/**
 * `opens(thread, followUps)` lists the files the thread has opened after it was sent that many follow-ups.
 * The windowed status poll (a `window` query) carries no tool calls, like the real console; the full snapshot carries all.
 */
function harness(opens: (thread: number, followUps: number) => string[], how: (thread: number) => "ok" | "failed" = () => "ok", cost = 0.01) {
  const err: string[] = [];
  const out: string[] = [];
  const messages: Array<{ thread: number; text: string }> = [];
  const followUps = new Map<number, number>();
  let counter = 0;
  const client = {
    request: vi.fn(async (method: string, path: string, body?: { text?: string }) => {
      if (method === "POST" && path === "/api/console/sessions") return { session: { id: `t${++counter}` } };
      const n = Number(/sessions\/t(\d+)/.exec(path)?.[1]);
      if (method === "POST" && path.endsWith("/messages")) {
        messages.push({ thread: n, text: String(body?.text) });
        if (/^You did not open/.test(String(body?.text))) followUps.set(n, (followUps.get(n) ?? 0) + 1);
        return {};
      }
      if (method === "GET") {
        const windowed = path.includes("window=");
        const failed = how(n) === "failed";
        const files = opens(n, followUps.get(n) ?? 0);
        const calls = windowed ? [] : files.map(file => ({ type: "tool_use", name: "bash", input: { command: `cat ${file}` } }));
        return { snapshot: { session: { id: `t${n}`, status: failed ? "failed" : "ready" }, ...(failed ? { lastOutcome: { error: "boom" } } : {}), usage: { costUsd: cost * (1 + (followUps.get(n) ?? 0)) }, messages: [{ role: "assistant", content: [...calls, { type: "text", text: `Done ${n}.` }] }] } };
      }
      return {};
    }),
    dispose: vi.fn(),
  };
  const deps: ScanDeps = {
    open: async () => client as never, out: bytes => out.push(typeof bytes === "string" ? bytes : new TextDecoder().decode(bytes)), err: text => err.push(text), sleep: async () => {}, now: () => new Date("2026-01-01T00:00:00Z"),
    writeBytes: vi.fn(), loadReport: vi.fn(async () => storedReport as never),
    startConsole: vi.fn(async () => () => {}), changedFiles: vi.fn(async () => undefined), prePass: vi.fn(async () => undefined), diffFiles: vi.fn(async () => []), clone: vi.fn(),
    gitHead: async () => "abc1234567",
  };
  return { deps, err, out, messages, followUps };
}
const opts = (extra: Record<string, unknown> = {}) => ({ budget: "5", format: "json", timeout: "600", skill: "scan", passes: "1", batches: "off", dbPath: join(temp(), "db.sqlite"), ...extra }) as never;
const all = ["routes/r0.js", "routes/r1.js", "routes/r2.js", "lib/util.js"];

describe("follow-up rounds for files a thread did not open", () => {
  it("names the files it skipped in the same thread and records that it opened them", async () => {
    const h = harness((_n, rounds) => (rounds === 0 ? ["routes/r0.js"] : all));
    await runScan(app(3), opts(), h.deps);
    const followUps = h.messages.filter(message => /^You did not open/.test(message.text));
    expect(followUps).toHaveLength(1);
    expect(followUps[0]!.thread).toBe(1);
    expect(followUps[0]!.text).toContain("- routes/r1.js");
    expect(followUps[0]!.text).not.toContain("- routes/r0.js");
    expect(followUps[0]!.text).toContain("Open and review each one now, then add any findings and update your summary.");
    const json = JSON.parse(h.out.join(""));
    expect(json.fileCoverage).toMatchObject({ inScope: 4, opened: 4, unopenedCount: 0, rounds: { allowed: 2, used: 1 } });
    expect(h.err.join("\n")).toMatch(/follow-up round 1 of 2/);
  });

  it("asks nothing when the thread opened every file", async () => {
    const h = harness(() => all);
    await runScan(app(3), opts(), h.deps);
    expect(h.messages.filter(message => /^You did not open/.test(message.text))).toHaveLength(0);
    expect(JSON.parse(h.out.join("")).fileCoverage).toMatchObject({ opened: 4, rounds: { used: 0 } });
  });

  it("stops after a round that opened none of the files twice in a row and lists what is left", async () => {
    const h = harness(() => ["routes/r0.js"]);
    await runScan(app(3), opts({ coverageRounds: "5" }), h.deps);
    expect(h.messages.filter(message => /^You did not open/.test(message.text))).toHaveLength(2);
    const json = JSON.parse(h.out.join(""));
    expect(json.fileCoverage).toMatchObject({ opened: 1, unopenedCount: 3, rounds: { allowed: 5, used: 2 } });
    expect(json.fileCoverage.unopened).toEqual(["lib/util.js", "routes/r1.js", "routes/r2.js"]);
  });

  it("sends no follow-up with --coverage-rounds 0, but still says what was not opened", async () => {
    const h = harness(() => ["routes/r0.js"]);
    await runScan(app(3), opts({ coverageRounds: "0" }), h.deps);
    expect(h.messages.filter(message => /^You did not open/.test(message.text))).toHaveLength(0);
    expect(JSON.parse(h.out.join("")).fileCoverage).toMatchObject({ opened: 1, unopenedCount: 3, rounds: { allowed: 0, used: 0 } });
  });

  it("does not run after a failure: that is for the retry, not for coverage", async () => {
    const h = harness(() => [], () => "failed");
    await runScan(app(3), opts({ retries: "0" }), h.deps);
    expect(h.messages.filter(message => /^You did not open/.test(message.text))).toHaveLength(0);
  });

  it("does not start a round when little of the budget is left", async () => {
    const h = harness(() => ["routes/r0.js"], () => "ok", 4.9);
    await runScan(app(3), opts({ budget: "5" }), h.deps);
    expect(h.messages.filter(message => /^You did not open/.test(message.text))).toHaveLength(0);
    expect(h.err.join("\n")).toMatch(/too little of the \$5 budget is left/);
  });

  it("rejects a number of rounds outside 0 to 5", async () => {
    const h = harness(() => all);
    await runScan(app(3), opts({ coverageRounds: "6" }), h.deps);
    expect(process.exitCode).toBe(2);
    expect(h.err.join("\n")).toMatch(/--coverage-rounds must be a whole number from 0 to 5/);
  });
});

describe("batched scan with files that were not opened", () => {
  const big = (): string => {
    const dir = temp();
    mkdirSync(join(dir, "routes"));
    for (let i = 0; i < 6; i++) writeFileSync(join(dir, "routes", `r${i}.js`), `app.get('/r${i}', (req, res) => res.send('${i}'));\n`);
    return dir;
  };
  const batched = { batches: "on", batchSize: "3" };

  it("marks a unit reviewed only when its file was opened, and leaves the rest pending as not opened", async () => {
    // Batch 1 opens everything, batch 2 opens one of its three files.
    const h = harness(n => (n === 1 ? ["routes/r0.js", "routes/r1.js", "routes/r2.js"] : ["routes/r3.js"]));
    await runScan(big(), opts({ ...batched }), h.deps);
    const json = JSON.parse(h.out.join(""));
    expect(json.coverage.statement).toBe("reviewed 4 of 6 entry points; 2 not reached (not opened); 2 files never opened");
    expect(json.coverage).toMatchObject({ complete: false, inScope: 6, opened: 4, unopenedCount: 2, rounds: { allowed: 2, used: 2 } });
    expect(json.coverage.pendingUnits.map((unit: { path: string; reason: string }) => `${unit.path} ${unit.reason}`)).toEqual(["routes/r4.js not opened", "routes/r5.js not opened"]);
    expect(json.status).toBe("partial");
    expect(process.exitCode).toBe(3);
    // The follow-ups go to the thread of the batch that skipped them.
    expect(h.messages.filter(message => /^You did not open/.test(message.text)).every(message => message.thread === 2)).toBe(true);
  });

  it("reviews every unit when the follow-up gets the model to open the files", async () => {
    const h = harness((_n, rounds) => (rounds === 0 ? [] : ["routes/r0.js", "routes/r1.js", "routes/r2.js", "routes/r3.js", "routes/r4.js", "routes/r5.js"]));
    await runScan(big(), opts({ ...batched }), h.deps);
    const json = JSON.parse(h.out.join(""));
    expect(json.coverage).toMatchObject({ complete: true, opened: 6, unopenedCount: 0 });
    expect(json.coverage.statement).toBe("reviewed 6 of 6 entry points");
    expect(process.exitCode).toBeUndefined();
  });

  it("counts every unit reviewed with --coverage-rounds 0, as before", async () => {
    const h = harness(() => []);
    await runScan(big(), opts({ ...batched, coverageRounds: "0" }), h.deps);
    const json = JSON.parse(h.out.join(""));
    expect(json.coverage.complete).toBe(true);
    expect(json.coverage.statement).toBe("reviewed 6 of 6 entry points");
  });
});
