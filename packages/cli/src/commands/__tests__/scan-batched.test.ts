import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runScan, type ScanDeps } from "../scan.js";

const dirs: string[] = [];
const temp = () => { const dir = mkdtempSync(join(tmpdir(), "scan-batched-")); dirs.push(dir); return dir; };
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); process.exitCode = undefined; });

/** A folder with `routes` Express files, one route each, and one helper file no matcher hits. */
function app(routes: number): string {
  const dir = temp();
  mkdirSync(join(dir, "routes"));
  for (let i = 0; i < routes; i++) writeFileSync(join(dir, "routes", `r${String(i).padStart(2, "0")}.js`), `app.get('/r${i}', (req, res) => res.send('${i}'));\n`);
  mkdirSync(join(dir, "lib"));
  writeFileSync(join(dir, "lib", "util.js"), "exports.noop = () => {};\n");
  return dir;
}

const finding = (id: string) => ({ id, templateId: "manual", title: `bug ${id}`, description: "d", severity: "high", category: "code-injection", status: "discovered", timestamp: 1, evidence: { request: "r", response: "s" }, reviewAnnotation: { path: `routes/${id}.js`, startLine: 1 } });
const storedReport = (findings: unknown[]) => ({ target: "", scanDepth: "default", startedAt: "", completedAt: "", durationMs: 0, summary: { totalAttacks: 0, totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }, findings, warnings: [] });

interface Harness { deps: ScanDeps; out: string[]; err: string[]; messages: string[]; created: string[]; loaded: string[] }
/** `behaviour(threadNumber)` says how thread N ends: normally, at its cost ceiling, or failed. */
function harness(dbPath: string, behaviour: (n: number) => "ok" | "ceiling" | "failed" | `error:${string}` = () => "ok", head: () => string | undefined = () => "abc1234567", start = 0): Harness {
  const out: string[] = [];
  const err: string[] = [];
  const messages: string[] = [];
  const created: string[] = [];
  const loaded: string[] = [];
  let counter = start;
  const client = {
    request: vi.fn(async (method: string, path: string, body?: { text?: string }) => {
      if (method === "POST" && path === "/api/console/sessions") { const id = `t${++counter}`; created.push(id); return { session: { id } }; }
      if (method === "POST" && path.endsWith("/messages")) { messages.push(String(body?.text)); return {}; }
      if (method === "GET") {
        const n = Number(/sessions\/t(\d+)/.exec(path)?.[1]);
        const how = behaviour(n);
        const failed = how === "failed" || how.startsWith("error:");
        return { snapshot: { session: { id: `t${n}`, status: failed ? "failed" : "ready", ...(how === "ceiling" ? { costCeilingExceeded: true, costCeilingUsd: 0.1 } : {}) }, ...(how.startsWith("error:") ? { lastOutcome: { error: how.slice(6) } } : {}), usage: { costUsd: 0.1 }, messages: [{ role: "assistant", content: [{ type: "text", text: `Covered thread ${n}.` }] }] } };
      }
      return {};
    }),
    dispose: vi.fn(),
  };
  const deps: ScanDeps = {
    open: async () => client as never, out: bytes => out.push(typeof bytes === "string" ? bytes : new TextDecoder().decode(bytes)), err: text => err.push(text), sleep: async () => {}, now: () => new Date("2026-01-01T00:00:00Z"),
    writeBytes: vi.fn(), loadReport: vi.fn(async (_client, id: string) => { loaded.push(id); return storedReport([finding(`r0${id.slice(1)}`)]) as never; }),
    startConsole: vi.fn(async () => () => {}), changedFiles: vi.fn(async () => undefined), prePass: vi.fn(async () => undefined), diffFiles: vi.fn(async () => []), clone: vi.fn(),
    gitHead: async () => head(),
  };
  void dbPath;
  return { deps, out, err, messages, created, loaded };
}
const opts = (dbPath: string, extra: Record<string, unknown> = {}) => ({ budget: "5", format: "json", timeout: "60", skill: "scan", passes: "1", dbPath, coverageRounds: "0", ...extra }) as never;
const report = (h: Harness) => JSON.parse(h.out.join(""));

describe("batched scan", () => {
  it("stays one thread for a small folder, with no coverage claim", async () => {
    const dir = app(3);
    const h = harness(join(temp(), "db.sqlite"));
    await runScan(dir, opts(join(temp(), "db.sqlite")), h.deps);
    expect(h.created).toHaveLength(1);
    expect(report(h).coverage).toBeUndefined();
    expect(h.messages[0]).not.toContain("<batch-units>");
  });

  it("keeps one thread with --batches off however large the folder is", async () => {
    const dir = app(30);
    const h = harness("x");
    await runScan(dir, opts(join(temp(), "db.sqlite"), { batches: "off" }), h.deps);
    expect(h.created).toHaveLength(1);
    expect(report(h).coverage).toBeUndefined();
  });

  it("splits a large folder into batches, reviews them all and reports complete coverage", async () => {
    const dir = app(20);
    const db = join(temp(), "db.sqlite");
    const h = harness(db);
    await runScan(dir, opts(db), h.deps);
    // 20 routes at 8 per batch is 3 batches, then one for the group of other files.
    expect(h.created).toHaveLength(4);
    expect(h.messages[0]).toContain("batch 1 of 4");
    expect(h.messages[0]).toContain("<batch-units>");
    expect(h.messages[0]).toContain("routes/r00.js:1 GET /r0");
    expect(h.messages[3]).toContain("lib/util.js");
    const json = report(h);
    expect(json.status).toBe("complete");
    expect(json.coverage).toMatchObject({ complete: true, statement: "reviewed 20 of 20 entry points; 1 of 1 groups of other files reviewed", entryPoints: { total: 20, reviewed: 20, pending: 0 }, batches: { total: 4, reviewed: 4, pending: 0 } });
    expect(json.threadIds).toEqual(["t1", "t2", "t3", "t4"]);
    expect(json.counts.total).toBe(4);
    expect(json.findings.every((item: Record<string, unknown>) => item["foundInPasses"] === undefined)).toBe(true);
    expect(process.exitCode).toBeUndefined();
  });

  it("splits the budget over the batches, so no thread gets all of it", async () => {
    const dir = app(20);
    const db = join(temp(), "db.sqlite");
    const h = harness(db);
    await runScan(dir, opts(db, { budget: "2" }), h.deps);
    expect(h.err.some(line => /batch 1 of 4, budget \$0\.5\)/.test(line))).toBe(true);
  });

  it("leaves units pending when a batch stops at its budget, says so everywhere and exits 3", async () => {
    const dir = app(20);
    const db = join(temp(), "db.sqlite");
    const h = harness(db, n => (n === 2 ? "ceiling" : "ok"));
    await runScan(dir, opts(db), h.deps);
    const json = report(h);
    expect(json.status).toBe("budget_exhausted");
    expect(json.coverage.complete).toBe(false);
    expect(json.coverage.statement).toBe("reviewed 12 of 20 entry points; 8 not reached (budget); 1 of 1 groups of other files reviewed");
    expect(json.coverage.entryPoints).toMatchObject({ reviewed: 12, pending: 8 });
    expect(json.coverage.pendingUnits).toHaveLength(8);
    expect(json.summary).toMatch(/^Coverage: reviewed 12 of 20 entry points; 8 not reached/);
    expect(process.exitCode).toBe(3);
    const stderr = h.err.join("\n");
    expect(stderr).toMatch(/Stopped by the \$5 budget; 8 of 20 entry points not reached\./);
    expect(stderr).toMatch(/Continue with: 0 scan \S+ --resume scan-\S+/);
    expect(stderr).toContain(`Continue with: ${json.coverage.resume}`);
    expect(json.coverage.stoppedBy).toBe("the $5 budget");
  });

  it("says the review is partial in markdown and sarif, never that the target passed", async () => {
    const dir = app(20);
    const db = join(temp(), "db.sqlite");
    for (const format of ["md", "sarif"]) {
      const h = harness(db, n => (n === 2 ? "ceiling" : "ok"));
      h.deps.loadReport = vi.fn(async () => storedReport([]) as never);
      await runScan(dir, opts(db, { format }), h.deps);
      const text = h.out.join("");
      if (format === "md") {
        expect(text).toContain("## Coverage");
        expect(text).toContain("reviewed 12 of 20 entry points; 8 not reached (budget)");
        expect(text).not.toContain("The target passed all tests");
        expect(text).not.toContain("No Findings");
      } else expect(JSON.parse(text).runs[0].properties.coverage).toMatchObject({ complete: false, entryPoints: { pending: 8 } });
      process.exitCode = undefined;
    }
  });

  it("resumes: only the pending units run, findings of the earlier threads are kept, and coverage completes", async () => {
    const dir = app(20);
    const db = join(temp(), "db.sqlite");
    const first = harness(db, n => (n === 2 ? "ceiling" : "ok"));
    await runScan(dir, opts(db), first.deps);
    const scanId = report(first).coverage.scanId as string;
    process.exitCode = undefined;

    const second = harness(db, () => "ok", () => "abc1234567", 10);
    await runScan(dir, opts(db, { resume: "latest" }), second.deps);
    expect(second.created).toHaveLength(1);
    const prompt = second.messages[0]!;
    expect(prompt).toContain("batch 1 of 1");
    expect(prompt).toContain("routes/r08.js:1");
    expect(prompt).not.toContain("routes/r00.js");
    const json = report(second);
    expect(json.coverage).toMatchObject({ scanId, complete: true, entryPoints: { reviewed: 20, pending: 0 } });
    expect(json.status).toBe("complete");
    // The earlier threads' findings are read back, plus the new thread's.
    expect(second.loaded).toEqual(expect.arrayContaining(["t1", "t3", "t4", "t11"]));
    expect(json.counts.total).toBe(5);
    expect(process.exitCode).toBeUndefined();
  });

  it("refuses to resume when the git HEAD changed, and continues with --force", async () => {
    const dir = app(20);
    const db = join(temp(), "db.sqlite");
    await runScan(dir, opts(db), harness(db, n => (n === 2 ? "ceiling" : "ok")).deps);
    process.exitCode = undefined;
    const refused = harness(db, () => "ok", () => "fffffff000");
    await runScan(dir, opts(db, { resume: "latest" }), refused.deps);
    expect(refused.err.join("\n")).toMatch(/git HEAD of .* changed since scan scan-.*--force/);
    expect(refused.created).toHaveLength(0);
    expect(process.exitCode).toBe(2);
    process.exitCode = undefined;
    const forced = harness(db, () => "ok", () => "fffffff000");
    await runScan(dir, opts(db, { resume: "latest", force: true }), forced.deps);
    expect(forced.created).toHaveLength(1);
    expect(forced.err.join("\n")).toMatch(/warning: continuing scan/);
  });

  it("stops starting batches when the budget is spent and leaves the rest pending", async () => {
    const dir = app(20);
    const db = join(temp(), "db.sqlite");
    const h = harness(db);
    // Each thread reports $0.10; a $0.20 budget leaves room for two batches, then the scan stops.
    await runScan(dir, opts(db, { budget: "0.2" }), h.deps);
    const json = report(h);
    expect(h.created.length).toBeLessThan(4);
    expect(json.coverage.complete).toBe(false);
    expect(json.status).toBe("budget_exhausted");
    expect(json.coverage.notReached).toMatchObject({ budget: expect.any(Number) });
    expect(process.exitCode).toBe(3);
  });

  it("rejects bad batch options and resume on nothing", async () => {
    const dir = app(2);
    const db = join(temp(), "db.sqlite");
    for (const [extra, message] of [[{ batches: "sometimes" }, /--batches must be/], [{ batchSize: "0" }, /--batch-size/], [{ concurrency: "9" }, /--concurrency/], [{ batches: "on", passes: "2" }, /--passes cannot/], [{ force: true }, /--force only applies/], [{ resume: "latest", diff: "main" }, /drop --diff/]] as const) {
      const h = harness(db);
      await runScan(dir, opts(db, extra), h.deps);
      expect(h.err.join("\n")).toMatch(message);
      expect(process.exitCode).toBe(2);
      process.exitCode = undefined;
    }
    const none = harness(db);
    await runScan(dir, opts(db, { resume: "latest" }), none.deps);
    expect(none.err.join("\n")).toMatch(/No batched scan of .* to resume/);
  });

  it("exits 0 with --allow-partial, still says partial, and exits 1 by --fail-on", async () => {
    const dir = app(20);
    const db = join(temp(), "db.sqlite");
    const h = harness(db, n => (n === 2 ? "ceiling" : "ok"));
    await runScan(dir, opts(db, { allowPartial: true }), h.deps);
    const json = report(h);
    expect(process.exitCode).toBeUndefined();
    expect(json.status).toBe("partial");
    expect(json.coverage).toMatchObject({ complete: false, entryPoints: { pending: 8 } });
    expect(json.coverage.resume).toMatch(/^0 scan \S+ --resume scan-/);
    expect(h.err.join("\n")).toMatch(/8 of 20 entry points not reached/);
    process.exitCode = undefined;
    const strict = harness(db, n => (n === 2 ? "ceiling" : "ok"));
    await runScan(dir, opts(db, { allowPartial: true, failOn: "high" }), strict.deps);
    expect(process.exitCode).toBe(1);
  });

  it("names the reason in the hint when a batch fails, and puts the hint in the markdown report", async () => {
    const dir = app(20);
    const db = join(temp(), "db.sqlite");
    const h = harness(db, n => (n === 2 ? "failed" : "ok"));
    h.deps.loadReport = vi.fn(async () => storedReport([]) as never);
    await runScan(dir, opts(db, { format: "md" }), h.deps);
    expect(h.err.join("\n")).toMatch(/Stopped by a failed batch/);
    expect(h.out.join("")).toMatch(/Continue with: 0 scan \S+ --resume scan-/);
    expect(process.exitCode).toBe(3);
  });

  it("quotes a folder with a space in the resume command", async () => {
    const dir = join(temp(), "my app");
    mkdirSync(join(dir, "routes"), { recursive: true });
    for (let i = 0; i < 20; i++) writeFileSync(join(dir, "routes", `r${i}.js`), `app.get('/r${i}', (req, res) => res.send('${i}'));\n`);
    const db = join(temp(), "db.sqlite");
    const h = harness(db, n => (n === 2 ? "ceiling" : "ok"));
    await runScan(dir, opts(db), h.deps);
    expect(report(h).coverage.resume).toMatch(/^0 scan '.*my app' --resume scan-/);
  });

  it("--plan lists the folder and starts nothing", async () => {
    const dir = app(20);
    const db = join(temp(), "db.sqlite");
    const h = harness(db);
    await runScan(dir, opts(db, { plan: true, format: "md" }), h.deps);
    const text = h.out.join("");
    expect(text).toMatch(/Entry points: 20 \(http-route 20\)/);
    expect(text).toMatch(/--batches auto would batch this folder/);
    expect(text).toMatch(/not a quote/);
    expect(h.created).toHaveLength(0);
    expect(h.deps.prePass).not.toHaveBeenCalled();
    expect(existsSync(db)).toBe(false);
    const json = harness(db);
    await runScan(dir, opts(db, { plan: true }), json.deps);
    expect(JSON.parse(json.out.join(""))).toMatchObject({ entryPoints: 20, batchCount: 4, autoWouldBatch: true });
    expect(existsSync(db)).toBe(false);
    const bad = harness(db);
    await runScan(dir, opts(db, { plan: true, resume: "latest" }), bad.deps);
    expect(process.exitCode).toBe(2);
  });

  it("prints the ledger with --coverage", async () => {
    const dir = app(20);
    const db = join(temp(), "db.sqlite");
    await runScan(dir, opts(db), harness(db, n => (n === 2 ? "ceiling" : "ok")).deps);
    process.exitCode = undefined;
    const text = harness(db);
    await runScan(dir, opts(db, { coverage: true, format: "md" }), text.deps);
    const body = text.out.join("");
    expect(body).toContain("reviewed 12 of 20 entry points; 8 not reached (budget)");
    expect(body).toMatch(/pending\s+http-route\s+routes\/r08\.js:1 GET \/r8\s+\(budget\)/);
    expect(body).toMatch(/reviewed\s+http-route\s+routes\/r00\.js:1/);
    expect(text.created).toHaveLength(0);
    const json = harness(db);
    await runScan(dir, opts(db, { coverage: "latest", format: "json" }), json.deps);
    expect(JSON.parse(json.out.join(""))).toMatchObject({ complete: false, entryPoints: { total: 20, pending: 8 } });
  });
});

describe("batched scan failures", () => {
  const dropped = "error:OpenAI API error: OpenAI transport failure [UND_ERR_SOCKET]: The connection closed before a complete response was received. Request outcome may be unknown. Automatic replay is disabled" as const;

  it("runs a batch again after a dropped connection, keeps the findings of the failed attempt and counts its cost", async () => {
    const dir = app(20);
    const db = join(temp(), "db.sqlite");
    // Thread 2 (batch 2, first attempt) fails; thread 3 is its retry.
    const h = harness(db, n => (n === 2 ? dropped : "ok"));
    await runScan(dir, opts(db), h.deps);
    const json = report(h);
    expect(h.created).toHaveLength(5);
    expect(json.status).toBe("complete");
    expect(json.coverage.retries).toMatchObject({ allowed: 2, total: 1, batches: [{ batch: 2, attempts: 2, causes: ["provider_connection"], recovered: true }] });
    expect(json.threadIds).toEqual(["t1", "t2", "t3", "t4", "t5"]);
    // The failed attempt's findings are in the report, and so is its cost (0.1 a thread).
    expect(h.loaded).toContain("t2");
    expect(json.costUsd).toBeCloseTo(0.5, 5);
    expect(json.failure).toBeUndefined();
    expect(h.err.join("\n")).toMatch(/batch 2 of 4: The model provider dropped the connection.*trying again in \d+s \(retry 1 of 2/);
    expect(process.exitCode).toBeUndefined();
  });

  it("leaves a batch pending with the cause after the retries are used, and names the cause in every format", async () => {
    const dir = app(20);
    const db = join(temp(), "db.sqlite");
    const h = harness(db, n => (n >= 2 && n <= 4 ? dropped : "ok"));
    await runScan(dir, opts(db), h.deps);
    const json = report(h);
    expect(json.status).toBe("partial");
    expect(json.failure).toMatchObject({ cause: "provider_connection" });
    expect(json.failure.message).toMatch(/^The model provider dropped the connection/);
    expect(json.failure.message).not.toContain("Automatic replay");
    expect(json.coverage.retries.batches[0]).toMatchObject({ batch: 2, attempts: 3, recovered: false });
    expect(json.coverage.failures).toEqual([{ batch: 2, cause: "provider_connection", message: json.failure.message }]);
    expect(json.coverage.pendingUnits[0].reason).toBe("thread failed");
    expect(h.err.join("\n")).toContain("scan stopped early: The model provider dropped the connection");
    expect(process.exitCode).toBe(3);
    process.exitCode = undefined;
    const sarif = harness(db, n => (n >= 2 && n <= 4 ? dropped : "ok"));
    await runScan(dir, opts(join(temp(), "db.sqlite"), { format: "sarif" }), sarif.deps);
    expect(JSON.parse(sarif.out.join("")).runs[0].properties.failure.cause).toBe("provider_connection");
  });

  it("does not retry with --retries 0, for a refused key, or at the budget", async () => {
    const dir = app(20);
    const none = harness("x", n => (n === 2 ? dropped : "ok"));
    await runScan(dir, opts(join(temp(), "db.sqlite"), { retries: "0" }), none.deps);
    expect(none.created).toHaveLength(4);
    expect(report(none).coverage.retries.total).toBe(0);
    process.exitCode = undefined;
    const auth = harness("x", n => (n === 2 ? "error:OpenAI API error 401: Incorrect API key provided" : "ok"));
    await runScan(dir, opts(join(temp(), "db.sqlite")), auth.deps);
    expect(auth.created).toHaveLength(4);
    expect(report(auth).failure.cause).toBe("provider_auth");
    process.exitCode = undefined;
    const ceiling = harness("x", n => (n === 2 ? "ceiling" : "ok"));
    await runScan(dir, opts(join(temp(), "db.sqlite")), ceiling.deps);
    expect(report(ceiling).failure.cause).toBe("budget");
    expect(report(ceiling).coverage.retries.total).toBe(0);
  });

  it("rejects a bad --retries or --batch-timeout", async () => {
    for (const extra of [{ retries: "-1" }, { retries: "9" }, { retries: "1.5" }, { batchTimeout: "0" }, { batchTimeout: "soon" }]) {
      const h = harness("x");
      await runScan(app(3), opts(join(temp(), "db.sqlite"), extra), h.deps);
      expect(process.exitCode).toBe(2);
      process.exitCode = undefined;
    }
  });
});

describe("single thread failures", () => {
  it("keeps the findings recorded before the thread failed, reports the cause and exits 1", async () => {
    const dir = app(3);
    const db = join(temp(), "db.sqlite");
    const h = harness(db, () => "error:OpenAI API error: OpenAI transport failure [ECONNRESET]: read ECONNRESET. Automatic replay is disabled");
    await runScan(dir, opts(db, { retries: "0" }), h.deps);
    const json = report(h);
    expect(json.status).toBe("failed");
    expect(json.counts.total).toBe(1);
    expect(json.failure).toMatchObject({ cause: "provider_connection" });
    expect(h.err.join("\n")).toMatch(/scan failed: The model provider dropped the connection.*The 1 finding recorded so far is in the report/);
    expect(process.exitCode).toBe(1);
  });

  it("asks the thread once to continue after a transient failure", async () => {
    const dir = app(3);
    const db = join(temp(), "db.sqlite");
    let polls = 0;
    // The thread fails on its first status read and is ready once it has been asked to continue.
    const h = harness(db, () => (polls++ < 1 ? "error:OpenAI API error 503: overloaded" : "ok"));
    await runScan(dir, opts(db), h.deps);
    expect(h.messages).toHaveLength(2);
    expect(h.messages[1]).toMatch(/Continue the scan from where you stopped/);
    expect(h.err.join("\n")).toMatch(/The model provider returned a server error.*asking thread t1 to continue/);
    expect(report(h).status).toBe("complete");
  });
});
