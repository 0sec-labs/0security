/**
 * Fault injection for `0 scan`: the built CLI runs a real scan (real console, real engine) against a local model API
 * that drops connections, answers 500, 429, 400 or 401, hangs or reports huge usage. Needs `pnpm --filter @0/cli build`;
 * the tests are skipped when the build is missing.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { startFaultServer, type Fault, type FaultServer } from "./fault-model-server.js";

// Each test runs a whole scan in a child process, some of them waiting out a time limit.
vi.setConfig({ testTimeout: 120_000 });

const here = fileURLToPath(new URL(".", import.meta.url));
const dist = join(here, "../../dist/index.js");
const built = existsSync(dist);
const root = mkdtempSync(join(tmpdir(), "0-scan-faults-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

/** Four routes, one helper: with --batch-size 2 that is two batches of routes and one of other files. */
function fixture(name: string): string {
  const dir = join(root, name);
  mkdirSync(join(dir, "routes"), { recursive: true });
  for (let i = 0; i < 4; i++) writeFileSync(join(dir, "routes", `r${i}.js`), `app.get('/r${i}', (req, res) => res.send('${i}'));\n`);
  mkdirSync(join(dir, "lib"));
  writeFileSync(join(dir, "lib", "util.js"), "exports.noop = () => {};\n");
  return dir;
}

interface Run { code: number | null; stdout: string; stderr: string; json: Record<string, any> }
function scan(dir: string, server: FaultServer, args: string[], timeoutMs = 120_000): Promise<Run> {
  const home = mkdtempSync(join(root, "home-"));
  const child = spawn(process.execPath, [dist, "scan", dir, "--format", "json", "--prepass", "off", "--budget", "1", "--coverage-rounds", "0", ...args], {
    cwd: dir,
    env: {
      PATH: process.env.PATH ?? "", HOME: home, TMPDIR: home, NO_COLOR: "1",
      OPENAI_API_KEY: "stub-key-not-a-secret", OPENAI_BASE_URL: server.url, OPENAI_WIRE_API: "chat_completions",
      // Fail fast: the provider layer's own backoff would turn one injected error into minutes.
      ZERO_LLM_MAX_RETRIES: "0", ZERO_LLM_429_MAX_RETRIES: "0", ZERO_LLM_FALLBACK: "",
      ZERO_NO_TELEMETRY: "1", ZERO_NO_UPDATE_CHECK: "1", DO_NOT_TRACK: "1", ZERO_DISABLE_MEMORY: "1", ZERO_SUPPRESS_PROVIDER_STARTUP_LOG: "1",
    },
  });
  let stdout = ""; let stderr = "";
  child.stdout.on("data", chunk => { stdout += chunk; });
  child.stderr.on("data", chunk => { stderr += chunk; });
  return new Promise(resolve => {
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.on("close", code => { clearTimeout(timer); let json: Record<string, any> = {}; try { json = JSON.parse(stdout); } catch { /* the test shows stderr */ } resolve({ code, stdout, stderr, json }); });
  });
}

let server: FaultServer | undefined;
afterEach(async () => { await server?.close(); server = undefined; });
const serve = async (plan: (n: number) => Fault) => (server = await startFaultServer(plan));
const batched = ["--batch-size", "2"];

describe.skipIf(!built)("scan with a failing model provider", () => {
  beforeAll(() => { expect(existsSync(dist)).toBe(true); });

  it("finishes when a batch loses its connection once, and says it retried", async () => {
    const s = await serve(n => (n === 2 ? "drop" : "ok"));
    const run = await scan(fixture("drop-once"), s, [...batched, "--retries", "2"]);
    expect(run.json.status, run.stderr).toBe("complete");
    expect(run.json.coverage.complete).toBe(true);
    expect(run.json.coverage.retries).toMatchObject({ allowed: 2, total: 1, batches: [{ attempts: 2, recovered: true }] });
    expect(run.json.coverage.retries.batches[0].causes[0]).toBe("provider_connection");
    expect(run.stderr).toMatch(/trying again in \d+s \(retry 1 of 2/);
    expect(s.seen.length).toBe(4);
    expect(run.code).toBe(0);
  });

  it("finishes after a 500 and after a 429", async () => {
    for (const fault of ["http500", "http429"] as const) {
      const s = await serve(n => (n === 1 ? fault : "ok"));
      const run = await scan(fixture(`once-${fault}`), s, batched);
      expect(run.json.status, run.stderr).toBe("complete");
      expect(run.json.coverage.retries.total).toBe(1);
      expect(run.json.coverage.retries.batches[0].causes[0]).toBe(fault === "http500" ? "provider_server" : "provider_rate_limit");
      await s.close();
    }
  });

  it("leaves the batch pending with the cause when the failure does not go away", async () => {
    const s = await serve(n => (n === 1 || n === 2 ? "ok" : "http500"));
    const run = await scan(fixture("persistent"), s, [...batched, "--retries", "1"]);
    expect(run.json.status).toBe("partial");
    expect(run.json.failure.cause).toBe("provider_server");
    expect(run.json.failure.message).toMatch(/server error/i);
    expect(run.json.coverage.complete).toBe(false);
    expect(run.json.coverage.retries.batches[0]).toMatchObject({ batch: 3, attempts: 2, recovered: false });
    expect(run.json.coverage.failures[0]).toMatchObject({ batch: 3, cause: "provider_server" });
    expect(run.json.coverage.pendingUnits[0]).toMatchObject({ path: "lib", reason: "thread failed" });
    expect(run.stderr).toContain("still failing after 1 retry");
    expect(run.code).toBe(3);
  });

  it("does not retry with --retries 0", async () => {
    const s = await serve(n => (n === 1 ? "drop" : "ok"));
    const run = await scan(fixture("no-retries"), s, [...batched, "--retries", "0"]);
    expect(run.json.status).toBe("partial");
    expect(run.json.coverage.retries.total).toBe(0);
    expect(run.json.failure.cause).toBe("provider_connection");
  });

  it("does not retry a refused key or an invalid request", async () => {
    for (const [fault, cause] of [["http401", "provider_auth"], ["http400", "provider_invalid_request"]] as const) {
      const s = await serve(() => fault);
      const run = await scan(fixture(`never-${fault}`), s, [...batched, "--retries", "2"]);
      expect(run.json.status, run.stderr).toBe("failed");
      expect(run.json.failure.cause).toBe(cause);
      expect(run.json.coverage.retries.total).toBe(0);
      // One request per batch that started: nothing was sent twice.
      expect(s.seen.length).toBeLessThanOrEqual(3);
      expect(run.stderr).not.toContain("trying again");
      await s.close();
    }
  });

  it("does not retry at the budget", async () => {
    const s = await serve(() => "costly");
    const run = await scan(fixture("budget"), s, [...batched, "--retries", "2", "--budget", "0.5"]);
    expect(run.json.status).toBe("budget_exhausted");
    expect(run.json.failure.cause).toBe("budget");
    expect(run.json.coverage.retries.total).toBe(0);
    expect(s.seen.length).toBe(1);
    expect(run.code).toBe(3);
  });

  it("cancels a batch that hangs at its own time limit and goes on with the next", async () => {
    const s = await serve(n => (n === 1 ? "hang" : "ok"));
    const run = await scan(fixture("hang"), s, [...batched, "--batch-timeout", "4", "--timeout", "300"]);
    expect(run.json.status, run.stderr).toBe("partial");
    expect(run.json.failure.cause).toBe("batch_timeout");
    expect(run.json.coverage.pendingUnits[0].reason).toBe("timeout");
    expect(run.json.coverage.batches.reviewed).toBe(2);
    expect(run.stderr).toMatch(/batch 1 of 3: not reviewed \(timeout/);
  }, 90_000);

  it("asks a single thread to continue once after the connection dropped", async () => {
    const s = await serve(n => (n === 1 ? "drop" : "ok"));
    const run = await scan(fixture("single-cut"), s, ["--batches", "off"]);
    expect(run.json.status, run.stderr).toBe("complete");
    expect(run.stderr).toContain("asking thread");
    expect(s.seen.length).toBe(2);
  });

  it("reports why a single thread failed when it keeps failing", async () => {
    const s = await serve(() => "drop");
    const run = await scan(fixture("single-fail"), s, ["--batches", "off"]);
    expect(run.json.status).toBe("failed");
    expect(run.json.failure.cause).toBe("provider_connection");
    expect(run.stderr).toMatch(/scan failed: The model provider dropped the connection/);
    expect(run.code).toBe(1);
  });
});
