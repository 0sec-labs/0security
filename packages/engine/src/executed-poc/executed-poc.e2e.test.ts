/**
 * End to end through the real path: the `finding` tool saves a finding, the harness hook builds a PoC from its steps
 * and runs it through the existing verifier (`runVerifier`) on a snapshot of a fixture vulnerable app, the outcome is
 * stored on the finding, and report export shows it.
 *
 * Docker is not used. The container port (`ContainerRunner`) is faked: it claims container isolation and runs each
 * step with the real host shell in the snapshot directory the verifier hands it. The OCI adapter itself is covered by
 * its own tests.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ToolExecutor } from "../agent/tools.js";
import type { ToolContext } from "../agent/types.js";
import { exportReport } from "../report-export.js";
import { osecDB } from "../storage/index.js";
import { restoreFindingReviewFields } from "../storage/finding-helpers.js";
import type { ScanReport } from "../shared/index.js";
import { HostRunner } from "../verifier/host-runner.js";
import type { ContainerRunner, StepRequest } from "../verifier/port.js";
import { createExecutedPoc } from "./run.js";
import { planPocSpec } from "./plan.js";

const IMAGE = `node:24-bookworm-slim@sha256:${"a".repeat(64)}`;
const SECRET = "TOP-SECRET-7f3a91";

const cleanups: Array<() => void> = [];
afterEach(() => { for (const c of cleanups.splice(0)) c(); });

/** A tiny app with one path traversal (`read`) and one guarded twin (`safe-read`). */
function fixtureApp(): string {
  const dir = mkdtempSync(join(tmpdir(), "0-poc-fixture-"));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(join(dir, "public"));
  mkdirSync(join(dir, "data"));
  writeFileSync(join(dir, "public", "index.txt"), "welcome\n");
  writeFileSync(join(dir, "data", "secret.txt"), `${SECRET}\n`);
  writeFileSync(join(dir, "app.js"), [
    "const fs = require('fs'); const path = require('path');",
    "const [cmd, name] = process.argv.slice(2);",
    "const target = path.join(__dirname, 'public', name || '');",
    "if (cmd === 'read') process.stdout.write(fs.readFileSync(target, 'utf8'));",
    "else if (cmd === 'safe-read') {",
    "  if (!path.resolve(target).startsWith(path.join(__dirname, 'public') + path.sep)) { console.log('denied'); process.exit(0); }",
    "  process.stdout.write(fs.readFileSync(target, 'utf8'));",
    "} else process.exit(2);",
    "",
  ].join("\n"));
  const git = (...args: string[]) => execFileSync("git", args, { cwd: dir, stdio: "ignore" });
  git("init", "-q"); git("add", "-A");
  git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "fixture");
  return dir;
}

/** The fake container port: isolation "container", steps run by the host shell in the snapshot. Records every request. */
function fakeContainer(): ContainerRunner & { requests: StepRequest[] } {
  const host = new HostRunner();
  const requests: StepRequest[] = [];
  return { isolation: "container", requests, probe: () => host.probe(), run: (request) => { requests.push(request); return host.run(request); } };
}

function harness(runner: ContainerRunner, maxRuns = 3) {
  const home = mkdtempSync(join(tmpdir(), "0-poc-db-"));
  const db = new osecDB(join(home, "scan.db"));
  cleanups.push(() => { db.close(); rmSync(home, { recursive: true, force: true }); });
  const app = fixtureApp();
  db.createScan({ target: app, depth: "default", format: "json" }, "scan-1");
  const ctx = { target: app, scanId: "scan-1", role: "attack", findings: [], attackResults: [], targetInfo: {}, scopePath: app, executedPoc: createExecutedPoc({ image: IMAGE, maxRuns }, runner) } as unknown as ToolContext;
  const tools = new ToolExecutor(ctx, db);
  const save = async (title: string, severity: string, poc_steps: unknown[]) => {
    const res = await tools.execute({ name: "finding", arguments: { title, severity, category: "path-traversal", description: `${title} in the fixture app`, evidence_request: `request for ${title}`, evidence_response: "response", poc_steps } });
    expect(res.success).toBe(true);
    return (res.output as { findingId: string }).findingId;
  };
  return { db, app, save };
}

const shell = (id: string, cmd: string, expectText?: string) => ({ id, kind: "exploit", summary: id, action: { type: "shell", cmd }, ...(expectText ? { expect: { type: "body-contains", text: expectText } } : {}) });

describe("executed PoC, end to end", () => {
  it("proves one finding, fails one, and leaves one static-only; export distinguishes the three", async () => {
    const runner = fakeContainer();
    const { db, save } = harness(runner);
    const proven = await save("Path traversal in read", "high", [shell("p1", "node app.js read ../data/secret.txt", SECRET)]);
    const failing = await save("Path traversal in safe-read", "critical", [shell("f1", "node app.js safe-read ../data/secret.txt", SECRET)]);
    const staticOnly = await save("Header injection", "high", [{ id: "h1", kind: "exploit", summary: "hit", action: { type: "http", method: "GET", url: "/x" }, expect: { type: "body-contains", text: "injected" } }]);
    const lowSeverity = await save("Verbose banner", "low", [shell("l1", "node app.js read ../data/secret.txt", SECRET)]);

    const stored = (id: string) => db.getFindingExecutedPoc(id);
    expect(stored(proven)).toMatchObject({ outcome: "executed-proven", reason: "expectation-met", stepIds: ["p1"], run: { status: "pass", isolation: "container", imageDigest: `sha256:${"a".repeat(64)}` } });
    expect(stored(failing)).toMatchObject({ outcome: "executed-failed", reason: "expectation-not-met", run: { status: "fail", isolation: "container" } });
    expect(stored(failing)!.run!.logTail).toContain("denied");
    expect(stored(staticOnly)).toMatchObject({ outcome: "static-only", reason: "http-steps-need-a-running-app" });
    expect(stored(staticOnly)!.run).toBeUndefined();
    expect(stored(lowSeverity)).toBeUndefined();

    // Sandbox rules reach the port: network off, pinned image, resource limits, and only the two runnable PoCs ran.
    expect(runner.requests).toHaveLength(2);
    for (const request of runner.requests) {
      expect(request).toMatchObject({ network: "none", image: IMAGE });
      expect(request.limits).toMatchObject({ pidsLimit: 128, memory: "512m" });
    }

    const findings = [proven, failing, staticOnly, lowSeverity].map((id) => {
      const row = db.getFinding(id) as Record<string, unknown>;
      return { id, templateId: "manual", title: String(row.title), description: String(row.description), severity: row.severity, category: row.category, status: "discovered", evidence: { request: "r", response: "p" }, timestamp: 1, ...restoreFindingReviewFields(row as never) };
    });
    const report = { target: "/app", scanDepth: "quick", startedAt: "2026-01-01T00:00:00.000Z", completedAt: "2026-01-01T00:01:00.000Z", durationMs: 1, warnings: [], summary: { totalAttacks: 0, totalFindings: 4, critical: 1, high: 2, medium: 0, low: 1, info: 0 }, findings } as unknown as ScanReport;

    const markdown = new TextDecoder().decode((await exportReport(report, "markdown")).body);
    expect(markdown).toMatch(/\*\*PoC execution:\*\* `executed-proven`\. Executed, proven/);
    expect(markdown).toMatch(/\*\*PoC execution:\*\* `executed-failed`\. Executed, failed/);
    expect(markdown).toMatch(/\*\*PoC execution:\*\* `static-only`\. Static only: not proven by execution \(http steps need a running app\)/);
    expect((markdown.match(/PoC execution:/g) ?? []).length).toBe(3);

    const json = JSON.parse(new TextDecoder().decode((await exportReport(report, "json")).body));
    expect(json.findings.map((f: { title: string; executedPoc?: { outcome: string } }) => [f.title, f.executedPoc?.outcome])).toEqual(expect.arrayContaining([["Path traversal in read", "executed-proven"], ["Path traversal in safe-read", "executed-failed"], ["Header injection", "static-only"], ["Verbose banner", undefined]]));

    const sarif = JSON.parse(new TextDecoder().decode((await exportReport(report, "sarif")).body));
    expect(sarif.runs[0].results.map((r: { properties: { executedPoc?: { outcome: string } } }) => r.properties.executedPoc?.outcome).sort()).toEqual(["executed-failed", "executed-proven", "static-only", undefined]);

    const html = new TextDecoder().decode((await exportReport(report, "html")).body);
    expect(html).toContain("PoC execution: executed-proven.");
    expect(html).toContain("PoC execution: static-only.");
  });

  it("honors the run budget: the next runnable PoC is static-only, not run", async () => {
    const runner = fakeContainer();
    const { db, save } = harness(runner, 1);
    const first = await save("Traversal one", "high", [shell("a", "node app.js read ../data/secret.txt", SECRET)]);
    const second = await save("Traversal two", "high", [shell("b", "node app.js read ../data/secret.txt", SECRET)]);
    expect(db.getFindingExecutedPoc(first)!.outcome).toBe("executed-proven");
    expect(db.getFindingExecutedPoc(second)).toMatchObject({ outcome: "static-only", reason: "budget-exhausted" });
    expect(runner.requests).toHaveLength(1);
  });

  it("never reports proven from a host runner: it cannot isolate, so nothing runs", async () => {
    const { db, save } = harness(new HostRunner());
    const id = await save("Traversal", "high", [shell("a", "node app.js read ../data/secret.txt", SECRET)]);
    expect(db.getFindingExecutedPoc(id)).toMatchObject({ outcome: "static-only", reason: "no-container-isolation" });
  });

  it("refuses an unusable sandbox record: a proven record without a container run is not stored", () => {
    const { db } = harness(fakeContainer());
    expect(() => db.setFindingExecutedPoc("missing", { schemaVersion: 1, harness: "0security-executed-poc/1", outcome: "executed-proven", reason: "x", stepIds: [], startedAt: "2026-01-01T00:00:00.000Z", finishedAt: "2026-01-01T00:00:01.000Z" })).toThrow(/not a complete/i);
  });
});

describe("PoC planning", () => {
  const step = (cmd: string, expect?: unknown, cwd?: string) => ({ id: "s", kind: "exploit" as const, summary: "s", action: { type: "shell" as const, cmd, ...(cwd ? { cwd } : {}) }, ...(expect ? { expect: expect as never } : {}) });
  const plan = (steps: ReturnType<typeof step>[], image: string | null = IMAGE) => planPocSpec(steps, { image: image ?? undefined });

  it("builds a network-off, digest-pinned spec from shell steps with an observable expectation", () => {
    const p = plan([step("node app.js read x", { type: "body-contains", text: "SECRET-VALUE" })]);
    expect(p).toMatchObject({ ok: true, spec: { network: "none", image: IMAGE, success: { exit0: true } } });
  });
  it("refuses what cannot be proven honestly", () => {
    expect(plan([step("x", { type: "body-contains", text: "VALUE" })], null)).toEqual({ ok: false, reason: "no-sandbox-image" });
    expect(plan([step("x", { type: "body-contains", text: "VALUE" })], "node:24")).toEqual({ ok: false, reason: "image-not-pinned-by-digest" });
    expect(plan([step("echo ok")])).toEqual({ ok: false, reason: "no-observable-expectation" });
    expect(plan([step("echo SECRET-VALUE", { type: "body-contains", text: "SECRET-VALUE" })])).toEqual({ ok: false, reason: "expectation-written-in-command" });
    expect(plan([step("ls", { type: "body-contains", text: "ab" })])).toEqual({ ok: false, reason: "expectation-too-weak" });
    expect(plan([step("ls", { type: "body-contains", text: "VALUE" }, "../outside")])).toEqual({ ok: false, reason: "unsafe-cwd" });
    expect(plan([step("ls", { type: "body-contains", text: "VALUE" }, "/etc")])).toEqual({ ok: false, reason: "unsafe-cwd" });
  });
});
