import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runScan, type ScanDeps } from "../scan.js";

const dirs: string[] = [];
const folder = () => { const dir = mkdtempSync(join(tmpdir(), "scan-ctx-test-")); dirs.push(dir); return dir; };
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); process.exitCode = undefined; });

const finished = { session: { id: "t1", status: "ready" }, usage: { costUsd: 0.01 }, messages: [{ role: "assistant", content: [{ type: "text", text: "done" }] }] };
const finding = (id: string, severity: string, path: string) => ({ id, templateId: "manual", title: `Finding ${id}`, description: "d", severity, category: "xss", status: "discovered", timestamp: 1, evidence: { request: "", response: "", analysis: "a" }, reviewAnnotation: { path, startLine: 1 } });
const report = { target: "", scanDepth: "default", startedAt: "", completedAt: "", durationMs: 0, summary: { totalAttacks: 0, totalFindings: 3, critical: 1, high: 1, medium: 1, low: 0, info: 0 }, warnings: [],
  findings: [finding("admin-high", "high", "services/admin/panel.ts"), finding("checkout-medium", "medium", "src/payments/checkout.ts"), finding("demo-critical", "critical", "examples/demo.ts")] };
function fakes() {
  const out: string[] = [], err: string[] = [];
  const client = { request: vi.fn(async (method: string) => (method === "GET" ? { snapshot: finished } : { session: { id: "t1" } })), dispose: vi.fn() };
  const deps = {
    open: async () => client as never, out: (text: string) => out.push(String(text)), err: (text: string) => err.push(text), sleep: async () => {}, now: () => new Date("2026-01-01T00:00:00Z"), writeBytes: vi.fn(),
    loadReport: vi.fn(async () => report as never), startConsole: vi.fn(async () => () => {}), changedFiles: vi.fn(async () => undefined), prePass: vi.fn(async () => undefined), diffFiles: vi.fn(async () => []), clone: vi.fn(),
    gitRemote: vi.fn(async () => "https://github.com/acme/shop.git"),
  } as ScanDeps;
  return { deps, out, err, client };
}
const options = (extra: Record<string, unknown> = {}) => ({ budget: "5", format: "json", timeout: "60", skill: "scan", passes: "1", ...extra }) as never;
const SHOP = { entries: [{ match: "src/payments/**", tags: ["payments", "personal-data"], note: "card data" }, { match: "examples/**", tags: ["non-production"] }] };
const ids = (out: string[]) => (JSON.parse(out.join("")) as { findings: Array<{ id: string }> }).findings.map(f => f.id);

describe("scan --business-context", () => {
  it("orders the report by the context, says why and still fails --fail-on by real severity", async () => {
    const dir = folder(); const file = join(folder(), "shop.json");
    writeFileSync(file, JSON.stringify(SHOP));
    const plain = fakes();
    await runScan(dir, options(), plain.deps);
    expect(ids(plain.out)).toEqual(["demo-critical", "admin-high", "checkout-medium"]);
    const ranked = fakes();
    await runScan(dir, options({ businessContext: file, failOn: "critical" }), ranked.deps);
    expect(ids(ranked.out)).toEqual(["checkout-medium", "admin-high", "demo-critical"]);
    const body = JSON.parse(ranked.out.join("")) as { counts: Record<string, number>; findings: Array<{ severity: string; businessContext?: { shift: number } }> };
    expect(body.findings.map(f => f.severity)).toEqual(["medium", "high", "critical"]);
    expect(body.findings[0]!.businessContext!.shift).toBe(2);
    expect(body.counts).toMatchObject({ critical: 1, high: 1, medium: 1 });
    // The critical demo finding sinks to the bottom of the list and still fails the run.
    expect(process.exitCode).toBe(1);
  });

  it("does not let the context change the exit code", async () => {
    const dir = folder(); const file = join(folder(), "shop.json");
    writeFileSync(file, JSON.stringify({ entries: [{ tags: ["internet-facing", "payments"] }] }));
    const lone = { ...report, findings: [finding("m", "medium", "src/a.ts")] };
    const run = fakes();
    run.deps.loadReport = vi.fn(async () => lone as never);
    await runScan(dir, options({ businessContext: file, failOn: "high" }), run.deps);
    expect(process.exitCode).toBeUndefined();
  });

  it("matches repository rules against the git remote of the scanned folder, or --repository", async () => {
    const dir = folder(); const file = join(folder(), "repos.json");
    writeFileSync(file, JSON.stringify({ repositories: { "acme/shop": SHOP.entries } }));
    const remote = fakes();
    await runScan(dir, options({ businessContext: file }), remote.deps);
    expect(ids(remote.out)).toEqual(["checkout-medium", "admin-high", "demo-critical"]);
    const named = fakes();
    await runScan(dir, options({ businessContext: file, repository: "acme/other" }), named.deps);
    expect(ids(named.out)).toEqual(["demo-critical", "admin-high", "checkout-medium"]);
  });

  it("never reads a context file from the scanned repository", async () => {
    const dir = folder();
    mkdirSync(join(dir, ".0"));
    writeFileSync(join(dir, ".0", "business-context.json"), JSON.stringify(SHOP));
    writeFileSync(join(dir, "context.json"), JSON.stringify(SHOP));
    const run = fakes();
    await runScan(dir, options(), run.deps);
    expect(ids(run.out)).toEqual(["demo-critical", "admin-high", "checkout-medium"]);
  });

  it("stops on a bad file before any console or model starts", async () => {
    const dir = folder(); const bad = join(folder(), "bad.json");
    writeFileSync(bad, "{}");
    const run = fakes();
    await runScan(dir, options({ businessContext: bad }), run.deps);
    expect(process.exitCode).toBe(2);
    expect(run.err.join("\n")).toContain("entries");
    expect(run.client.request).not.toHaveBeenCalled();
    expect(run.deps.startConsole).not.toHaveBeenCalled();
  });
});
