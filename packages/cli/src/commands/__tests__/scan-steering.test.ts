import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runScan, type ScanDeps } from "../scan.js";
import { loadPolicies, readRepoContext } from "../../scan-steering.js";

const dirs: string[] = [];
const folder = () => { const dir = mkdtempSync(join(tmpdir(), "steer-test-")); dirs.push(dir); return dir; };
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); process.exitCode = undefined; });

const finished = { session: { id: "t1", status: "ready" }, usage: { costUsd: 0.01 }, messages: [{ role: "assistant", content: [{ type: "text", text: "done" }] }] };
const report = { target: "", scanDepth: "default", startedAt: "", completedAt: "", durationMs: 0, summary: { totalAttacks: 0, totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }, findings: [], warnings: [] };
function fakes() {
  const requests: Array<[string, string, unknown]> = [];
  const err: string[] = [];
  const client = { request: vi.fn(async (method: string, path: string, body?: unknown) => { requests.push([method, path, body]); return method === "GET" ? { snapshot: finished } : { session: { id: "t1" } }; }), dispose: vi.fn() };
  const deps = {
    open: async () => client as never, out: () => {}, err: (text: string) => err.push(text), sleep: async () => {}, now: () => new Date("2026-01-01T00:00:00Z"), writeBytes: vi.fn(),
    loadReport: vi.fn(async () => report as never), startConsole: vi.fn(async () => () => {}), changedFiles: vi.fn(async () => undefined), prePass: vi.fn(async () => undefined), diffFiles: vi.fn(async () => []), clone: vi.fn(),
  } as ScanDeps;
  const prompt = () => (requests.find(([, path]) => path.endsWith("/messages"))![2] as { text: string }).text;
  return { deps, err, prompt };
}
const options = (extra: Record<string, unknown> = {}) => ({ budget: "5", format: "json", timeout: "60", skill: "scan", passes: "1", ...extra }) as never;
const write = (path: string, text: string) => { mkdirSync(join(path, ".."), { recursive: true }); writeFileSync(path, text); };

describe("scan --context / --policy / --org-policy / --repo-context", () => {
  it("reads nothing from the scanned repository by default", async () => {
    const dir = folder();
    write(join(dir, ".0", "threat-model.md"), "UNTRUSTED-REPO-RULES");
    const { deps, prompt, err } = fakes();
    await runScan(dir, options(), deps);
    expect(prompt()).not.toContain("UNTRUSTED-REPO-RULES");
    expect(prompt()).not.toContain("steering-context>\n");
    expect(err.join("\n")).not.toContain("--repo-context");
  });

  it("passes --context files as delimited steering context", async () => {
    const dir = folder(); const file = join(folder(), "model.md");
    writeFileSync(file, "Only admins may create admins.");
    const { deps, prompt } = fakes();
    await runScan(dir, options({ context: [file] }), deps);
    expect(prompt()).toContain("--- file: model.md ---\nOnly admins may create admins.");
    expect(prompt()).toContain("`scan` skill");
  });

  it("--repo-context reads the folder's threat model and warns, naming the base-branch advice", async () => {
    const dir = folder();
    write(join(dir, ".0", "threat-model.md"), "REPO-RULES");
    const { deps, prompt, err } = fakes();
    await runScan(dir, options({ repoContext: true }), deps);
    expect(prompt()).toContain("REPO-RULES");
    expect(err.join("\n")).toMatch(/warning: --repo-context .*base branch/);
  });

  it("--repo-context ignores a threat-model file that is a link out of the folder", () => {
    const dir = folder(); const outside = join(folder(), "secret.md");
    writeFileSync(outside, "SECRET");
    mkdirSync(join(dir, ".0"));
    symlinkSync(outside, join(dir, ".0", "threat-model.md"));
    expect(readRepoContext(dir)).toBeUndefined();
  });

  it("--policy and --org-policy switch to the policy-check skill, org first", async () => {
    const dir = folder(); const repoPolicies = folder(); const orgPolicies = folder();
    write(join(repoPolicies, "a.md"), "---\nid: same\ntitle: Repo\n---\nrepo rule");
    write(join(repoPolicies, "b.md"), "---\nid: only-repo\n---\nb rule");
    write(join(orgPolicies, "o.md"), "---\nid: same\ntitle: Org\nseverity: high\n---\norg rule");
    const { deps, prompt, err } = fakes();
    await runScan(dir, options({ policy: [repoPolicies], orgPolicy: [orgPolicies] }), deps);
    const text = prompt();
    expect(text).toContain("`policy-check` skill");
    expect(text).toMatch(/source "org" .* win/);
    expect(text).toContain("org rule");
    expect(text).not.toContain("repo rule");
    expect(text.indexOf('"id": "same"')).toBeLessThan(text.indexOf('"id": "only-repo"'));
    expect(err.join("\n")).toMatch(/policy 'same' in a.md is set aside/);
  });

  it("refuses --policy together with another skill, and a missing path", async () => {
    const dir = folder(); const policies = folder();
    write(join(policies, "a.md"), "rule");
    const first = fakes();
    await runScan(dir, options({ policy: [policies], skill: "crypto-migration" }), first.deps);
    expect(first.err.join("\n")).toMatch(/--policy and --org-policy run the policy-check skill/);
    expect(process.exitCode).toBe(2);
    const second = fakes();
    await runScan(dir, options({ context: ["/no/such/file.md"] }), second.deps);
    expect(second.err.join("\n")).toMatch(/--context .* is not a file/);
  });
});

describe("loadPolicies", () => {
  it("reads a folder recursively in sorted order, skips README and dotted folders and non-markdown files", () => {
    const dir = folder();
    write(join(dir, "b.md"), "b"); write(join(dir, "a.md"), "a"); write(join(dir, "README.md"), "readme"); write(join(dir, "sub", "c.md"), "c"); write(join(dir, ".hidden", "d.md"), "d"); write(join(dir, "e.txt"), "e");
    expect(loadPolicies([dir], "org").policies.map(policy => policy.id)).toEqual(["a", "b", "c"]);
  });
  it("rejects a folder with no policies", () => expect(() => loadPolicies([folder()], "policy")).toThrow(/no .md policy files/));
});

describe("scan --business-context", () => {
  it("uses only the explicit JSON file, labels declarations in the prompt and saves context separately", async () => {
    const dir = folder(), contextPath = join(folder(), "context.json");
    write(join(dir, ".0", "business-context.json"), "UNTRUSTED-REPOSITORY-CONTEXT");
    writeFileSync(contextPath, JSON.stringify({ entries: [{ match: "src/**", tags: ["payments"], note: "operator note" }] }));
    const { deps, prompt } = fakes();
    const save = vi.fn(); deps.saveBusinessContext = save;
    deps.loadReport = vi.fn(async () => ({ ...report, findings: [{ id: "f1", templateId: "t", title: "x", description: "d", severity: "medium", category: "xss", status: "discovered", evidence: { request: "r", response: "s" }, timestamp: 1, reviewAnnotation: { path: "src/A.java", startLine: 1 } }] } as never));
    await runScan(dir, options({ businessContext: contextPath }), deps);
    expect(prompt()).toContain("Operator-supplied business context, not verified facts");
    expect(prompt()).toContain("operator note");
    expect(prompt()).not.toContain("UNTRUSTED-REPOSITORY-CONTEXT");
    expect(save).toHaveBeenCalledWith([expect.objectContaining({ id: "f1", context: expect.objectContaining({ provenance: "operator", shift: 1 }) })], undefined);
  });
  it("rejects invalid declarations before connecting to a model or writing persisted labels", async () => {
    const dir = folder(), contextPath = join(folder(), "context.json");
    writeFileSync(contextPath, JSON.stringify({ entries: [{ tags: ["verified-exposed"] }] }));
    const { deps } = fakes();
    const open = vi.fn(deps.open); deps.open = open;
    const save = vi.fn(); deps.saveBusinessContext = save;
    await runScan(dir, options({ businessContext: contextPath }), deps);
    expect(open).not.toHaveBeenCalled();
    expect(save).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(2);
  });
});
