// Sending Sentinel results to GitHub code scanning, and the open pull request poll at scale, tested with a fake gh. Nothing here reaches GitHub.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SecurityWorkflowStore, SentinelStore } from "@0/engine/storage";
import { createSecurityWorkflowTemplate } from "@0/engine/shared";
import { WebSentinelService } from "./sentinels.js";
import type { SentinelSessionEvent } from "./sentinel-runner.js";
import { checkEvent } from "./sentinel-github-events.js";
import { MAX_SARIF_RESULTS, buildSentinelSarif, neutralise } from "./sentinel-github-results.js";

const T0 = Date.parse("2026-03-02T10:00:00Z");
const MIN = 60_000;
const dirs: string[] = [];
const P = "/api/console/sentinels";
const SHA = "e".repeat(40);

type Gh = (args: string[]) => string | undefined;
interface Call { args: string[]; input?: string }

function fixture(gh: Gh | undefined, calls: Call[]) {
  const dir = mkdtempSync(join(tmpdir(), "zero-sentinel-results-"));
  dirs.push(dir);
  const dbPath = join(dir, "control.db");
  let counter = 0;
  const listeners = new Map<string, Set<(event: SentinelSessionEvent) => void>>();
  const emit = (id: string, event: SentinelSessionEvent) => { for (const listener of [...(listeners.get(id) ?? [])]) listener(event); };
  const missions = {
    create: vi.fn((_input: Record<string, unknown>) => ({ id: `mission-${++counter}` })),
    send: vi.fn(async (id: string, text: string) => { emit(id, { type: "user", text }); return {}; }),
    pendingDecisions: vi.fn((_id: string) => 0),
    subscribe: vi.fn((id: string, listener: (event: SentinelSessionEvent) => void) => { const set = listeners.get(id) ?? new Set(); set.add(listener); listeners.set(id, set); return () => set.delete(listener); }),
    cancel: vi.fn(async (_id: string) => ({})),
    usage: vi.fn((_id: string) => ({ costUsd: 0 })),
    exists: vi.fn((_id: string) => true),
    findings: vi.fn((_id: string): unknown[] => []),
  };
  const run = async (args: string[], input?: string) => {
    calls.push({ args, ...(input !== undefined ? { input } : {}) });
    const out = gh!(args);
    if (out === "THROW") throw new Error("gh: HTTP 403");
    return { stdout: out ?? "" };
  };
  const service = new WebSentinelService({ dbPath, missions: missions as never, executionProfile: () => "local", checkout: async () => undefined, persistentThread: () => false, ...(gh ? { gh: { run } } : {}) });
  const workflows = new SecurityWorkflowStore(dbPath);
  const store = new SentinelStore(dbPath);
  const call = async (method: string, path: string, body?: unknown) => {
    const url = new URL(`http://localhost${path}`);
    return (await service.handle(url.pathname, method, body, url.searchParams))!;
  };
  async function armed(kind: "github-pr" | "release" | "check-completed", config: Record<string, unknown>) {
    const created = (await call("POST", P, { name: "Scan Watch", skills: ["pr-diff-review"] })).data as { sentinel: { id: string } };
    const id = created.sentinel.id;
    await call("POST", `${P}/${id}/resume`, { acknowledge: true });
    const automation = workflows.save({ ...createSecurityWorkflowTemplate("dependency-review", { target: "." }), ownerSentinelId: id });
    const key = kind === "github-pr" ? "github" : kind === "release" ? "release" : "check";
    const trigger = await call("POST", `${P}/${id}/triggers`, { automationId: automation.id, kind, [key]: { repo: "acme/app", pollMs: 60_000, ...config }, enabled: true, approval: "enable-reviewed-trigger" });
    expect(trigger.status).toBe(201);
    return { id, triggerId: (trigger.data as { trigger: { id: string } }).trigger.id };
  }
  const activations = async (id: string) => ((await call("GET", `${P}/${id}/activations`)).data as { activations: Array<Record<string, any>> }).activations;
  const poll = async (minutes: number) => { vi.setSystemTime(T0 + minutes * MIN); await service.tick(); };
  const finish = async (id: string, index = 0) => {
    const found = (await activations(id))[index]!;
    emit(found.missionId, { type: "turn-complete", stopReason: "end_turn" });
    await vi.advanceTimersByTimeAsync(10);
  };
  return { service, missions, store, call, armed, activations, poll, finish };
}

beforeEach(() => { vi.useFakeTimers({ now: T0 }); vi.stubEnv("ZERO_PR_COMMENT_MIN_GAP_MS", "0"); });
afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

const pr = (number: number, sha = SHA, extra: Record<string, unknown> = {}) => ({ number, headRefOid: sha, title: `PR ${number}`, url: `https://github.com/acme/app/pull/${number}`, baseRefName: "main", headRefName: `b${number}`, isCrossRepository: false, isDraft: false, state: "OPEN", ...extra });
const finding = (extra: Record<string, unknown> = {}) => ({ id: "f1", templateId: "sql-injection", title: "SQL injection @everyone [x](https://evil.example) #123 <img src=x>", severity: "high", category: "injection", status: "open", description: "SECRET-DESCRIPTION", location: { path: "src/db.ts", startLine: 12 }, ...extra });
const sarifUploads = (calls: Call[]) => calls.filter(c => c.args.includes("--input") && c.args.some(a => a.endsWith("/code-scanning/sarifs")));
const decode = (call: Call) => {
  const body = JSON.parse(call.input!) as { commit_sha: string; ref: string; sarif: string; tool_name: string };
  return { body, sarif: JSON.parse(gunzipSync(Buffer.from(body.sarif, "base64")).toString("utf8")) as { version: string; runs: Array<{ results: Array<Record<string, any>>; tool: { driver: { name: string } }; automationDetails: { id: string } }> } };
};

describe("SARIF built from a run", () => {
  it("keeps share-safe fields only and neutralises text for GitHub", () => {
    const built = buildSentinelSarif("Scan Watch", [finding(), finding({ id: "f2", title: "No file", location: undefined }), finding({ id: "f3", location: { path: "/Users/me/x.ts", startLine: 1 } }), finding({ id: "f4", location: { path: "../x.ts", startLine: 1 } })] as never);
    expect(built).toMatchObject({ included: 1, skipped: 3 });
    expect(built.text).not.toContain("SECRET-DESCRIPTION");
    expect(built.text).not.toContain("https://evil");
    expect(built.text).not.toContain("<img");
    expect(built.text).not.toContain("@everyone");
    expect(built.text).not.toContain("#123");
    const doc = JSON.parse(built.text);
    expect(doc.version).toBe("2.1.0");
    expect(doc.runs[0].results[0]).toMatchObject({ level: "error", locations: [{ physicalLocation: { artifactLocation: { uri: "src/db.ts" }, region: { startLine: 12 } } }] });
    expect(doc.runs[0].automationDetails.id).toBe("0-sentinel/scan-watch/");
  });

  it("caps the results and keeps the most severe ones", () => {
    const many = Array.from({ length: MAX_SARIF_RESULTS + 50 }, (_, i) => finding({ id: `f${i}`, title: `Item ${i}`, severity: i < 5 ? "critical" : "low", location: { path: `src/f${i}.ts`, startLine: 1 } }));
    const built = buildSentinelSarif("S", many as never);
    expect(built).toMatchObject({ included: MAX_SARIF_RESULTS, skipped: 50 });
    const levels = JSON.parse(built.text).runs[0].results.slice(0, 5).map((r: { level: string }) => r.level);
    expect(levels).toEqual(["error", "error", "error", "error", "error"]);
  });

  it("neutralises mentions, issue references, links and markup", () => {
    expect(neutralise("hi @bob see #12 http://x.example/a <b>`c`</b>", 200)).toBe("hi @​bob see #​12 (link removed) bc/b");
  });
});

describe("pull request trigger results", () => {
  it("uploads nothing by default", async () => {
    let listing = [pr(1)];
    const calls: Call[] = [];
    const f = fixture(args => (args[0] === "pr" && args[1] === "list" ? JSON.stringify(listing) : undefined), calls);
    const { id } = await f.armed("github-pr", {});
    await f.poll(0);
    listing = [pr(1), pr(2)];
    await f.poll(2);
    f.missions.findings.mockReturnValue([finding()]);
    await f.finish(id);
    expect(sarifUploads(calls)).toHaveLength(0);
    expect(calls.some(c => c.args[0] === "pr" && c.args[1] === "comment")).toBe(false);
  });

  it("uploads SARIF with the commit and pull request ref when results is sarif, and posts no comment", async () => {
    let listing = [pr(1)];
    const calls: Call[] = [];
    const f = fixture(args => (args[0] === "pr" && args[1] === "list" ? JSON.stringify(listing) : args.includes("--input") ? JSON.stringify({ id: "77" }) : undefined), calls);
    const { id } = await f.armed("github-pr", { results: "sarif" });
    await f.poll(0);
    listing = [pr(1), pr(2, SHA)];
    await f.poll(2);
    f.missions.findings.mockReturnValue([finding()]);
    await f.finish(id);
    const uploads = sarifUploads(calls);
    expect(uploads).toHaveLength(1);
    expect(uploads[0]!.args).toEqual(["api", "--method", "POST", "repos/acme/app/code-scanning/sarifs", "--input", "-"]);
    const { body, sarif } = decode(uploads[0]!);
    expect(body).toMatchObject({ commit_sha: SHA, ref: "refs/pull/2/head", tool_name: "0security Sentinel" });
    expect(sarif.runs[0]!.results).toHaveLength(1);
    expect(calls.some(c => c.args[0] === "pr" && c.args[1] === "comment")).toBe(false);
    // Nothing from the run or the environment travels in the request: the body is the SARIF document only.
    expect(JSON.stringify(calls)).not.toContain("SECRET-DESCRIPTION");
  });

  it("does both for results both, and the comment is still one comment edited in place", async () => {
    let listing = [pr(1)];
    let existing = "";
    const calls: Call[] = [];
    const f = fixture(args => {
      if (args[0] === "pr" && args[1] === "list") return JSON.stringify(listing);
      if (args[0] === "api" && args[1] === "--paginate" && args[2]!.includes("/issues/2/comments")) return existing;
      if (args[0] === "pr" && args[1] === "comment") { existing = "901"; return ""; }
      if (args.includes("--input")) return JSON.stringify({ id: "5" });
      return undefined;
    }, calls);
    const { id } = await f.armed("github-pr", { results: "both" });
    await f.poll(0);
    listing = [pr(1), pr(2, SHA)];
    await f.poll(2);
    f.missions.findings.mockReturnValue([finding()]);
    await f.finish(id);
    expect(calls.filter(c => c.args[0] === "pr" && c.args[1] === "comment")).toHaveLength(1);
    expect(sarifUploads(calls)).toHaveLength(1);
    const body = calls.find(c => c.args[0] === "pr" && c.args[1] === "comment")!.args.at(-1)!;
    expect(body).not.toContain("@everyone");
    expect(body).not.toContain("https://evil");
    // A later commit edits the comment instead of adding another.
    listing = [pr(1), pr(2, "f".repeat(40))];
    await f.poll(4);
    await f.finish(id, 0);
    expect(calls.filter(c => c.args[0] === "pr" && c.args[1] === "comment")).toHaveLength(1);
    expect(calls.some(c => c.args.includes("PATCH") && c.args.includes("repos/acme/app/issues/comments/901"))).toBe(true);
    expect(sarifUploads(calls)).toHaveLength(2);
  });

  it("skips fork pull requests unless allowed, and never uploads SARIF for an allowed fork", async () => {
    let listing = [pr(1)];
    const calls: Call[] = [];
    const f = fixture(args => (args[0] === "pr" && args[1] === "list" ? JSON.stringify(listing) : args.includes("--input") ? "{}" : undefined), calls);
    const { id } = await f.armed("github-pr", { results: "sarif" });
    await f.poll(0);
    listing = [pr(1), pr(3, SHA, { isCrossRepository: true })];
    await f.poll(2);
    expect(await f.activations(id)).toMatchObject([{ status: "skipped", error: "Skipped: fork pull request." }]);
    expect(sarifUploads(calls)).toHaveLength(0);

    const calls2: Call[] = [];
    const g = fixture(args => (args[0] === "pr" && args[1] === "list" ? JSON.stringify(listing) : args.includes("--input") ? "{}" : undefined), calls2);
    listing = [pr(1)];
    const armedFork = await g.armed("github-pr", { results: "sarif", includeForks: true });
    await g.poll(10);
    listing = [pr(1), pr(3, SHA, { isCrossRepository: true })];
    await g.poll(12);
    g.missions.findings.mockReturnValue([finding()]);
    await g.finish(armedFork.id);
    expect(sarifUploads(calls2)).toHaveLength(0);
  });

  it("shows a failed upload on the run and does not fail the run", async () => {
    let listing = [pr(1)];
    const calls: Call[] = [];
    const f = fixture(args => (args[0] === "pr" && args[1] === "list" ? JSON.stringify(listing) : args.includes("--input") ? "THROW" : undefined), calls);
    const { id } = await f.armed("github-pr", { results: "sarif" });
    await f.poll(0);
    listing = [pr(1), pr(2)];
    await f.poll(2);
    f.missions.findings.mockReturnValue([finding()]);
    await f.finish(id);
    const [run] = await f.activations(id);
    expect(run).toMatchObject({ status: "completed" });
    expect(String(run!.error)).toContain("The code scanning upload failed");
  });

  it("blocks every gh call under ZERO_ENTERPRISE", async () => {
    vi.stubEnv("ZERO_ENTERPRISE", "1");
    const f = fixture(undefined, []);
    const { triggerId } = await f.armed("github-pr", { results: "sarif" });
    await f.poll(0);
    const trigger = f.store.getTrigger(triggerId)!;
    expect(trigger.lastStatus).toBe("blocked");
    expect(String(trigger.lastError)).toMatch(/ZERO_ENTERPRISE|enterprise/i);
  });
});

describe("release trigger results", () => {
  it("resolves the tag to a commit and uploads under the tag ref", async () => {
    let listing = JSON.stringify({ tag_name: "v1.0.0", draft: false });
    const calls: Call[] = [];
    const f = fixture(args => {
      if (args[1]?.includes("/releases")) return listing;
      if (args[1] === "repos/acme/app/commits/v1.1.0") return `${SHA}\n`;
      if (args.includes("--input")) return JSON.stringify({ id: "9" });
      return undefined;
    }, calls);
    const { id } = await f.armed("release", { results: "sarif" });
    await f.poll(0);
    listing = [JSON.stringify({ tag_name: "v1.0.0", draft: false }), JSON.stringify({ tag_name: "v1.1.0", draft: false })].join("\n");
    await f.poll(2);
    f.missions.findings.mockReturnValue([finding()]);
    await f.finish(id);
    const uploads = sarifUploads(calls);
    expect(uploads).toHaveLength(1);
    expect(decode(uploads[0]!).body).toMatchObject({ commit_sha: SHA, ref: "refs/tags/v1.1.0" });
    expect(calls.some(c => c.args.some(a => a.includes("/statuses/")))).toBe(false);
  });
});

describe("check trigger results", () => {
  const check = (id: number) => JSON.stringify({ id, name: "build", status: "completed", conclusion: "failure", head_sha: SHA, pr: null });
  it("uploads a polled check under its branch ref", async () => {
    let listing = check(1);
    const calls: Call[] = [];
    const f = fixture(args => (args[1] === "repos/acme/app" ? "main" : args.includes("--input") ? "{}" : args[1] === "--paginate" ? listing : undefined), calls);
    const { id } = await f.armed("check-completed", { results: "sarif" });
    await f.poll(0);
    listing = [check(1), check(2)].join("\n");
    await f.poll(2);
    f.missions.findings.mockReturnValue([finding()]);
    await f.finish(id);
    const uploads = sarifUploads(calls);
    expect(uploads).toHaveLength(1);
    expect(decode(uploads[0]!).body).toMatchObject({ commit_sha: SHA, ref: "refs/heads/main" });
  });

  it("never uploads a check that arrived by webhook, because it can belong to a fork pull request", async () => {
    const calls: Call[] = [];
    const f = fixture(() => "{}", calls);
    const { id, triggerId } = await f.armed("check-completed", { results: "sarif", branch: "main" });
    const event = checkEvent({ repo: "acme/app", id: 5, name: "build", conclusion: "failure", sha: SHA, branch: "main", pr: 7 })!;
    expect(await f.service.deliverWebhookEvent(triggerId, event)).toBe(true);
    f.missions.findings.mockReturnValue([finding()]);
    await f.finish(id);
    expect(sarifUploads(calls)).toHaveLength(0);
  });
});

describe("open pull request poll at scale", () => {
  /** Behaves like `gh pr list --limit N`: the newest N, with no sign that more exist. */
  const listOf = (total: number) => (args: string[]) => {
    if (args[0] !== "pr" || args[1] !== "list") return undefined;
    const limit = Number(args[args.indexOf("--limit") + 1]);
    return JSON.stringify(Array.from({ length: Math.min(total, limit) }, (_, i) => pr(total - i, `${(total - i).toString(16).padStart(40, "a")}`)));
  };

  it("reads more than 50 open pull requests and reviews only a new one", async () => {
    let total = 60;
    const calls: Call[] = [];
    const f = fixture(args => listOf(total)(args), calls);
    const { id, triggerId } = await f.armed("github-pr", {});
    await f.poll(0);
    expect(f.store.getTrigger(triggerId)).toMatchObject({ lastStatus: "baseline" });
    expect(Object.keys(f.store.getTrigger(triggerId)!.cursor!)).toHaveLength(60);
    expect(calls[0]!.args).toContain("--limit");
    expect(calls[0]!.args[calls[0]!.args.indexOf("--limit") + 1]).toBe("1000");
    total = 61;
    await f.poll(2);
    const runs = await f.activations(id);
    expect(runs).toHaveLength(1);
    expect(runs[0]).toMatchObject({ trigger: { event: { pr: 61 } } });
  });

  it("keeps a cursor for 500 open pull requests and reviews only the new one", async () => {
    let total = 500;
    const f = fixture(args => listOf(total)(args), []);
    const { id, triggerId } = await f.armed("github-pr", {});
    await f.poll(0);
    expect(f.store.getTrigger(triggerId)).toMatchObject({ lastStatus: "baseline" });
    expect(f.store.getTrigger(triggerId)!.lastError).toBeUndefined();
    expect(Object.keys(f.store.getTrigger(triggerId)!.cursor!)).toHaveLength(500);
    total = 501;
    await f.poll(2);
    expect((await f.activations(id)).map(run => run.trigger.event.pr)).toEqual([501]);
  });

  it("reads the newest 1,000 of 1,500 open pull requests, reports the cut, and never re-reviews older ones", async () => {
    let total = 1500;
    const f = fixture(args => listOf(total)(args), []);
    const { id, triggerId } = await f.armed("github-pr", {});
    await f.poll(0);
    let trigger = f.store.getTrigger(triggerId)!;
    expect(trigger.lastStatus).toBe("baseline");
    expect(trigger.lastError).toMatch(/newest 1,000 open pull requests; older ones are not reviewed/);
    expect(Object.keys(trigger.cursor!)).toHaveLength(1000);
    // Nothing changed: nothing is reviewed, and the report stays.
    await f.poll(2);
    expect(await f.activations(id)).toHaveLength(0);
    expect(f.store.getTrigger(triggerId)!.lastError).toMatch(/newest 1,000/);
    // A new pull request is reviewed once.
    total = 1501;
    await f.poll(4);
    expect((await f.activations(id)).map(run => run.trigger.event.pr)).toEqual([1501]);
    trigger = f.store.getTrigger(triggerId)!;
    expect(Object.keys(trigger.cursor!)).toHaveLength(1001);
  });
});
