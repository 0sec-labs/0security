import { describe, expect, it } from "vitest";
import { runBurndown, selectCandidates, renderReport, type BurndownDeps, type BurndownOptions, type BurndownState, type Candidate } from "../burndown.js";
import type { FixOptions, FixOutcome } from "../fix.js";

const candidate = (n: number, extra: Partial<Candidate> = {}): Candidate => ({ id: `f-${n}`, fingerprint: `fp-${n}`, title: `Finding ${n}`, severity: "high", category: "xss", tool: "foxguard", scanId: "scan-1", status: "discovered", triage: "new", timestamp: n, ...extra });
const options = (extra: Partial<BurndownOptions> = {}): BurndownOptions => ({ pr: true, timeout: "60", concurrency: "1", budget: "10", perFix: "3", maxConsecutiveFailures: "3", maxFailureRate: "0.5", ...extra });
const pr = (id: string, extra: Partial<FixOutcome> = {}): FixOutcome => ({ finding: id, branch: `0/fix-${id}`, changed: true, committed: true, checks: [], verified: true, costUsd: 0.5, pullRequest: { url: `https://example.test/pull/${id}`, created: true, draft: false }, ...extra });
const none = (id: string): FixOutcome => ({ finding: id, branch: `0/fix-${id}`, changed: false, committed: false, checks: [], verified: false, costUsd: 0.1 });

function harness(candidates: Candidate[], fix: (id: string, o: FixOptions) => Promise<FixOutcome | undefined> = async id => pr(id), initial?: BurndownState) {
  let state: BurndownState = initial ?? { version: 1, findings: {}, runs: [] };
  const calls: Array<[string, FixOptions]> = [];
  let clock = 1_000_000;
  const deps: BurndownDeps = {
    listCandidates: () => candidates, repoRoot: async () => "/repo",
    fix: async (id, o) => { calls.push([id, o]); return fix(id, o); },
    store: { load: () => structuredClone(state), save: s => { state = structuredClone(s); } },
    now: () => (clock += 1000), err: () => {},
  };
  return { deps, calls, state: () => state };
}

describe("0 findings burndown", () => {
  it("selects open findings by filters, worst first, and drops fixed, false-positive, accepted and suppressed ones", () => {
    const all = [candidate(1, { severity: "low" }), candidate(2, { severity: "critical", tool: "semgrep" }), candidate(3, { status: "fixed" }), candidate(4, { status: "false-positive" }), candidate(5, { triage: "accepted" }), candidate(6, { triage: "suppressed" }), candidate(7)];
    expect(selectCandidates(all, {}).map(c => c.id)).toEqual(["f-2", "f-7", "f-1"]);
    expect(selectCandidates(all, { severity: "high,low" }).map(c => c.id)).toEqual(["f-7", "f-1"]);
    expect(selectCandidates(all, { tool: "SEMGREP" }).map(c => c.id)).toEqual(["f-2"]);
    expect(selectCandidates(all, { source: "semgrep" }).map(c => c.id)).toEqual(["f-2"]);
    expect(selectCandidates(all, { fingerprint: "fp-7" }).map(c => c.id)).toEqual(["f-7"]);
    expect(selectCandidates(all, { category: "sqli" })).toEqual([]);
    expect(() => selectCandidates(all, { severity: "bad" })).toThrow(/--severity/);
  });

  it("fixes each finding with a per-fix cap, records the outcome and reports pull requests", async () => {
    const h = harness([candidate(1), candidate(2)]);
    const report = await runBurndown(options({ test: ["pnpm test"] }), h.deps);
    expect(h.calls.map(([id]) => id)).toEqual(["f-1", "f-2"]);
    expect(h.calls[0]![1]).toMatchObject({ repo: "/repo", budget: "3", pr: true, test: ["pnpm test"] });
    expect(report).toMatchObject({ selected: 2, attempted: 2, costUsd: 1, totals: { proposed: 2, prsOpened: 2, checksPassing: 2, failed: 0, skipped: 0 } });
    expect(report.items[0]).toMatchObject({ result: "pr-opened", pullRequestUrl: "https://example.test/pull/f-1" });
    expect(h.state().runs).toHaveLength(1);
    expect(h.state().runs[0]).toMatchObject({ attempted: 2, proposed: 2, ciResult: "passing", costUsd: 1, tokens: null });
    expect(renderReport(report)).toContain("pull requests opened 2");
  });

  it("is idempotent: a second run skips findings that have a pull request and retries the ones that made no change", async () => {
    const h = harness([candidate(1), candidate(2)], async id => (id === "f-2" ? none(id) : pr(id)));
    await runBurndown(options({ maxConsecutiveFailures: "5" }), h.deps);
    h.calls.length = 0;
    const second = await runBurndown(options(), h.deps);
    expect(h.calls.map(([id]) => id)).toEqual(["f-2"]);
    expect(second.items[0]).toMatchObject({ result: "skipped", reason: expect.stringContaining("pull request is already open") });
    expect(h.state().runs).toHaveLength(2);
  });

  it("continues in batches with --limit", async () => {
    const h = harness([1, 2, 3].map(n => candidate(n)));
    const first = await runBurndown(options({ limit: "2" }), h.deps);
    expect(first.attempted).toBe(2);
    expect(first.items[2]).toMatchObject({ result: "skipped", reason: expect.stringContaining("--limit") });
    h.calls.length = 0;
    await runBurndown(options({ limit: "2" }), h.deps);
    expect(h.calls.map(([id]) => id)).toEqual(["f-3"]);
  });

  it("with --no-pr skips committed work, and picks it up again once pull requests are on", async () => {
    const h = harness([candidate(1)], async id => pr(id, { pullRequest: undefined }));
    await runBurndown(options({ pr: false }), h.deps);
    expect(h.state().findings[Object.keys(h.state().findings)[0]!]).toMatchObject({ result: "committed" });
    h.calls.length = 0;
    expect((await runBurndown(options({ pr: false }), h.deps)).items[0]).toMatchObject({ result: "skipped", reason: expect.stringContaining("already committed") });
    await runBurndown(options({ pr: true }), h.deps);
    expect(h.calls).toHaveLength(1);
  });

  it("stops after consecutive failures and says which findings were not attempted", async () => {
    const h = harness([1, 2, 3, 4, 5].map(n => candidate(n)), async id => none(id));
    const report = await runBurndown(options({ maxConsecutiveFailures: "2" }), h.deps);
    expect(h.calls).toHaveLength(2);
    expect(report.stoppedReason).toBe("2 fixes failed in a row");
    expect(report.items[4]).toMatchObject({ result: "skipped", reason: expect.stringContaining("not attempted") });
  });

  it("stops when the failure share is above the threshold after the minimum attempts", async () => {
    const h = harness([1, 2, 3, 4, 5, 6].map(n => candidate(n)), async id => (["f-1", "f-4"].includes(id) ? pr(id) : none(id)));
    const report = await runBurndown(options({ maxConsecutiveFailures: "9", minAttempts: "4", maxFailureRate: "0.4" }), h.deps);
    expect(h.calls).toHaveLength(4);
    expect(report.stoppedReason).toContain("failure share 50%");
  });

  it("counts a draft with a failed check as a failure and reports it", async () => {
    const h = harness([candidate(1)], async id => pr(id, { verified: false, pullRequest: { url: "u", created: true, draft: true } }));
    const report = await runBurndown(options({ maxConsecutiveFailures: "1" }), h.deps);
    expect(report.totals).toMatchObject({ drafts: 1, checksPassing: 0, prsOpened: 1 });
    expect(report.stoppedReason).toBeDefined();
    expect(h.state().runs[0]!.ciResult).toBe("failing");
  });

  it("treats a thrown fix as a failed item and carries on", async () => {
    const h = harness([candidate(1), candidate(2)], async id => { if (id === "f-1") throw new Error("boom"); return pr(id); });
    const report = await runBurndown(options(), h.deps);
    expect(report.items[0]).toMatchObject({ result: "failed", reason: "boom" });
    expect(report.items[1]!.result).toBe("pr-opened");
  });

  it("splits the total budget: the cap shrinks to what is left and no fix starts once it is spent", async () => {
    const h = harness([1, 2, 3, 4].map(n => candidate(n)), async id => pr(id, { costUsd: 2 }));
    const report = await runBurndown(options({ budget: "4", perFix: "3" }), h.deps);
    expect(h.calls.map(([, o]) => o.budget)).toEqual(["3", "2"]);
    expect(report.attempted).toBe(2);
    expect(report.stoppedReason).toBe("the total budget is spent");
    expect(report.costUsd).toBe(4);
  });

  it("runs fixes concurrently up to the limit and never reserves more than the budget", async () => {
    let running = 0, peak = 0;
    const h = harness([1, 2, 3, 4, 5, 6].map(n => candidate(n)), async id => { running++; peak = Math.max(peak, running); await new Promise(r => setTimeout(r, 5)); running--; return pr(id); });
    await runBurndown(options({ concurrency: "3", budget: "9" }), h.deps);
    expect(peak).toBe(3);
    const budgets = h.calls.map(([, o]) => Number(o.budget));
    expect(budgets.every(b => b <= 3)).toBe(true);
    const tight = harness([1, 2, 3].map(n => candidate(n)), async id => pr(id, { costUsd: 0.1 }));
    const report = await runBurndown(options({ concurrency: "4", budget: "4", perFix: "3" }), tight.deps);
    expect(tight.calls.slice(0, 2).map(([, o]) => o.budget)).toEqual(["3", "1"]);
    expect(report.attempted).toBe(3);
  });

  it("changes nothing on a dry run", async () => {
    const h = harness([candidate(1)]);
    const report = await runBurndown(options({ dryRun: true }), h.deps);
    expect(h.calls).toHaveLength(0);
    expect(report.items[0]).toMatchObject({ result: "planned" });
    expect(h.state().runs).toHaveLength(0);
  });

  it("rejects bad numbers and remote engines", async () => {
    const h = harness([]);
    await expect(runBurndown(options({ concurrency: "5" }), h.deps)).rejects.toThrow(/--concurrency/);
    await expect(runBurndown(options({ budget: "0" }), h.deps)).rejects.toThrow(/--budget/);
    await expect(runBurndown(options({ computer: "c1" }), h.deps)).rejects.toThrow(/local console/);
  });
});
