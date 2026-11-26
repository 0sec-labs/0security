import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import { metricPullRequest, metricRepositoryFromOrigin } from "./metric-pr.js";
import { appendHostObservation, readHostObservations, refreshMetricHostReceipts, summarizeHostReceipts, type MetricHostObservation } from "./metric-host-receipts.js";
import { appendRunMetric, groupMetrics, metricsPath, readRunMetrics, sanitizeMetric } from "./run-metrics.js";
import { BitbucketHost } from "./host/bitbucket.js";
import type { Host } from "./host/index.js";

const dirs: string[] = [];
const home = () => { const h = mkdtempSync(join(tmpdir(), "0-host-receipts-")); dirs.push(h); return h; };
afterEach(() => { vi.useRealTimers(); for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
const url = "https://github.com/o/r/pull/7";
const row = (extra: Record<string, unknown> = {}) => sanitizeMetric({ at: "2026-11-25T00:00:00Z", command: "fix", model: "m", costUsd: .1, findingsProposed: 1, pullRequestUrl: url, sentinelId: "s-1", ...extra })!;
const observation = (extra: Partial<MetricHostObservation> = {}): MetricHostObservation => ({ version: 1, checkedAt: "2026-11-26T00:00:00Z", ...metricPullRequest(url)!, state: "merged", ci: "passing", ...extra });

describe("actual PR metrics association", () => {
  it("rejects secrets, arbitrary links and local paths, and pins repository identity across clone URL forms", () => {
    expect(metricPullRequest("https://user:secret@github.com/o/r/pull/1")).toBeUndefined();
    expect(metricPullRequest(`${url}?token=secret`)).toBeUndefined(); expect(metricPullRequest("/private/repo")).toBeUndefined();
    expect(metricPullRequest("https://example.test/a")).toBeUndefined();
    expect(metricPullRequest("https://github.com:8443/o/r/pull/1")).toBeUndefined();
    expect(metricRepositoryFromOrigin("file://github.com/o/r.git")).toBeUndefined();
    expect(metricRepositoryFromOrigin("https://github.com:8443/o/r.git")).toBeUndefined();
    expect(metricRepositoryFromOrigin("git@github.com:o/r.git")).toBe(metricPullRequest(url)!.repositoryId);
    expect(metricRepositoryFromOrigin("https://bitbucket.org/o/r.git")).toBe(metricPullRequest("https://bitbucket.org/o/r/pull-requests/1")!.repositoryId);
    expect(metricRepositoryFromOrigin("ssh://git@bb.example:7999/KEY/repo.git", "https://bb.example/context")).toBe(metricPullRequest("https://bb.example/context/projects/KEY/repos/repo/pull-requests/1")!.repositoryId);
  });
  it("stores observations separately without rewriting immutable usage or keeping checkout paths", async () => {
    const h = home(); appendRunMetric(row(), h); const before = readFileSync(metricsPath(h), "utf8");
    const records = readRunMetrics(h); const requests: string[] = [];
    const result = await refreshMetricHostReceipts(records, "/explicit/private/checkout", {}, {
      origin: async () => "https://github.com/o/r.git", now: () => Date.parse("2026-11-26T00:00:00Z"),
      host: async () => ({ pullRequestState: async (value: string) => { requests.push(value); return { state: "merged", draft: false, commits: 1 }; }, pullRequestChecks: async () => ({ status: "passing" }) }) as Pick<Host, "pullRequestState" | "pullRequestChecks">,
      append: record => appendHostObservation(record, h),
    });
    expect(result).toEqual({ checked: 1, remaining: 0, unavailable: 0 }); expect(requests).toEqual([url]);
    expect(readFileSync(metricsPath(h), "utf8")).toBe(before);
    expect(JSON.stringify(readHostObservations(h))).not.toMatch(/private|checkout|secret/);
    expect(summarizeHostReceipts(records, readHostObservations(h))).toMatchObject({ pullRequests: 1, merged: 1, ciPassing: 1, shareMerged: 1 });
  });
  it("deduplicates repeated PR updates per workflow and applies grouping and since filters before receipt joins", () => {
    const rows = [row(), row({ at: "2026-11-26T00:00:00Z" }), row({ sentinelId: "s-2", pullRequestUrl: "https://github.com/o/r/pull/8" }), row({ sentinelId: "s-1", at: "2026-01-01T00:00:00Z", pullRequestUrl: "https://github.com/o/r/pull/9" })];
    const receipts = [observation(), observation({ ...metricPullRequest("https://github.com/o/r/pull/8")!, state: "closed", ci: "failing" }), observation({ ...metricPullRequest("https://github.com/o/r/pull/9")!, state: "closed" })];
    const grouped = groupMetrics(rows, "sentinel", { since: Date.parse("2026-11-01") }, receipts);
    expect(grouped[0]!.host).toMatchObject({ pullRequests: 1, merged: 1, closed: 0, shareMerged: 1 });
    expect(grouped[1]!.host).toMatchObject({ pullRequests: 1, merged: 0, closed: 1, shareMerged: 0, ciFailing: 1 });
  });
  it("uses the latest explicit observation, keeping unavailable credentials unknown rather than rejected", async () => {
    const records = [row()]; const appended: MetricHostObservation[] = [];
    await refreshMetricHostReceipts(records, "/checkout", {}, { origin: async () => "https://github.com/o/r.git", host: async () => { throw new Error("missing credentials"); }, append: value => appended.push(value), now: () => Date.parse("2026-11-27") });
    expect(summarizeHostReceipts(records, [observation(), ...appended])).toMatchObject({ unknown: 1, merged: 0, closed: 0, ciUnknown: 1, shareMerged: null });
  });
  it("does not contact a different repository and bounds one refresh to 20 distinct PRs", async () => {
    const records = Array.from({ length: 25 }, (_, i) => row({ pullRequestUrl: `https://github.com/o/r/pull/${i + 1}` }));
    records.push(row({ pullRequestUrl: "https://github.com/other/repo/pull/1" }));
    const state = vi.fn(async () => ({ state: "open", draft: true, commits: 1 }));
    const append = vi.fn();
    const result = await refreshMetricHostReceipts(records, "/checkout", {}, { origin: async () => "https://github.com/o/r.git", host: async () => ({ pullRequestState: state }) as Pick<Host, "pullRequestState" | "pullRequestChecks">, append, now: Date.now });
    expect(result).toMatchObject({ checked: 20, remaining: 5 }); expect(state).toHaveBeenCalledTimes(20);
    expect(state.mock.calls.flat().join(" ")).not.toContain("other/repo"); expect(append).toHaveBeenCalledTimes(20);
  });
  it("prioritizes unobserved PRs so repeated bounded refreshes reach the whole repository", async () => {
    const records = Array.from({ length: 25 }, (_, i) => row({ pullRequestUrl: `https://github.com/o/r/pull/${i + 1}` }));
    const seen: string[] = [];
    await refreshMetricHostReceipts(records, "/checkout", {}, {
      origin: async () => "https://github.com/o/r.git", now: Date.now, append: () => {},
      observations: () => records.slice(0, 20).map(record => observation({ pullRequestUrl: record.pullRequestUrl! })),
      host: async () => ({ pullRequestState: async (value: string) => { seen.push(value); return { state: "open", draft: true, commits: 1 }; } }) as Pick<Host, "pullRequestState" | "pullRequestChecks">,
    });
    expect(seen.slice(0, 5)).toEqual(expect.arrayContaining(records.slice(20).map(record => record.pullRequestUrl)));
  });
  it("terminates a stalled host read at the explicit total deadline without recording success", async () => {
    vi.useFakeTimers(); const appended: MetricHostObservation[] = [];
    const work = refreshMetricHostReceipts([row()], "/checkout", {}, { origin: async () => "https://github.com/o/r.git", host: async () => ({ pullRequestState: () => new Promise(() => {}) }) as Pick<Host, "pullRequestState" | "pullRequestChecks">, append: value => appended.push(value), now: Date.now });
    await vi.advanceTimersByTimeAsync(60_000); await work;
    expect(appended[0]).toMatchObject({ state: "unknown", ci: "unknown" });
  });
  it("reads actual Data Center lifecycle and build receipts from a local HTTP host using GET only", async () => {
    const methods: string[] = []; const sha = "a".repeat(40);
    const server = createServer((req, res) => {
      methods.push(req.method!); res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify(req.url?.includes("/builds") ? { values: [{ state: "SUCCESSFUL" }], isLastPage: true } : req.url?.includes("/commits") ? { values: [{ id: sha }], isLastPage: true } : { state: "MERGED", draft: false, fromRef: { latestCommit: sha } }));
    });
    await new Promise<void>(done => server.listen(0, "127.0.0.1", done));
    try {
      const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`; const pr = `${base}/projects/KEY/repos/repo/pull-requests/1`;
      const receipts: MetricHostObservation[] = [];
      await refreshMetricHostReceipts([row({ pullRequestUrl: pr })], "/checkout", { bitbucketUrl: base }, {
        origin: async () => `${base}/scm/KEY/repo.git`, now: Date.now, append: value => receipts.push(value),
        host: async (_checkout, signal) => new BitbucketHost({ platform: "bitbucket-dc", owner: "KEY", repo: "repo", token: "fixture-only", baseUrl: base, git: async () => "", fetch: (input, init) => fetch(input, { ...init, signal }) }),
      });
      expect(receipts[0]).toMatchObject({ state: "merged", ci: "passing" }); expect(methods.every(method => method === "GET")).toBe(true);
    } finally { await new Promise<void>((done, reject) => server.close(error => error ? reject(error) : done())); }
  });
});
