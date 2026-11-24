import { describe, expect, it } from "vitest";
import { buildFixReport, renderFixReportMarkdown, runExportFixes, type ExportFixesDeps } from "../findings-export-fixes.js";
import { recordStandaloneFix, type BurndownState } from "../burndown.js";
import type { Host, PullRequestState } from "../../host/index.js";

const key = (repo: string, fp: string) => `${repo}\u0000${fp}`;
const state: BurndownState = {
  version: 1, runs: [],
  findings: {
    [key("/repo", "fp-a")]: { finding: "f-aaaaaaaaaaaa", branch: "0/fix-aaa", result: "pr-opened", pullRequestUrl: "https://github.com/o/r/pull/1", draft: false, checksPassing: true, costUsd: 0.5, runId: "r1", updatedAt: "2026-03-01T10:00:00.000Z" },
    [key("/repo", "fp-b")]: { finding: "f-bbbbbbbbbbbb", branch: "0/fix-bbb", result: "pr-opened", pullRequestUrl: "https://github.com/o/r/pull/2", draft: true, checksPassing: false, costUsd: 0.25, runId: "r1", updatedAt: "2026-03-02T10:00:00.000Z" },
    [key("/repo", "fp-c")]: { finding: "f-cccccccccccc", branch: "0/fix-ccc", result: "pr-opened", pullRequestUrl: "https://github.com/o/r/pull/3", draft: false, checksPassing: true, costUsd: 0.25, runId: "r1", updatedAt: "2026-03-03T10:00:00.000Z" },
    [key("/repo", "fp-d")]: { finding: "f-dddddddddddd", branch: "0/fix-ddd", result: "committed", checksPassing: true, runId: "r1", updatedAt: "2026-03-04T10:00:00.000Z" },
    [key("/repo", "fp-e")]: { finding: "f-eeeeeeeeeeee", result: "no-change", runId: "r1", updatedAt: "2026-03-05T10:00:00.000Z" },
    [key("/other", "fp-f")]: { finding: "f-ffffffffffff", branch: "0/fix-fff", result: "pr-updated", pullRequestUrl: "https://github.com/o/s/pull/9", draft: false, checksPassing: true, runId: "r2", updatedAt: "2026-04-01T10:00:00.000Z" },
  },
};
const SECRET_EVIDENCE = "EVIDENCE-BODY-MUST-NOT-APPEAR";

function deps(extra: { states?: Record<string, PullRequestState | Error>; asked?: string[]; written?: Array<{ dir: string; names: string[]; text: string }>; out?: string[] } = {}): ExportFixesDeps {
  const host = { pullRequestState: async (url: string) => {
    extra.asked?.push(url);
    const result = extra.states?.[url];
    if (result instanceof Error) throw result;
    if (!result) throw new Error("no such pull request");
    return result;
  } } as unknown as Host;
  const lookup = new Map([
    ["f-aaaaaaaaaaaa", { title: "SQL injection in search", severity: "high", category: "sql-injection" }],
    ["f-bbbbbbbbbbbb", { title: "Ping @victim about #12 <b>x</b> | pipe", severity: "critical", category: "xss" }],
    ["f-cccccccccccc", { title: "Weak hash", severity: "medium", category: "crypto" }],
    ["f-dddddddddddd", { title: "Path traversal", severity: "high", category: "path-traversal" }],
    ["f-ffffffffffff", { title: "Other repo", severity: "low", category: "misc" }],
  ]);
  // The lookup only ever carries these three fields; the evidence stays in the database.
  void SECRET_EVIDENCE;
  return {
    store: { load: () => state, save: () => { throw new Error("export must not write state"); } },
    lookup: () => lookup, host: () => host, repoRoot: async dir => dir, now: () => new Date("2026-06-01T00:00:00.000Z"),
    out: text => { extra.out?.push(text); }, err: () => {},
    writeReport: (dir, files) => { extra.written?.push({ dir, names: files.map(f => f.name), text: files.map(f => f.text).join("\n") }); },
  };
}

describe("0 findings export-fixes", () => {
  it("counts what is known without asking the code host", async () => {
    const asked: string[] = [];
    const report = await buildFixReport({}, deps({ asked }));
    expect(asked).toEqual([]);
    expect(report.summary).toMatchObject({ attempted: 6, proposed: 5, pullRequestsOpened: 4, draft: 1, checksPassed: 4, checksFailed: 1, costUsd: 1, merged: null, acceptanceRate: null });
    expect(report.fixes[0]).toMatchObject({ finding: "f-aaaaaaaaaaaa", title: "SQL injection in search", severity: "high", branch: "0/fix-aaa", pullRequest: null });
    expect(renderFixReportMarkdown(report)).toContain("not measured");
  });

  it("asks the host only with --check-merged and works out the acceptance rate", async () => {
    const asked: string[] = [];
    const states = {
      "https://github.com/o/r/pull/1": { state: "merged", draft: false, commits: 1 },
      "https://github.com/o/r/pull/2": { state: "closed", draft: true, commits: 1 },
      "https://github.com/o/r/pull/3": { state: "merged", draft: false, commits: 3 },
      "https://github.com/o/s/pull/9": new Error("rate limited"),
    } as Record<string, PullRequestState | Error>;
    const report = await buildFixReport({ checkMerged: true }, deps({ states, asked }));
    expect(asked).toHaveLength(4);
    expect(report.summary).toMatchObject({ merged: 2, closedWithoutMerge: 1, stillOpen: 0, unknown: 1, edited: 1, acceptanceRate: 0.6667 });
    expect(report.fixes.find(r => r.finding === "f-cccccccccccc")!.pullRequest).toMatchObject({ state: "merged", editedAfterOpening: true });
    expect(renderFixReportMarkdown(report)).toContain("67%");
  });

  it("filters by repository and date", async () => {
    expect((await buildFixReport({ repo: "/other" }, deps())).fixes.map(r => r.finding)).toEqual(["f-ffffffffffff"]);
    expect((await buildFixReport({ since: "2026-03-03" }, deps())).summary.attempted).toBe(4);
    await expect(buildFixReport({ since: "last week" }, deps())).rejects.toThrow("--since");
  });

  it("neutralises titles in the Markdown and never carries evidence", async () => {
    const report = await buildFixReport({}, deps());
    const markdown = renderFixReportMarkdown(report);
    expect(markdown).not.toMatch(/@(?!​)/);
    expect(markdown).not.toMatch(/#(?!​)12/);
    expect(markdown).not.toContain("<b>");
    expect(markdown).toContain("\\|");
    expect(JSON.stringify(report)).not.toContain(SECRET_EVIDENCE);
    expect(Object.keys(report.fixes[0]!).sort()).toEqual(["branch", "category", "checksPassing", "costUsd", "draft", "finding", "pullRequest", "pullRequestUrl", "recordedAt", "repo", "result", "severity", "title"]);
  });

  it("writes a Markdown and a JSON report to the folder, or prints one", async () => {
    const written: Array<{ dir: string; names: string[]; text: string }> = [];
    await runExportFixes({ output: "/tmp/fix-report" }, deps({ written }));
    expect(written[0]!.names).toEqual(["fix-outcomes.md", "fix-outcomes.json"]);
    expect(written[0]!.text).toContain("0.fix-outcomes.v1");
    const out: string[] = [];
    await runExportFixes({ format: "json" }, deps({ out }));
    expect(JSON.parse(out[0]!).schema).toBe("0.fix-outcomes.v1");
  });

  it("gives the same summary for each repository", async () => {
    const report = await buildFixReport({}, deps());
    expect(report.workspaces.map(w => [w.repo, w.summary.attempted])).toEqual([["/other", 1], ["/repo", 5]]);
    expect(renderFixReportMarkdown(report)).toContain("## By repository");
  });

  it("reads a standalone fix recorded through the same state file", async () => {
    let saved: BurndownState = { version: 1, findings: {}, runs: [] };
    const store = { load: () => structuredClone(saved), save: (s: BurndownState) => { saved = structuredClone(s); } };
    const outcome = { finding: "f-aaaaaaaaaaaa", branch: "0/fix-aaa", changed: true, committed: true, checks: [{ command: "t", code: 0, output: "" }], verified: true, costUsd: 0.3, pullRequest: { url: "https://github.com/o/r/pull/5", created: true, draft: false } };
    recordStandaloneFix("/repo", "fp-a", outcome, store, () => new Date("2026-05-01T00:00:00.000Z"));
    // A later run that changed nothing does not erase the pull request.
    recordStandaloneFix("/repo", "fp-a", { ...outcome, changed: false, committed: false, checks: [], verified: false, pullRequest: undefined }, store);
    const report = await buildFixReport({}, { ...deps(), store });
    expect(report.fixes).toHaveLength(1);
    expect(report.fixes[0]).toMatchObject({ finding: "f-aaaaaaaaaaaa", result: "pr-opened", pullRequestUrl: "https://github.com/o/r/pull/5", checksPassing: true, costUsd: 0.3, repo: "/repo" });
  });

  it("says so when nothing is recorded", async () => {
    const empty: ExportFixesDeps = { ...deps(), store: { load: () => ({ version: 1, findings: {}, runs: [] }), save: () => {} } };
    expect(renderFixReportMarkdown(await buildFixReport({}, empty))).toContain("No fix outcomes are recorded yet");
  });
});
