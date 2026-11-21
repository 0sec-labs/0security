import { describe, expect, it, vi } from "vitest";
import {
  buildIssue, findingKey, GitHubIssueTracker, neutralise, planIssueSync, runIssues,
  type IssuesDeps, type IssueTracker, type TrackedFinding, type TrackerIssue,
} from "../findings-issues.js";

const finding = (over: Partial<TrackedFinding> = {}): TrackedFinding => ({ key: "fp-1", id: "abcdef1234567890", title: "SQL injection in login", severity: "high", category: "injection", path: "src/auth.ts", startLine: 12, ...over });
const issueFor = (f: TrackedFinding, over: Partial<TrackerIssue> = {}): TrackerIssue => {
  const draft = buildIssue(f);
  return { number: 7, key: f.key, title: draft.title, body: draft.body, open: true, labels: draft.labels, ...over };
};

describe("issue text", () => {
  it("carries the marker, severity, category, location and the attacker impact, and nothing else", () => {
    const draft = buildIssue(finding({ impact: "Read any user's data. Who: anyone. They can: read data." }));
    expect(draft.title).toBe("[high] SQL injection in login");
    expect(draft.body).toContain("<!-- 0-finding:fp-1 -->");
    expect(draft.body).toContain("| high | injection | `src/auth.ts:12` | open |");
    expect(draft.body).toContain("What an attacker gets");
    expect(draft.labels).toEqual(["security", "severity:high"]);
  });

  it("neutralises mentions, issue references, markup, links and line breaks", () => {
    const text = neutralise("hi @octocat see #123 and org/repo#9 <img src=x onerror=1> [x](https://evil.test) www.evil.test\nline");
    expect(text).not.toMatch(/@(?!​)/);
    expect(text).not.toMatch(/#(?=\d)/);
    expect(text).not.toContain("<");
    expect(text).not.toContain("://");
    expect(text).not.toContain("\n");
    expect(text).not.toMatch(/\]\(/);
  });

  it("cannot be tricked into writing a second marker or leaking a local path", () => {
    const draft = buildIssue(finding({ title: "x --> <!-- 0-finding:other -->", category: "<!-- 0-finding:other2 -->", path: "/Users/someone/secret.ts" }));
    expect(draft.body.match(/<!-- 0-finding:/g)).toHaveLength(1);
    expect(draft.title).not.toContain("<!--");
    expect(draft.body).not.toContain("/Users/someone");
    expect(draft.body).toContain("| not given |");
  });

  it("hashes a fingerprint that is not plainly safe", () => {
    expect(findingKey("sarif:abc123")).toBe("sarif:abc123");
    expect(findingKey("a b --> c")).toMatch(/^h:[0-9a-f]{32}$/);
  });
});

describe("planning", () => {
  it("creates for open findings at or above the minimum, in severity order", () => {
    const plan = planIssueSync([finding({ key: "m", severity: "medium" }), finding({ key: "c", severity: "critical" }), finding({ key: "l", severity: "low" })], [], "medium");
    expect(plan.actions.map(action => `${action.kind}:${action.finding.key}`)).toEqual(["create:c", "create:m"]);
    expect(plan.belowMinimum).toBe(1);
  });

  it("does nothing when the issue is already current, and updates it when the finding changed", () => {
    const f = finding();
    expect(planIssueSync([f], [issueFor(f)], "medium")).toMatchObject({ actions: [], unchanged: 1 });
    const changed = planIssueSync([finding({ title: "Better title" })], [issueFor(f)], "medium");
    expect(changed.actions.map(action => action.kind)).toEqual(["update"]);
  });

  it("closes the issue for a suppressed, accepted or fixed finding, and not twice", () => {
    for (const closedBecause of ["suppressed", "accepted", "fixed"] as const) {
      const f = finding({ closedBecause });
      expect(planIssueSync([f], [issueFor(f)], "medium").actions.map(action => action.kind)).toEqual(["close"]);
      expect(planIssueSync([f], [issueFor(f, { open: false })], "medium").actions).toEqual([]);
    }
    expect(planIssueSync([finding({ closedBecause: "fixed" })], [], "medium").actions).toEqual([]);
  });

  it("reopens a closed issue when the finding reappears", () => {
    const f = finding();
    expect(planIssueSync([f], [issueFor(f, { open: false })], "medium").actions.map(action => action.kind)).toEqual(["reopen"]);
  });

  it("never duplicates: a second issue with the same key is left alone", () => {
    const f = finding();
    const plan = planIssueSync([f], [issueFor(f, { number: 9, title: "x" }), issueFor(f)], "medium");
    expect(plan.actions).toEqual([]);
  });

  it("updates an issue whose severity label is outdated", () => {
    const f = finding();
    const stale = issueFor(f, { labels: ["security", "severity:low"] });
    expect(planIssueSync([f], [stale], "medium").actions.map(action => action.kind)).toEqual(["update"]);
  });
});

function fakeTracker(issues: TrackerIssue[] = [], labelsUsable = ["security", "severity:high", "severity:medium", "severity:critical"]) {
  const calls: string[] = [];
  const tracker: IssueTracker = {
    list: async () => issues,
    ensureLabels: async () => ({ usable: labelsUsable, warnings: labelsUsable.length ? [] : ["no labels"] }),
    create: async draft => { calls.push(`create ${draft.title} [${draft.labels.join(",")}]`); return 100; },
    update: async (issue, draft) => { calls.push(`update #${issue.number} ${draft.title}`); },
    close: async (issue, comment, completed) => { calls.push(`close #${issue.number} ${completed ? "completed" : "not_planned"} ${comment.slice(0, 20)}`); },
    reopen: async issue => { calls.push(`reopen #${issue.number}`); },
  };
  return { tracker, calls };
}
function deps(findings: TrackedFinding[], tracker: IssueTracker, extra: Partial<IssuesDeps> = {}): IssuesDeps & { sleeps: number[]; errs: string[] } {
  const sleeps: number[] = []; const errs: string[] = [];
  return { out: vi.fn(), err: text => { errs.push(text); }, sleep: async ms => { sleeps.push(ms); }, gh: async () => "o/r\n", loadFindings: async () => findings, makeTracker: () => tracker, sleeps, errs, ...extra };
}
const opts = { minSeverity: "medium", max: "25", delay: "500" };

describe("runIssues", () => {
  it("a dry run prints the plan and changes nothing", async () => {
    const { tracker, calls } = fakeTracker();
    const d = deps([finding()], tracker);
    const result = await runIssues({ ...opts, repo: "o/r", dryRun: true }, d);
    expect(calls).toEqual([]);
    expect(d.errs.join("\n")).toContain("would create: [high] SQL injection in login");
    expect(result.outcomes).toHaveLength(1);
  });

  it("applies the changes, waits between them and honours --max", async () => {
    const { tracker, calls } = fakeTracker();
    const d = deps([finding({ key: "a" }), finding({ key: "b", severity: "medium" }), finding({ key: "c", severity: "medium" })], tracker);
    const result = await runIssues({ ...opts, max: "2", repo: "o/r" }, d);
    expect(calls).toEqual(["create [high] SQL injection in login [security,severity:high]", "create [medium] SQL injection in login [security,severity:medium]"]);
    expect(d.sleeps).toEqual([500]);
    expect(result).toMatchObject({ planned: 3, deferred: 1 });
  });

  it("keeps going and reports a failure, and drops labels that cannot be used", async () => {
    const { tracker, calls } = fakeTracker([], []);
    tracker.create = async draft => { if (draft.title.includes("boom")) throw new Error("rate limited"); calls.push(`create [${draft.labels}]`); return 1; };
    const d = deps([finding({ key: "a", title: "boom" }), finding({ key: "b", severity: "medium" })], tracker);
    const result = await runIssues({ ...opts, repo: "o/r" }, d);
    expect(result.outcomes.map(outcome => outcome.ok)).toEqual([false, true]);
    expect(calls).toEqual(["create []"]);
    expect(d.errs.join("\n")).toContain("warning: no labels");
  });

  it("rejects bad input", async () => {
    const { tracker } = fakeTracker();
    await expect(runIssues({ ...opts, repo: "not a repo" }, deps([], tracker))).rejects.toThrow(/--repo/);
    await expect(runIssues({ ...opts, minSeverity: "urgent", repo: "o/r" }, deps([], tracker))).rejects.toThrow(/--min-severity/);
    await expect(runIssues({ ...opts, max: "0", repo: "o/r" }, deps([], tracker))).rejects.toThrow(/--max/);
  });
});

describe("GitHub tracker over a fake gh", () => {
  function fakeGh(state: { issues?: string; labels?: string[]; failLabelCreate?: boolean } = {}) {
    const calls: Array<{ args: string[]; input?: string }> = [];
    const gh = async (args: string[], input?: string): Promise<string> => {
      calls.push({ args, ...(input !== undefined ? { input } : {}) });
      const path = args.find(arg => arg.startsWith("repos/")) ?? "";
      if (path.includes("/issues?")) return state.issues ?? "";
      if (path.includes("/labels?")) return (state.labels ?? []).join("\n");
      if (path.endsWith("/labels") && args.includes("POST") && state.failLabelCreate) throw new Error("HTTP 403");
      if (path.endsWith("/issues") && args.includes("POST")) return JSON.stringify({ number: 42 });
      return "";
    };
    return { gh, calls };
  }

  it("lists only issues carrying a marker, from the security-labelled issues", async () => {
    const row = (number: number, body: string, state = "open") => JSON.stringify({ number, title: "t", body, open: state === "open", labels: ["security"] });
    const { gh, calls } = fakeGh({ issues: [row(1, "<!-- 0-finding:fp-1 -->\nbody"), row(2, "no marker"), row(3, "<!-- 0-finding:fp-2 -->", "closed")].join("\n") });
    const issues = await new GitHubIssueTracker("o/r", gh).list();
    expect(issues.map(issue => [issue.number, issue.key, issue.open])).toEqual([[1, "fp-1", true], [3, "fp-2", false]]);
    expect(calls[0]!.args).toContain("repos/o/r/issues?state=all&labels=security&per_page=100");
  });

  it("creates missing labels with a colour and skips, with a warning, the ones it cannot create", async () => {
    const ok = fakeGh({ labels: ["security"] });
    expect(await new GitHubIssueTracker("o/r", ok.gh).ensureLabels(["security", "severity:high"])).toEqual({ usable: ["security", "severity:high"], warnings: [] });
    expect(JSON.parse(ok.calls.at(-1)!.input!)).toMatchObject({ name: "severity:high", color: "d93f0b" });
    const denied = fakeGh({ failLabelCreate: true });
    const result = await new GitHubIssueTracker("o/r", denied.gh).ensureLabels(["security"]);
    expect(result.usable).toEqual([]);
    expect(result.warnings[0]).toContain("could not create label 'security'");
  });

  it("creates, updates, closes and reopens with the right API calls", async () => {
    const { gh, calls } = fakeGh();
    const tracker = new GitHubIssueTracker("o/r", gh);
    const f = finding();
    expect(await tracker.create(buildIssue(f))).toBe(42);
    const issue = issueFor(f, { labels: ["security", "severity:low"] });
    await tracker.update(issue, buildIssue(f));
    await tracker.close(issue, "done", true);
    await tracker.reopen(issue, "back");
    const summary = calls.map(call => `${call.args.filter(arg => /^(POST|PATCH|DELETE)$/.test(arg))[0]} ${call.args.find(arg => arg.startsWith("repos/"))}`);
    expect(summary).toEqual([
      "POST repos/o/r/issues", "PATCH repos/o/r/issues/7", "POST repos/o/r/issues/7/labels", "DELETE repos/o/r/issues/7/labels/severity%3Alow",
      "POST repos/o/r/issues/7/comments", "PATCH repos/o/r/issues/7", "PATCH repos/o/r/issues/7", "POST repos/o/r/issues/7/comments",
    ]);
    expect(JSON.parse(calls[5]!.input!)).toEqual({ state: "closed", state_reason: "completed" });
  });
});
