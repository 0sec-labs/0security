import { describe, expect, it } from "vitest";
import { checksLabel, ciLabel, locationText, parseDiff, pullRequestLabel, safePullRequestHref } from "./finding-fix-model";

const record = { branch: "0/fix-a", result: "pr-opened", pullRequestUrl: "https://github.com/o/r/pull/1", draft: true, checksPassing: false, recordedAt: "2026-03-01T10:00:00Z" };

describe("locationText", () => {
  it("gives path:line or a range", () => {
    expect(locationText({ path: "src/a.ts", startLine: 4 })).toBe("src/a.ts:4");
    expect(locationText({ path: "src/a.ts", startLine: 4, endLine: 4 })).toBe("src/a.ts:4");
    expect(locationText({ path: "src/a.ts", startLine: 4, endLine: 9 })).toBe("src/a.ts:4-9");
  });
});

describe("fix labels", () => {
  it("never claims merged or closed", () => {
    expect(pullRequestLabel(record)).toMatch(/^Draft pull request/);
    expect(pullRequestLabel({ ...record, draft: false })).toMatch(/ready for review/);
    expect(pullRequestLabel({ ...record, draft: null })).toMatch(/^Pull request,/);
    expect(pullRequestLabel({ ...record, pullRequestUrl: null, result: "committed" })).toMatch(/no pull request/);
    for (const text of [pullRequestLabel(record), checksLabel(record)]) expect(text).not.toMatch(/merged|closed/i);
  });
  it("says checks are local and only when recorded", () => {
    expect(checksLabel(record)).toBe("Local checks failed");
    expect(checksLabel({ ...record, checksPassing: true })).toBe("Local checks passed");
    expect(checksLabel({ ...record, checksPassing: null })).toBe("No checks recorded");
  });
  it("links only http and https", () => {
    expect(safePullRequestHref("https://github.com/o/r/pull/1")).toBe("https://github.com/o/r/pull/1");
    expect(safePullRequestHref("javascript:alert(1)")).toBeNull();
    expect(safePullRequestHref("nope")).toBeNull();
    expect(safePullRequestHref(null)).toBeNull();
  });
});

describe("parseDiff", () => {
  it("marks added, removed and header lines, and does not mistake file headers for changes", () => {
    const lines = parseDiff("diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\n same\n");
    expect(lines.map(line => line.kind)).toEqual(["meta", "meta", "meta", "hunk", "remove", "add", "context"]);
  });
});

describe("CI labels", () => {
  it("keeps host checks separate from local test results, including unavailable and empty CI", () => {
    expect(ciLabel({ ...record, checksPassing: true })).toBe("CI status unavailable");
    const ci = { checkedAt: "2026-11-25T00:00:00Z" };
    expect(ciLabel({ ...record, ci: { ...ci, status: "none" } })).toBe("No CI checks reported");
    expect(ciLabel({ ...record, ci: { ...ci, status: "passing" } })).toBe("CI passed");
    expect(ciLabel({ ...record, ci: { ...ci, status: "failing" } })).toBe("CI failed");
    expect(ciLabel({ ...record, ci: { ...ci, status: "pending" } })).toBe("CI pending");
  });
});
