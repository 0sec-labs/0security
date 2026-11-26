import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { CodeLocationSection, FixSection } from "./finding-code-fix";

const html = (node: ReturnType<typeof createElement>) => renderToStaticMarkup(node);
const record = { branch: "0/fix-a", result: "pr-opened", pullRequestUrl: "https://github.com/o/r/pull/1", draft: true, checksPassing: true, recordedAt: "2026-03-01T10:00:00Z" };

describe("CodeLocationSection", () => {
  it("shows a copyable path:line with an accessible label, and the stored suggestion as text", () => {
    const out = html(createElement(CodeLocationSection, { location: { path: "src/a.ts", startLine: 4, endLine: 6, suggestion: "<b>x</b>" } }));
    expect(out).toContain("src/a.ts:4-6");
    expect(out).toContain('aria-label="Copy src/a.ts:4-6"');
    expect(out).toContain("&lt;b&gt;x&lt;/b&gt;");
    expect(out).not.toContain("style=");
  });
  it("renders nothing without a location", () => {
    expect(html(createElement(CodeLocationSection, { location: null }))).toBe("");
    expect(html(createElement(CodeLocationSection, { location: undefined }))).toBe("");
  });
});

describe("FixSection", () => {
  it("opens a real verification session for the selected finding without claiming the fix passed", () => {
    const out = html(createElement(MemoryRouter, {}, createElement(FixSection, { findingId: "f/a?b", fix: { records: [record], command: "c" } })));
    expect(out).toContain('href="/chats?finding=f%2Fa%3Fb&amp;intent=verify"');
    expect(out).toContain("Re-verify");
    expect(out).toContain("Review its result before updating this finding’s status");
  });
  it("shows the exact command when no fix is recorded", () => {
    const out = html(createElement(FixSection, { fix: { records: [], command: "0security findings fix abc12345" } }));
    expect(out).toContain("No fix recorded");
    expect(out).toContain("0security findings fix abc12345");
  });
  it("shows the branch, a safe pull request link, local checks and the diff with line markers", () => {
    const out = html(createElement(FixSection, { fix: { command: "c", records: [{ ...record, diff: "diff --git a/a b/a\n@@ -1 +1 @@\n-old\n+new\n", diffTruncated: true }] } }));
    expect(out).toContain("0/fix-a");
    expect(out).toContain('href="https://github.com/o/r/pull/1"');
    expect(out).toContain('rel="noopener noreferrer"');
    expect(out).toContain("Draft pull request");
    expect(out).toContain("Local checks passed");
    expect(out).toContain('aria-label="Fix diff"');
    expect(out).toContain("-old");
    expect(out).toContain("+new");
    expect(out).toContain("The diff is cut here");
  });
  it("shows a timestamped CI snapshot and a safe checks link separately from local checks", () => {
    const out = html(createElement(FixSection, { fix: { command: "c", records: [{ ...record, ci: { status: "failing", checkedAt: "2026-11-25T00:00:00Z", url: "https://bitbucket.org/o/r/addon/pipelines/home" } }] } }));
    expect(out).toContain("Local checks passed");
    expect(out).toContain("CI failed");
    expect(out).toContain("Checked");
    expect(out).toContain('href="https://bitbucket.org/o/r/addon/pipelines/home"');
  });
  it("does not render an unsafe link and does not invent a diff", () => {
    const out = html(createElement(FixSection, { fix: { command: "c", records: [{ ...record, pullRequestUrl: "javascript:alert(1)", checksPassing: null }] } }));
    expect(out).not.toContain("href=");
    expect(out).toContain("No checks recorded");
    expect(out).toContain("CI status unavailable");
    expect(out).toContain("The diff is not available");
    expect(out).not.toContain("Fix diff");
  });
  it("renders nothing for an older engine that sends no fix field", () => {
    expect(html(createElement(FixSection, { fix: undefined }))).toBe("");
  });
});
