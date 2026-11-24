import { describe, expect, it } from "vitest";
import { renderMarkdownForTerminal } from "./terminal-markdown.js";

const report = [
  "# 0 Scan Report", "", "| Field | Value |", "|-------|-------|", "| Target | /app |", "",
  "## Summary", "", "- **Findings:** 3", "",
  "**Evidence:** CWE: CWE-89", "",
  "<details>", "<summary>Request / Response</summary>", "", "**Request:**", "```", "`GET /orders` with the `x-api-token` header.", "```", "</details>",
].join("\n");

describe("renderMarkdownForTerminal", () => {
  it("drops markdown and HTML markers and keeps the words", () => {
    const text = renderMarkdownForTerminal(report, { color: false });
    expect(text).not.toMatch(/\*\*|<details>|<summary>|\|---|```/);
    expect(text).toContain("0 SCAN REPORT");
    expect(text).toContain("Target   /app");
    expect(text).toContain("- Findings: 3");
    expect(text).toContain("Request / Response");
    expect(text).toContain("`GET /orders` with the `x-api-token` header.");
  });
  it("adds colour only when asked and unescapes the report's escapes", () => {
    expect(renderMarkdownForTerminal("**x** \\*a\\* &lt;b&gt;", { color: false })).toBe("x *a* <b>\n");
    expect(renderMarkdownForTerminal("**x**")).toContain("\u001b[1mx");
  });
});
