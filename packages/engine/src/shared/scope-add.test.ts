import { describe, expect, it } from "vitest";
import { addScopeEntries, parseScope, scopeBullet } from "./scope.js";

const entry = (kind: "in" | "out", vector: string, reason: string, extra: { until?: string; paths?: string[] } = {}) => ({ kind, vector, reason, paths: extra.paths ?? [], ...(extra.until ? { until: extra.until } : {}) });

describe("addScopeEntries", () => {
  it("appends a whole section to a file without one, keeping the file byte for byte", () => {
    const original = "# Security\n\nMail us.\n";
    const out = addScopeEntries(original, [entry("out", "denial-of-service", "gateway")]);
    expect(out.startsWith(original)).toBe(true);
    expect(parseScope(out).entries).toMatchObject([{ kind: "out", category: "denial-of-service", reason: "gateway" }]);
  });

  it("adds to the end of an existing list and keeps the person's own text and order", () => {
    const original = "# Security\n\nIntro.\n\n## Scope\n\nWe care about the following.\n\n### In scope\n\n- xss: we render html\n\n### Out of scope\n\n- csrf: api only\n\nSome closing words.\n\n## Credits\n\nthanks\n";
    const out = addScopeEntries(original, [entry("out", "dos", "gateway", { until: "2027-06-30" }), entry("in", "broken-access-control", "tenants", { paths: ["src/api/**"] })]);
    expect(out).toContain("We care about the following.");
    expect(out).toContain("Some closing words.");
    expect(out.endsWith("## Credits\n\nthanks\n")).toBe(true);
    const parsed = parseScope(out);
    expect(parsed.entries.map(e => [e.kind, e.category])).toEqual([["in", "xss"], ["in", "broken-access-control"], ["out", "csrf"], ["out", "denial-of-service"]]);
    expect(parsed.entries[3]).toMatchObject({ until: "2027-06-30" });
    expect(parsed.entries[1]!.paths).toEqual(["src/api/**"]);
  });

  it("creates a missing list inside the section", () => {
    const original = "## Scope\n\n### In scope\n\n- xss: html\n\n## After\n\nx\n";
    const out = addScopeEntries(original, [entry("out", "csrf", "api only")]);
    expect(parseScope(out).entries.map(e => [e.kind, e.category])).toEqual([["in", "xss"], ["out", "csrf"]]);
    expect(out.endsWith("## After\n\nx\n")).toBe(true);
  });

  it("adds to an existing out list and creates the in list after it, each entry under its own heading", () => {
    const original = "# S\n\n## Scope\n\n### Out of scope\n\n- csrf: api only\n\n## Credits\n\nthanks\n";
    const out = addScopeEntries(original, [entry("in", "xss", "html"), entry("out", "dos", "gateway"), entry("in", "XSS", "again")]);
    const parsed = parseScope(out);
    expect(parsed.entries.map(e => [e.kind, e.category])).toEqual([["out", "csrf"], ["out", "denial-of-service"], ["in", "xss"]]);
    expect(out.endsWith("## Credits\n\nthanks\n")).toBe(true);
  });

  it("does not add an entry the section holds, even under another name", () => {
    const original = "## Scope\n### Out of scope\n- dos: gateway\n";
    expect(addScopeEntries(original, [entry("out", "denial-of-service", "other words")])).toBe(original);
    expect(parseScope(addScopeEntries(original, [entry("out", "denial-of-service", "x", { paths: ["src/**"] })])).entries).toHaveLength(2);
  });

  it("keeps CRLF files CRLF and handles a file with no final newline", () => {
    const crlf = "# S\r\n\r\n## Scope\r\n\r\n### Out of scope\r\n\r\n- csrf: a\r\n\r\n## After\r\nx\r\n";
    const out = addScopeEntries(crlf, [entry("out", "xss", "b")]);
    expect(out).not.toMatch(/[^\r]\n/);
    expect(parseScope(out).entries).toHaveLength(2);
    const bare = "## Scope\n### Out of scope\n- csrf: a";
    const out2 = addScopeEntries(bare, [entry("out", "xss", "b")]);
    expect(out2.startsWith(bare)).toBe(true);
    expect(parseScope(out2).entries).toHaveLength(2);
    expect(out2.endsWith("\n")).toBe(false);
  });

  it("writes a reason of 'not given' when none was given and cleans hostile text", () => {
    expect(scopeBullet({ vector: "csrf", reason: "", paths: [] })).toBe("- csrf: not given");
    expect(scopeBullet({ vector: "<b>csrf</b>", reason: "a\u0007<script>x</script>b", paths: [] })).not.toMatch(/[<>\u0007]/);
  });
  it("keeps route-group parentheses in paths and never writes a path-less entry when every path is rejected", () => {
    const original = "# Security\n";
    const kept = addScopeEntries(original, [entry("out", "broken-access-control", "public login", { paths: ["app/(auth)/login.ts"] })]);
    expect(parseScope(kept).entries[0]?.paths).toEqual(["app/(auth)/login.ts"]);
    const dropped = addScopeEntries(original, [entry("out", "broken-access-control", "bad", { paths: ["src/a,b.ts", "../x.ts"] })]);
    expect(dropped).toBe(original);
  });
});
