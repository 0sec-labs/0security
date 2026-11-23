import { describe, expect, it } from "vitest";
import { dominantEol, globToRegExp, labelWithScope, matchesScope, MAX_SCOPE_ENTRIES, parseScope, renderScopeSection, replaceScopeSection, scopeEntryExpired, splitByScope } from "./scope.js";

const DOC = `# Security policy

Report issues by email.

## Scope

### In scope

- broken-access-control: tenants must never see each other's data [paths: src/api/**]
- hardcoded secrets: keys in source are never acceptable

### Out of scope

- denial of service: the service sits behind a rate-limiting gateway (until 2027-06-30)
- Missing rate limit: same gateway
- csrf: API only, tokens in headers

## Credits

- somebody
`;

describe("parseScope", () => {
  it("reads both lists, maps vectors to categories and stops at the next heading", () => {
    const parsed = parseScope(DOC);
    expect(parsed.found).toBe(true);
    expect(parsed.entries.map(e => [e.kind, e.category])).toEqual([
      ["in", "broken-access-control"], ["in", "hardcoded-secret"], ["out", "denial-of-service"], ["out", "missing-rate-limit"], ["out", "csrf"],
    ]);
    expect(parsed.entries[0]).toMatchObject({ reason: "tenants must never see each other's data", paths: ["src/api/**"] });
    expect(parsed.entries[2]).toMatchObject({ until: "2027-06-30", reason: "the service sits behind a rate-limiting gateway" });
    expect(parsed.warnings).toEqual([]);
  });

  it("reports no section when there is none", () => {
    expect(parseScope("# Policy\n\nNothing here.\n")).toMatchObject({ found: false, entries: [] });
    expect(parseScope("")).toMatchObject({ found: false });
  });

  it("ignores case and extra whitespace in headings and vectors", () => {
    const parsed = parseScope("##   SCOPE  \n\n###  OUT-OF-SCOPE\n\n-    DoS   :    behind a gateway\n###in scope\n* XSS:  we render user html\n");
    // '###in scope' has no space after the hashes, so it is not a heading and its bullet stays in the out list.
    expect(parsed.entries.map(e => [e.kind, e.category])).toEqual([["out", "denial-of-service"], ["out", "xss"]]);
    const ok = parseScope("## scope\n### In Scope\n\n*   XSS:  we render user html\n");
    expect(ok.entries[0]).toMatchObject({ kind: "in", category: "xss" });
  });

  it("reads CRLF and bare CR line endings", () => {
    const crlf = DOC.replace(/\n/g, "\r\n");
    expect(parseScope(crlf).entries).toHaveLength(5);
    expect(parseScope(DOC.replace(/\n/g, "\r")).entries).toHaveLength(5);
  });

  it("accepts odd bullets: asterisks, plus signs, numbers, unicode dots", () => {
    const parsed = parseScope("## Scope\n### Out of scope\n* dos: a\n+ csrf: b\n1. xss: c\n2) cors: d\n• xxe: e\n");
    expect(parsed.entries.map(e => e.category)).toEqual(["denial-of-service", "csrf", "xss", "cors", "xxe"]);
  });

  it("folds nested bullets and wrapped lines into the reason of the entry above", () => {
    const parsed = parseScope("## Scope\n### Out of scope\n- dos: behind a gateway\n  - the gateway allows 10 requests a second\n  - audited yearly\n- csrf: api only\n  and cookies are never used\n");
    expect(parsed.entries).toHaveLength(2);
    expect(parsed.entries[0]!.reason).toBe("behind a gateway; the gateway allows 10 requests a second; audited yearly");
    expect(parsed.entries[1]!.reason).toBe("api only and cookies are never used");
  });

  it("keeps an entry with no colon and an empty reason", () => {
    const parsed = parseScope("## Scope\n### Out of scope\n- denial of service\n");
    expect(parsed.entries[0]).toMatchObject({ category: "denial-of-service", reason: "" });
  });

  it("splits on a dash when there is no colon", () => {
    const parsed = parseScope("## Scope\n### Out of scope\n- rate limiting — the gateway does it\n");
    expect(parsed.entries[0]).toMatchObject({ category: "missing-rate-limit", reason: "the gateway does it" });
  });

  it("reports an unmatched entry, keeps it and labels nothing with it", () => {
    const parsed = parseScope("## Scope\n### Out of scope\n- everything: we do not care\n- the colour of the logo: no\n");
    expect(parsed.unmatched.map(e => e.vector)).toEqual(["everything", "the colour of the logo"]);
    expect(parsed.entries).toHaveLength(2);
    expect(parsed.warnings.filter(w => w.startsWith("unmatched scope entry"))).toHaveLength(2);
    expect(matchesScope({ category: "xss" }, parsed.entries)).toBeUndefined();
    expect(matchesScope({ category: "other" }, parsed.entries)).toBeUndefined();
  });

  it("maps free text with the same keywords as the finding categories", () => {
    const parsed = parseScope("## Scope\n### Out of scope\n- catastrophic backtracking on user input: ok\n- SQL injection: ok\n- exhausting memory with large uploads: ok\n");
    expect(parsed.entries.map(e => e.category)).toEqual(["regex-dos", "sql-injection", "denial-of-service"]);
  });

  it("reads expiry, ignores an entry with an impossible date and says so", () => {
    const parsed = parseScope("## Scope\n### Out of scope\n- csrf: a (until 2027-02-30)\n- cors: b (until soon)\n- xss: c (until 2027-01-31)\n");
    expect(parsed.entries.map(e => e.category)).toEqual(["xss"]);
    expect(parsed.warnings.filter(w => w.includes("is not a date"))).toHaveLength(2);
  });

  it("reads several path globs and drops absolute and parent paths", () => {
    const parsed = parseScope("## Scope\n### Out of scope\n- csrf: a [paths: src/admin/**, ./tools/*.js, /etc/passwd, ../up/**]\n");
    expect(parsed.entries[0]!.paths).toEqual(["src/admin/**", "tools/*.js"]);
  });

  it("drops a repeated entry once and warns", () => {
    const parsed = parseScope("## Scope\n### Out of scope\n- dos: a\n- Denial of Service: b\n- csrf: c\n");
    expect(parsed.entries).toHaveLength(2);
    expect(parsed.entries[0]!.reason).toBe("a");
    expect(parsed.warnings.some(w => w.includes("repeats an earlier entry"))).toBe(true);
  });

  it("warns when a vector is both in and out of scope; in scope wins", () => {
    const parsed = parseScope("## Scope\n### In scope\n- dos: matters\n### Out of scope\n- dos: gateway\n");
    expect(parsed.warnings.some(w => w.includes("both in scope and out of scope"))).toBe(true);
    expect(matchesScope({ category: "denial-of-service" }, parsed.entries)?.scope).toBe("in-scope");
  });

  it("ignores bullets under an unknown heading or before any heading, and says so", () => {
    const parsed = parseScope("## Scope\n- dos: loose\n### Notes\n- csrf: a\n### Out of scope\n- xss: b\n");
    expect(parsed.entries.map(e => e.category)).toEqual(["xss"]);
    expect(parsed.warnings.some(w => w.includes("not 'In scope' or 'Out of scope'"))).toBe(true);
    expect(parsed.warnings.some(w => w.includes("outside"))).toBe(true);
  });

  it("does not read a Scope heading inside a code fence", () => {
    expect(parseScope("```\n## Scope\n### Out of scope\n- dos: x\n```\n").found).toBe(false);
  });

  it("ignores deeper Scope headings and other levels", () => {
    expect(parseScope("# Scope\n### Out of scope\n- dos: x\n").found).toBe(false);
    expect(parseScope("### Scope\n- dos: x\n").found).toBe(false);
  });

  it("cleans hostile text: HTML, links, control characters, zero-width and bidi characters", () => {
    const parsed = parseScope("## Scope\n### Out of scope\n- <script>alert(1)</script>csrf<b>: </b>**bold** <!-- hidden --> [click](http://evil.example) \u0007‮ reversed​ text\n");
    const entry = parsed.entries[0]!;
    expect(entry.category).toBe("csrf");
    expect(entry.reason).not.toMatch(/[<>\u0007‮​]/);
    expect(entry.reason).not.toContain("hidden");
    expect(entry.reason).not.toContain("evil.example");
    expect(entry.reason).toContain("click");
  });

  it("caps the length of vectors, reasons and paths", () => {
    const parsed = parseScope(`## Scope\n### Out of scope\n- csrf ${"x".repeat(500)}: ${"y".repeat(5000)} [paths: ${"p".repeat(500)}]\n`);
    const entry = parsed.entries[0]!;
    expect(entry.vector.length).toBeLessThanOrEqual(120);
    expect(entry.reason.length).toBeLessThanOrEqual(400);
    expect(entry.paths[0]!.length).toBeLessThanOrEqual(200);
  });

  it("reads at most 100 entries and says so", () => {
    const lines = Array.from({ length: 150 }, (_, i) => `- vector number ${i}: reason`).join("\n");
    const parsed = parseScope(`## Scope\n### Out of scope\n${lines}\n`);
    expect(parsed.entries).toHaveLength(MAX_SCOPE_ENTRIES);
    expect(parsed.warnings.some(w => w.includes("more than 100"))).toBe(true);
  });

  it("survives a huge file and a binary-looking one", () => {
    const parsed = parseScope(`## Scope\n### Out of scope\n- csrf: a\n${"z".repeat(600_000)}\n`);
    expect(parsed.entries).toHaveLength(1);
    expect(parseScope("\u0000\u0001\u0002## Scope\n").found).toBe(false);
  });
});

describe("matchesScope", () => {
  const entries = parseScope(DOC).entries;
  const now = new Date("2027-01-15T12:00:00Z");

  it("matches an out-of-scope category", () => {
    expect(matchesScope({ category: "denial-of-service", path: "src/a.js" }, entries, now)).toMatchObject({ scope: "out-of-scope", entry: { reason: "the service sits behind a rate-limiting gateway" } });
    expect(matchesScope({ category: "regex-dos" }, entries, now)?.scope).toBe("out-of-scope");
    expect(matchesScope({ category: "sql-injection" }, entries, now)).toBeUndefined();
  });

  it("requires the path when the entry has paths", () => {
    expect(matchesScope({ category: "broken-access-control", path: "src/api/users/get.js" }, entries, now)?.scope).toBe("in-scope");
    expect(matchesScope({ category: "broken-access-control", path: "src/web/a.js" }, entries, now)).toBeUndefined();
    expect(matchesScope({ category: "broken-access-control" }, entries, now)).toBeUndefined();
  });

  it("ignores an expired entry, through the end of the day", () => {
    expect(matchesScope({ category: "denial-of-service" }, entries, new Date("2027-06-30T23:59:59Z"))?.scope).toBe("out-of-scope");
    expect(matchesScope({ category: "denial-of-service" }, entries, new Date("2027-07-01T00:00:00Z"))).toBeUndefined();
    expect(scopeEntryExpired({ until: "2027-06-30" }, Date.parse("2027-07-01T00:00:01Z"))).toBe(true);
    expect(scopeEntryExpired({}, Date.now())).toBe(false);
  });

  it("prefers an entry with paths over one without, and in scope on a tie", () => {
    const mixed = parseScope("## Scope\n### Out of scope\n- csrf: api only\n### In scope\n- csrf: but the admin area uses cookies [paths: src/admin/**]\n").entries;
    expect(matchesScope({ category: "csrf", path: "src/admin/a.js" }, mixed)?.scope).toBe("in-scope");
    expect(matchesScope({ category: "csrf", path: "src/other.js" }, mixed)?.scope).toBe("out-of-scope");
  });
});

describe("labelWithScope and splitByScope", () => {
  const entries = parseScope("## Scope\n### Out of scope\n- dos: gateway\n").entries;
  it("labels a matching finding and leaves the others as they are", () => {
    const hit = labelWithScope({ category: "denial-of-service", id: "a" }, entries, "SECURITY.md");
    expect(hit).toMatchObject({ scope: "out-of-scope", scopeReason: "gateway", scopeSource: "SECURITY.md" });
    const miss = { category: "xss", id: "b" };
    expect(labelWithScope(miss, entries, "SECURITY.md")).toBe(miss);
    expect(labelWithScope({ category: "denial-of-service" }, parseScope("## Scope\n### Out of scope\n- dos\n").entries, "s").scopeReason).toBe("no reason given");
  });
  it("splits and keeps order", () => {
    const list = [{ scope: "out-of-scope", n: 1 }, { n: 2 }, { scope: "in-scope", n: 3 }, { scope: "out-of-scope", n: 4 }];
    const { inScope, outOfScope } = splitByScope(list);
    expect(inScope.map(f => f.n)).toEqual([2, 3]);
    expect(outOfScope.map(f => f.n)).toEqual([1, 4]);
  });
});

describe("globToRegExp", () => {
  it("handles stars, double stars and folders", () => {
    expect(globToRegExp("src/admin/**").test("src/admin/a/b.js")).toBe(true);
    expect(globToRegExp("src/admin/**").test("src/administrator/a.js")).toBe(false);
    expect(globToRegExp("src/*.js").test("src/a.js")).toBe(true);
    expect(globToRegExp("src/*.js").test("src/a/b.js")).toBe(false);
    expect(globToRegExp("**/*.test.js").test("a/b/c.test.js")).toBe(true);
    expect(globToRegExp("**/*.test.js").test("c.test.js")).toBe(true);
    expect(globToRegExp("src/admin").test("src/admin/x.js")).toBe(true);
    expect(globToRegExp("a.b").test("axb")).toBe(false);
  });
});

describe("renderScopeSection and replaceScopeSection", () => {
  it("renders what parseScope reads back", () => {
    const section = renderScopeSection([
      { kind: "in", vector: "broken-access-control", reason: "tenants", until: undefined, paths: ["src/api/**"] },
      { kind: "out", vector: "denial-of-service", reason: "gateway", until: "2027-06-30", paths: [] },
    ]);
    const parsed = parseScope(section);
    expect(parsed.warnings).toEqual([]);
    expect(parsed.entries).toMatchObject([{ kind: "in", category: "broken-access-control", paths: ["src/api/**"] }, { kind: "out", category: "denial-of-service", until: "2027-06-30" }]);
    expect(parseScope(renderScopeSection([])).entries).toEqual([]);
  });

  it("appends a section to a file without one and keeps every byte of the file", () => {
    const original = "# Security\r\n\r\nMail us.\r\n";
    const out = replaceScopeSection(original, renderScopeSection([{ kind: "out", vector: "csrf", reason: "api", paths: [] }]));
    expect(out.startsWith(original)).toBe(true);
    expect(out).toContain("## Scope\r\n");
    expect(out).not.toMatch(/[^\r]\n/);
  });

  it("appends after a file with no final newline", () => {
    const out = replaceScopeSection("# Security", "## Scope\n");
    expect(out.startsWith("# Security")).toBe(true);
    expect(parseScope(out).found).toBe(true);
  });

  it("replaces only the section, keeping text before and after byte for byte", () => {
    const before = "# Security\n\nIntro  with  odd   spacing\t\n\n";
    const after = "## Credits\n\n- somebody\n\ntrailing spaces   ";
    const original = `${before}## Scope\n\n### Out of scope\n\n- old: thing\n\n${after}`;
    const out = replaceScopeSection(original, renderScopeSection([{ kind: "out", vector: "csrf", reason: "api", paths: [] }]));
    expect(out.startsWith(before)).toBe(true);
    expect(out.endsWith(after)).toBe(true);
    expect(out).not.toContain("old: thing");
    expect(parseScope(out).entries.map(e => e.category)).toEqual(["csrf"]);
  });

  it("keeps CRLF in a CRLF file when replacing", () => {
    const original = "# S\r\n\r\n## Scope\r\n\r\n- old: x\r\n\r\n## After\r\ntext\r\n";
    const out = replaceScopeSection(original, "## Scope\n\n### Out of scope\n\n- csrf: a\n");
    expect(out).not.toMatch(/[^\r]\n/);
    expect(out.endsWith("## After\r\ntext\r\n")).toBe(true);
  });

  it("does not touch a Scope heading inside a fence", () => {
    const original = "```\n## Scope\n```\n";
    const out = replaceScopeSection(original, "## Scope\n");
    expect(out.startsWith(original)).toBe(true);
  });

  it("is stable: replacing twice with the same section gives the same text", () => {
    const section = renderScopeSection([{ kind: "out", vector: "csrf", reason: "api", paths: [] }]);
    const once = replaceScopeSection("# S\n\n## After\nx\n", section);
    expect(replaceScopeSection(once, section)).toBe(once);
  });

  it("detects the dominant line ending", () => {
    expect(dominantEol("a\r\nb\r\n")).toBe("\r\n");
    expect(dominantEol("a\nb\r\n")).toBe("\n");
    expect(dominantEol("none")).toBe("\n");
  });
});
