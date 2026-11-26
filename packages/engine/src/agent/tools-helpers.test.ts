import { describe, expect, it } from "vitest";
import { findMatchingFindingCandidate } from "./tools-helpers.js";

describe("findMatchingFindingCandidate by location", () => {
  const at = (id: string, title: string, path: string, startLine: number, endLine?: number, category = "code-injection") =>
    ({ id, title, category, evidenceRequest: `${title} request`, reviewAnnotation: { path, startLine, ...(endLine ? { endLine } : {}) } });

  it("treats the same category at overlapping or adjacent lines of one file as one finding, whatever the title", () => {
    const existing = [at("a", "Server-side JavaScript injection via contributions", "app/routes/contributions.js", 32, 34)];
    expect(findMatchingFindingCandidate(existing, at("b", "Unauthenticated client input reaches eval", "app/routes/contributions.js", 35), { byLocation: true })?.id).toBe("a");
    expect(findMatchingFindingCandidate(existing, at("b", "eval in contribution update", "app/routes/contributions.js", 33), { byLocation: true })?.id).toBe("a");
  });

  it("keeps findings apart when the file, the category or the place differs", () => {
    const existing = [at("a", "SQL injection in users", "src/users.ts", 10, 12, "sql-injection")];
    for (const other of [
      at("b", "Other title", "src/orders.ts", 10, 12, "sql-injection"),
      at("c", "Other title", "src/users.ts", 40, 42, "sql-injection"),
      at("d", "Other title", "src/users.ts", 14, 15, "xss"),
    ]) expect(findMatchingFindingCandidate(existing, other, { byLocation: true })).toBeUndefined();
  });

  it("merges overlapping lines whatever the category, but nearby lines only within one category", () => {
    const existing = [at("a", "NoSQL injection in allocations", "app/data/allocations-dao.js", 77, 77, "sql-injection")];
    expect(findMatchingFindingCandidate(existing, at("b", "Server-side JavaScript via $where", "app/data/allocations-dao.js", 77, 77, "code-injection"), { byLocation: true })?.id).toBe("a");
    expect(findMatchingFindingCandidate(existing, at("c", "Something else", "app/data/allocations-dao.js", 79, 79, "code-injection"), { byLocation: true })).toBeUndefined();
    expect(findMatchingFindingCandidate(existing, at("d", "Something else", "app/data/allocations-dao.js", 79, 79, "sql-injection"), { byLocation: true })?.id).toBe("a");
  });

  it("reads the location from a stored row's JSON text", () => {
    const stored = { id: "row", title: "x", category: "ssrf", evidenceRequest: "r", reviewAnnotation: JSON.stringify({ path: "a.js", startLine: 7 }) };
    expect(findMatchingFindingCandidate([stored], at("n", "different words", "a.js", 8, undefined, "ssrf"), { byLocation: true })?.id).toBe("row");
  });

  it("keeps findings that name different advisories apart, even on one manifest line", () => {
    const existing = [at("a", "[not-reached] snakeyaml 1.30: GHSA-3mc7-4q67-w48m", "pom.xml", 6, undefined, "vulnerable-dependency")];
    const options = { byLocation: true };
    expect(findMatchingFindingCandidate(existing, at("b", "[not-reached] snakeyaml 1.30: GHSA-98wm-3w3q-mw94", "pom.xml", 6, undefined, "vulnerable-dependency"), options)).toBeUndefined();
    // Same evidence request and near-identical titles must not merge through the fuzzy-title rule either.
    const near = (id: string, advisory: string) => ({ id, title: `[not-reached] snakeyaml 1.30: ${advisory}`, category: "vulnerable-dependency", evidenceRequest: "pom.xml advisory check", reviewAnnotation: { path: "pom.xml", startLine: 6 } });
    expect(findMatchingFindingCandidate([near("x", "GHSA-3mc7-4q67-w48m")], near("y", "GHSA-98wm-3w3q-mw94"))).toBeUndefined();
    expect(findMatchingFindingCandidate(existing, at("c", "snakeyaml 1.30 again: GHSA-3MC7-4Q67-W48M", "pom.xml", 6, undefined, "vulnerable-dependency"), options)?.id).toBe("a");
  });

  it("does nothing by location unless asked, so the older behaviour is unchanged", () => {
    const existing = [at("a", "Server-side JavaScript injection", "app/routes/contributions.js", 32)];
    expect(findMatchingFindingCandidate(existing, at("b", "Totally different title", "app/routes/contributions.js", 32))).toBeUndefined();
  });
});
