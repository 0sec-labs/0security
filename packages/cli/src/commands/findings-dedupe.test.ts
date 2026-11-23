import { describe, expect, it } from "vitest";
import { foldSimilarGroups, type FoldableGroup, type GroupRow } from "./findings-dedupe.js";

const group = (fingerprint: string, row: Partial<GroupRow> & { path?: string; start?: number; end?: number }, count = 1, scans = 1): FoldableGroup<GroupRow> => ({
  fingerprint, count, scans,
  latest: { title: row.title ?? "t", category: row.category ?? "other", triageStatus: row.triageStatus ?? "new", reviewAnnotation: row.path ? JSON.stringify({ path: row.path, startLine: row.start ?? 1, endLine: row.end }) : null },
});

describe("foldSimilarGroups", () => {
  it("folds the same flaw found by two runs, summing the hits, and keeps the first group", () => {
    const folded = foldSimilarGroups([
      group("a", { title: "Unauthenticated debug endpoint exposes plaintext passwords", category: "information-disclosure", path: "api_views/users.py", start: 24, end: 25 }, 2, 2),
      group("b", { title: "Public debug endpoint discloses every user's plaintext password", category: "information-disclosure", path: "api_views/users.py", start: 24, end: 25 }, 3, 1),
    ]);
    expect(folded).toHaveLength(1);
    expect(folded[0]).toMatchObject({ fingerprint: "a", count: 5, scans: 3, similar: 1 });
  });
  it("does not fold groups in another file, another category, or without a location", () => {
    const folded = foldSimilarGroups([
      group("a", { title: "SQL injection in user lookup", category: "sql-injection", path: "a.py", start: 10, end: 12 }),
      group("b", { title: "SQL injection in user lookup", category: "sql-injection", path: "b.py", start: 10, end: 12 }),
      group("c", { title: "Passwords stored in plaintext", category: "other", path: "a.py", start: 10, end: 12 }),
      group("d", { title: "SQL injection in user lookup", category: "sql-injection" }),
    ]);
    expect(folded.map(g => g.fingerprint)).toEqual(["a", "b", "c", "d"]);
  });
  it("never folds a suppressed group into a new one", () => {
    const folded = foldSimilarGroups([
      group("a", { title: "Open redirect at learn route", category: "open-redirect", path: "r.js", start: 70, end: 72 }),
      group("b", { title: "Open redirect at learn route", category: "open-redirect", path: "r.js", start: 70, end: 72, triageStatus: "suppressed" }),
    ]);
    expect(folded).toHaveLength(2);
  });
  it("keeps groups apart when their lines do not overlap", () => {
    const folded = foldSimilarGroups([
      group("a", { title: "Stored XSS in the users page", category: "xss", path: "u.ejs", start: 40, end: 40 }),
      group("b", { title: "Reflected XSS in search", category: "xss", path: "u.ejs", start: 80, end: 80 }),
    ]);
    expect(folded).toHaveLength(2);
  });
});
