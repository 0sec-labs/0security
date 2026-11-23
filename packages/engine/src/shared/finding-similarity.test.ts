import { describe, expect, it } from "vitest";
import { sameFlaw, titleSimilarity, type SimilarityInput } from "./finding-similarity.js";

const at = (title: string, category: string, path: string, start: number, end?: number, extra: Partial<SimilarityInput> = {}): SimilarityInput => ({ title, category, location: { path, startLine: start, ...(end ? { endLine: end } : {}) }, ...extra });

describe("sameFlaw on pairs from real scans", () => {
  it("merges one flaw reported under two labels once the categories are normalized", () => {
    // The same ownership check, filed as information-disclosure by one batch and missing-validation by another.
    expect(sameFlaw(at("Book lookup omits ownership authorization", "information-disclosure", "api_views/books.py", 50, 51), at("Authenticated users can read other users' book secrets", "missing-validation", "api_views/books.py", 50, 56))).toBe(true);
    // A hardcoded signing key labelled two ways.
    expect(sameFlaw(at("Known hardcoded JWT signing key allows token forgery", "security-misconfiguration", "config.py", 13, 13), at("Hard-coded JWT signing key enables token forgery", "information-disclosure", "config.py", 13, 13))).toBe(true);
    // The unauthenticated database reset.
    expect(sameFlaw(at("Unauthenticated database reset via GET /createdb", "security-misconfiguration", "api_views/main.py", 6, 9), at("Unauthenticated database reset destroys application data", "missing-validation", "api_views/main.py", 6, 9))).toBe(true);
  });
  it("merges overlapping findings in one category whatever the wording", () => {
    expect(sameFlaw(at("Public registration permits attacker-created administrator accounts", "missing-validation", "api_views/users.py", 59, 66), at("Unauthenticated registration accepts caller-controlled admin privilege", "other", "api_views/users.py", 60, 66))).toBe(true);
  });
  it("never merges across files", () => {
    expect(sameFlaw(at("SQL injection in user lookup", "sql-injection", "a.py", 10, 12), at("SQL injection in user lookup", "sql-injection", "b.py", 10, 12))).toBe(false);
  });
  it("never merges different categories on the same lines", () => {
    expect(sameFlaw(at("SQL injection in user lookup", "sql-injection", "models/user_model.py", 71, 74), at("User passwords are stored and compared in plaintext", "other", "models/user_model.py", 71, 74))).toBe(false);
  });
  it("merges different categories that share a CWE", () => {
    const analysis = "CWE: CWE-798\n\nthe key is in source";
    expect(sameFlaw(at("Weird flaw", "sql-injection", "x.py", 5, 6, { evidenceAnalysis: analysis }), at("Another word", "xss", "x.py", 5, 6, { cwe: ["CWE-798"] }))).toBe(true);
  });
  it("keeps both when the lines do not overlap and the titles differ", () => {
    expect(sameFlaw(at("Shell command injection in db-reset task", "command-injection", "Gruntfile.js", 159, 159), at("Unquoted argument reaches exec", "command-injection", "Gruntfile.js", 163, 163))).toBe(false);
    expect(sameFlaw(at("Stored XSS in the users page", "xss", "views/users.ejs", 40, 40), at("Reflected XSS in search", "xss", "views/users.ejs", 80, 80))).toBe(false);
  });
  it("merges near lines only when the titles read alike", () => {
    expect(sameFlaw(at("SQL injection in username lookup", "sql-injection", "m.py", 72, 73), at("SQL injection in user lookup", "sql-injection", "m.py", 75, 76))).toBe(true);
    expect(sameFlaw(at("SQL injection in username lookup", "sql-injection", "m.py", 72, 73), at("Query log leaks user names", "sql-injection", "m.py", 75, 76))).toBe(false);
  });
  it("needs agreeing titles when a cited range is as wide as a file", () => {
    expect(sameFlaw(at("Stored XSS in profile page", "xss", "app.js", 1, 400), at("Reflected XSS in search box", "xss", "app.js", 120, 121))).toBe(false);
    expect(sameFlaw(at("Stored XSS in profile page", "xss", "app.js", 1, 400), at("Stored XSS in the profile page", "xss", "app.js", 120, 121))).toBe(true);
  });
  it("does not merge findings with no location", () => {
    expect(sameFlaw({ title: "a", category: "xss" }, { title: "a", category: "xss" })).toBe(false);
  });
});

describe("titleSimilarity", () => {
  it("is high for the same words in another order and zero for unrelated titles", () => {
    expect(titleSimilarity("Authenticated user can change another user's password", "Authenticated users can change another account's password")).toBeGreaterThan(0.4);
    expect(titleSimilarity("Open redirect in learn route", "Catastrophic backtracking in routing regex")).toBe(0);
    expect(titleSimilarity("", "x")).toBe(0);
  });
});
