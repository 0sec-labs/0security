import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Finding } from "@0/engine/shared";
import { buildSheet, checkSheetFolder, commandLineOf, coverageStatement, csvCell, CSV_COLUMNS, reviewCsv, sheetFindings, sheetRunOf, verdictOf, writeSheet, type SheetRun } from "./evaluation-sheet.js";
import type { ScanOutcome } from "./scan-report.js";

const finding = (id: string, over: Partial<Finding> = {}): Finding => ({
  id, templateId: "manual", title: `Finding ${id}`, description: `Description of ${id}`, severity: "medium", category: "xss", status: "discovered", timestamp: 1,
  evidence: { request: "", response: "", analysis: "" }, reviewAnnotation: { path: "src/a.ts", startLine: 10 }, ...over,
}) as Finding;

const run: SheetRun = { source: "scan", generatedAt: "2026-01-01T00:02:00.000Z", command: "0security scan . --model m", cliVersion: "9.9.9", target: "repo", commit: "abc123", model: "m", costUsd: 0.1234, budgetUsd: 0.3, durationMs: 61500, status: "complete", coverage: "Opened 3 of 3 source files in scope.", scanners: [{ id: "foxguard", version: "foxguard 1.2.3" }] };

// A small RFC 4180 reader, so the tests check what a spreadsheet would see rather than the writer's own view.
function parseCsv(text: string): string[][] {
  const rows: string[][] = []; let row: string[] = []; let cell = ""; let quoted = false;
  const body = text.replace(/^﻿/, "");
  for (let i = 0; i < body.length; i++) {
    const c = body[i]!;
    if (quoted) { if (c === '"') { if (body[i + 1] === '"') { cell += '"'; i++; } else quoted = false; } else cell += c; }
    else if (c === '"') quoted = true;
    else if (c === ",") { row.push(cell); cell = ""; }
    else if (c === "\r" && body[i + 1] === "\n") { row.push(cell); rows.push(row); row = []; cell = ""; i++; }
    else cell += c;
  }
  if (cell || row.length) { row.push(cell); rows.push(row); }
  return rows;
}
const col = (name: (typeof CSV_COLUMNS)[number]): number => CSV_COLUMNS.indexOf(name);

describe("csvCell", () => {
  it("prefixes every cell a spreadsheet could read as a formula", () => {
    for (const lead of ["=", "+", "-", "@", "\t", "\r"]) expect(csvCell(`${lead}SUM(A1)`).replace(/^"|"$/g, "").startsWith("'")).toBe(true);
    expect(csvCell("=HYPERLINK(\"http://x\",\"y\")")).toBe(`"'=HYPERLINK(""http://x"",""y"")"`);
  });
  it("leaves ordinary text alone and quotes commas, quotes and line breaks", () => {
    expect(csvCell("plain")).toBe("plain");
    expect(csvCell("a,b")).toBe('"a,b"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell("one\ntwo")).toBe('"one\ntwo"');
    expect(csvCell("one\r\ntwo")).toBe('"one\r\ntwo"');
    expect(csvCell(null)).toBe("");
    expect(csvCell(7)).toBe("7");
  });
  it("does not prefix text that only contains a formula character", () => {
    expect(csvCell("a=b")).toBe("a=b");
    expect(csvCell("x-y")).toBe("x-y");
  });
});

describe("review.csv", () => {
  it("round-trips injected, quoted and multi-line text, with the formula characters neutralised", () => {
    const rows = sheetFindings([finding("a", { title: "=cmd|' /C calc'!A0", description: "+1\nline two, with \"quotes\"", reviewAnnotation: { path: "@evil,path.ts", startLine: 3, fixExplanation: "-2+3" } })]);
    const parsed = parseCsv(reviewCsv(rows, "f".repeat(64)));
    expect(parsed[0]).toEqual([...CSV_COLUMNS]);
    expect(parsed[1]).toHaveLength(CSV_COLUMNS.length);
    expect(parsed[1]![col("title")]).toBe("'=cmd|' /C calc'!A0");
    expect(parsed[1]![col("description")]).toBe("'+1\nline two, with \"quotes\"");
    expect(parsed[1]![col("location")]).toBe("'@evil,path.ts:3");
    expect(parsed[1]![col("fix explanation")]).toBe("'-2+3");
    // No data cell starts with a formula character.
    for (const cell of parsed.slice(1).flat()) expect(cell).not.toMatch(/^[=+\-@\t\r]/);
  });
  it("leaves the four judgement columns blank and carries the short list hash", () => {
    const sheet = buildSheet([finding("a"), finding("b", { reviewAnnotation: { path: "src/b.ts", startLine: 1 } })], run);
    const parsed = parseCsv(sheet.files.find(f => f.name === "review.csv")!.text);
    for (const row of parsed.slice(1)) {
      for (const name of ["true positive", "false positive", "unsure", "notes"] as const) expect(row[col(name)]).toBe("");
      expect(row[col("list hash")]).toBe(sheet.findingsSha256.slice(0, 16));
    }
  });
  it("keeps unicode intact and starts with a byte order mark", () => {
    const text = reviewCsv(sheetFindings([finding("u", { title: "Injection dans le système — 日本語 \u{1F512}", reviewAnnotation: { path: "src/日本語.ts", startLine: 2 } })]), "0".repeat(64));
    expect(text.startsWith("﻿")).toBe(true);
    const row = parseCsv(text)[1]!;
    expect(row[col("title")]).toBe("Injection dans le système — 日本語 \u{1F512}");
    expect(row[col("location")]).toBe("src/日本語.ts:2");
  });
  it("uses CRLF between records", () => {
    expect(reviewCsv(sheetFindings([finding("a")]), "0".repeat(64)).split("\r\n")).toHaveLength(3);
  });
});

describe("ordering and ids", () => {
  const mixed = [
    finding("low", { severity: "low", reviewAnnotation: { path: "a.ts", startLine: 1 } }),
    finding("c2", { severity: "critical", reviewAnnotation: { path: "b.ts", startLine: 5 } }),
    finding("c1", { severity: "critical", reviewAnnotation: { path: "b.ts", startLine: 2 } }),
    finding("c0", { severity: "critical", reviewAnnotation: { path: "a.ts", startLine: 99 } }),
    finding("high", { severity: "high", reviewAnnotation: { path: "z.ts", startLine: 1 } }),
    finding("cn", { severity: "critical", reviewAnnotation: undefined }),
  ];
  it("orders by severity, then path, then line, with a finding that has no location last in its severity", () => {
    expect(sheetFindings(mixed).map(r => r.findingId)).toEqual(["c0", "c1", "c2", "cn", "high", "low"]);
  });
  it("gives the same order and the same ids whatever order the findings arrive in", () => {
    const a = sheetFindings(mixed), b = sheetFindings([...mixed].reverse());
    expect(b).toEqual(a);
    expect(new Set(a.map(r => r.id)).size).toBe(a.length);
    expect(a.every(r => /^F[0-9a-f]{8}$/.test(r.id))).toBe(true);
  });
  it("keeps an id when unrelated findings are added or removed", () => {
    const before = sheetFindings(mixed).find(r => r.findingId === "high")!.id;
    const after = sheetFindings([...mixed.slice(0, 3), finding("extra", { severity: "info" })].concat(mixed.slice(4))).find(r => r.findingId === "high")!.id;
    expect(after).toBe(before);
  });
  it("tells identical findings apart", () => {
    const rows = sheetFindings([finding("x1", { title: "same" }), finding("x2", { title: "same" })]);
    expect(rows.map(r => r.id)[1]).toBe(`${rows[0]!.id}-2`);
  });
  it("sorts unknown severities after the known ones", () => {
    expect(sheetFindings([finding("w", { severity: "weird" as never }), finding("i", { severity: "info" })]).map(r => r.findingId)).toEqual(["i", "w"]);
  });
});

describe("findings without a location", () => {
  it("is listed, says so, and has no path or line", () => {
    const sheet = buildSheet([finding("n", { reviewAnnotation: undefined })], run);
    expect(sheet.findings[0]!.location).toBeNull();
    const row = parseCsv(sheet.files.find(f => f.name === "review.csv")!.text)[1]!;
    expect(row[col("location")]).toBe("(no location recorded)");
  });
  it("drops a path that points outside the scanned folder", () => {
    expect(sheetFindings([finding("o", { reviewAnnotation: { path: "../../etc/passwd", startLine: 1 } })], ["/work/repo"])[0]!.location).toBeNull();
  });
  it("makes a path relative to the scanned folder", () => {
    expect(sheetFindings([finding("r", { reviewAnnotation: { path: "/work/repo/src/x.ts", startLine: 4, endLine: 6 } })], ["/work/repo"])[0]!.location).toEqual({ path: "src/x.ts", startLine: 4, endLine: 6 });
  });
});

describe("verdict and fix explanation", () => {
  it("says not verified when nothing checked the finding", () => {
    expect(verdictOf(finding("a"))).toBe("not verified");
    expect(verdictOf(finding("a", { executedPoc: { schemaVersion: 1, harness: "0security-executed-poc/1", outcome: "static-only", reason: "no-sandbox-image", stepIds: [], startedAt: "", finishedAt: "" } as never }))).toBe("not verified");
  });
  it("reports the check that ran, without calling a script match proof", () => {
    expect(verdictOf(finding("a", { executedPoc: { outcome: "script-matched" } as never }))).toMatch(/^script matched.*not proof/);
    expect(verdictOf(finding("a", { executedPoc: { outcome: "script-unmatched" } as never }))).toMatch(/does not show the finding is false/);
    expect(verdictOf(finding("a", { reproduction: { result: { status: "reproduced" } } as never }))).toMatch(/^reproduced/);
    expect(verdictOf(finding("a", { sourceVerification: { status: "matched" } as never }))).toMatch(/^source check matched/);
  });
  it("carries the fix explanation, or says none was recorded", () => {
    const sheet = buildSheet([finding("a", { reviewAnnotation: { path: "a.ts", startLine: 1, fixExplanation: "Bind the id as a parameter." } }), finding("b", { reviewAnnotation: { path: "b.ts", startLine: 1 } })], run);
    const rows = parseCsv(sheet.files.find(f => f.name === "review.csv")!.text);
    expect(rows[1]![col("fix explanation")]).toBe("Bind the id as a parameter.");
    expect(rows[2]![col("fix explanation")]).toBe("none recorded");
    expect(rows[1]![col("verification verdict")]).toBe("not verified");
  });
});

describe("business context rank", () => {
  const context = (shift: number, score: number) => ({ provenance: "operator", repository: "o/r", tags: ["payments"], notes: [], shift, score, rationale: "r" });
  it("ranks by the declared order without changing severity or the sheet order", () => {
    const rows = sheetFindings([
      finding("low-pay", { severity: "low", businessContext: context(2, 3) as never, reviewAnnotation: { path: "a.ts", startLine: 1 } }),
      finding("med", { severity: "medium", businessContext: context(0, 1) as never, reviewAnnotation: { path: "b.ts", startLine: 1 } }),
    ]);
    expect(rows.map(r => r.findingId)).toEqual(["med", "low-pay"]);
    expect(Object.fromEntries(rows.map(r => [r.findingId, r.businessContext?.rank]))).toEqual({ med: 2, "low-pay": 1 });
    expect(rows.map(r => r.severity)).toEqual(["medium", "low"]);
  });
  it("says none declared without a context, and not set for a finding the context did not reach", () => {
    expect(parseCsv(reviewCsv(sheetFindings([finding("a")]), "0".repeat(64)))[1]![col("business context rank")]).toBe("none declared");
    const rows = parseCsv(reviewCsv(sheetFindings([finding("a", { businessContext: context(1, 1) as never }), finding("b", { reviewAnnotation: { path: "z.ts", startLine: 1 } })]), "0".repeat(64)));
    expect(rows[1]![col("business context rank")]).toBe("1");
    expect(rows[2]![col("business context rank")]).toBe("not set");
  });
});

describe("empty scan", () => {
  it("still writes every file, with a header-only CSV and a README that says an empty sheet is not a clean result", () => {
    const sheet = buildSheet([], run);
    expect(sheet.files.map(f => f.name)).toEqual(["README.md", "review.csv", "findings.json", "run.json"]);
    expect(parseCsv(sheet.files[1]!.text)).toEqual([[...CSV_COLUMNS]]);
    expect(JSON.parse(sheet.files[2]!.text).count).toBe(0);
    expect(sheet.files[0]!.text).toContain("An empty sheet is not a clean result");
  });
});

describe("hash, README and run facts", () => {
  const sheet = buildSheet([finding("a"), finding("b", { severity: "high" })], run);
  const text = (name: string) => sheet.files.find(f => f.name === name)!.text;
  it("hashes findings.json and records the hash in the README, run.json and the CSV", () => {
    const expected = createHash("sha256").update(text("findings.json")).digest("hex");
    expect(sheet.findingsSha256).toBe(expected);
    expect(text("README.md")).toContain(expected);
    expect(JSON.parse(text("run.json")).findings.sha256).toBe(expected);
  });
  it("gives the same hash for the same findings, and another for a changed one", () => {
    expect(buildSheet([finding("b", { severity: "high" }), finding("a")], { ...run, generatedAt: "later" }).findingsSha256).toBe(sheet.findingsSha256);
    expect(buildSheet([finding("a"), finding("b", { severity: "high", title: "changed" })], run).findingsSha256).not.toBe(sheet.findingsSha256);
  });
  it("says plainly that the sheet is for human judgement and not an accuracy result", () => {
    expect(text("README.md")).toContain("This sheet is for human judgement. It is not an accuracy result.");
  });
  it("records the command, CLI version, commit, model, scanner version, cost, time and coverage", () => {
    const readme = text("README.md");
    for (const part of ["0security scan . --model m", "9.9.9", "abc123", "`m`", "foxguard 1.2.3", "$0.1234", "(budget $0.3)", "61.5 s", "Opened 3 of 3 source files in scope."]) expect(readme).toContain(part);
    expect(JSON.parse(text("run.json"))).toMatchObject({ command: "0security scan . --model m", cliVersion: "9.9.9", repository: { commit: "abc123" }, model: "m", costUsd: 0.1234, durationMs: 61500 });
  });
  it("writes not recorded for what a stored sheet does not know", () => {
    const stored = buildSheet([], { source: "stored", generatedAt: "t", command: "0security findings export", cliVersion: "1" });
    expect(stored.files[0]!.text).toContain("Model: not recorded");
    expect(stored.files[0]!.text).toContain("rebuilt from stored findings");
    expect(JSON.parse(stored.files[3]!.text).model).toBeNull();
  });
  it("does not claim a model reviewed a pre-pass-only or empty-diff scan", () => {
    const outcome: ScanOutcome = { target: "repo", threadId: "none", startedAt: "2026-01-01T00:00:00.000Z", completedAt: "2026-01-01T00:00:00.000Z", budgetUsd: 1, budgetExhausted: false, failed: false };
    const r = sheetRunOf({ outcome, command: "c", cliVersion: "1", now: new Date(0), model: "m" });
    expect(r.model).toBeUndefined();
    expect(r.coverage).toBe("Nothing was scanned.");
  });
});

describe("coverageStatement", () => {
  const base: ScanOutcome = { target: "repo", threadId: "t", startedAt: "a", completedAt: "b", budgetUsd: 2, budgetExhausted: false, failed: false };
  it("uses the batch statement and says when the budget stopped the scan", () => {
    expect(coverageStatement({ ...base, budgetExhausted: true, coverage: { statement: "reviewed 41 of 57 entry points; 16 not reached (budget)" } as never })).toBe("reviewed 41 of 57 entry points; 16 not reached (budget). Stopped at the $2 budget; findings are partial.");
  });
  it("counts the files a single thread opened", () => {
    expect(coverageStatement({ ...base, fileCoverage: { inScope: 10, opened: 7, unopened: [], unopenedCount: 3, rounds: { allowed: 1, used: 0 } } })).toBe("The scan opened 7 of 10 source files in scope; 3 not opened.");
  });
});

describe("commandLineOf", () => {
  it("quotes what a shell would split or expand", () => {
    expect(commandLineOf(["scan", "my repo", "--model", "gpt", "it's"])).toBe("0security scan 'my repo' --model gpt 'it'\\''s'");
  });
});

describe("a large scan", () => {
  it("builds 5000 findings quickly, in order, with unique ids and a row per finding", () => {
    const many = Array.from({ length: 5000 }, (_, i) => finding(`id${i}`, { severity: (["critical", "high", "medium", "low", "info"] as const)[i % 5]!, title: `Issue ${i % 700}`, reviewAnnotation: i % 97 === 0 ? undefined : { path: `src/m${i % 40}/f${i % 13}.ts`, startLine: (i * 7) % 300 + 1 } }));
    const started = Date.now();
    const sheet = buildSheet(many, run);
    expect(Date.now() - started).toBeLessThan(5000);
    expect(new Set(sheet.findings.map(r => r.id)).size).toBe(5000);
    expect(parseCsv(sheet.files[1]!.text)).toHaveLength(5001);
    const order = ["critical", "high", "medium", "low", "info"];
    for (let i = 1; i < sheet.findings.length; i++) {
      const a = sheet.findings[i - 1]!, b = sheet.findings[i]!;
      expect(order.indexOf(a.severity)).toBeLessThanOrEqual(order.indexOf(b.severity));
    }
  });
});

describe("the folder", () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "0-sheet-")); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });
  const sheet = buildSheet([finding("a")], run);

  it("writes a new folder and an existing empty one", () => {
    writeSheet(join(dir, "new"), sheet, false);
    expect(readdirSync(join(dir, "new")).sort()).toEqual(["README.md", "findings.json", "review.csv", "run.json"]);
    mkdirSync(join(dir, "empty"));
    writeSheet(join(dir, "empty"), sheet, false);
    expect(existsSync(join(dir, "empty", "review.csv"))).toBe(true);
  });
  it("refuses a non-empty folder and changes nothing in it", () => {
    writeFileSync(join(dir, "mine.txt"), "keep");
    expect(() => writeSheet(dir, sheet, false)).toThrow(/not empty/);
    expect(readdirSync(dir)).toEqual(["mine.txt"]);
  });
  it("replaces only the sheet files when asked, and leaves the other files", () => {
    writeFileSync(join(dir, "mine.txt"), "keep");
    writeFileSync(join(dir, "review.csv"), "old");
    writeSheet(dir, sheet, true);
    expect(readFileSync(join(dir, "mine.txt"), "utf8")).toBe("keep");
    expect(readFileSync(join(dir, "review.csv"), "utf8")).not.toBe("old");
  });
  it("refuses a symbolic link, a file, a missing parent and a link in place of a sheet file", () => {
    mkdirSync(join(dir, "real"));
    symlinkSync(join(dir, "real"), join(dir, "link"));
    expect(() => checkSheetFolder(join(dir, "link"), true)).toThrow(/symbolic link/);
    writeFileSync(join(dir, "file"), "x");
    expect(() => checkSheetFolder(join(dir, "file"), true)).toThrow(/not a folder/);
    expect(() => checkSheetFolder(join(dir, "no", "such", "x"), false)).toThrow(/parent/);
    symlinkSync(join(dir, "file"), join(dir, "real", "review.csv"));
    expect(() => writeSheet(join(dir, "real"), sheet, true)).toThrow(/not a regular file/);
    expect(readFileSync(join(dir, "file"), "utf8")).toBe("x");
  });
});
