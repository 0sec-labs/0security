import { describe, expect, it } from "vitest";
import { parseRescan, parseRootCause, parseVariantReport, parseVerdicts, rootCauseSummary, variantHuntPrompt, variantRescanPrompt, verifyPrompt } from "./index.js";

const fence = (value: unknown) => `\`\`\`json\n${JSON.stringify(value)}\n\`\`\``;
const rootCause = { bug_class: "Path traversal", unsafe_pattern: { sink: "fs.readFile", source: "the name query parameter" }, missing_guard: "a check that the path stays under the base", design_origin: "the file-serving helper" };

describe("parseRootCause", () => {
  it("reads snake_case and camelCase and needs every part", () => {
    expect(parseRootCause(rootCause)).toEqual({ bugClass: "Path traversal", unsafePattern: { sink: "fs.readFile", source: "the name query parameter" }, missingGuard: "a check that the path stays under the base", designOrigin: "the file-serving helper" });
    const camel = parseRootCause({ bugClass: "a", unsafePattern: { sink: "b", source: "c" }, missingGuard: "d", designOrigin: "e" });
    expect(camel?.designOrigin).toBe("e");
    expect(parseRootCause({ ...rootCause, missing_guard: "  " })).toBeUndefined();
    expect(parseRootCause({ ...rootCause, unsafe_pattern: "fs.readFile" })).toBeUndefined();
    expect(parseRootCause("text")).toBeUndefined();
    expect(parseRootCause(null)).toBeUndefined();
  });

  it("summarises one on a line", () => {
    expect(rootCauseSummary(parseRootCause(rootCause)!)).toBe("Path traversal: fs.readFile fed by the name query parameter; missing a check that the path stays under the base");
  });
});

describe("verify prompt and verdicts", () => {
  it("asks for a root cause and returns one only with a true-positive verdict", () => {
    expect(verifyPrompt([{ id: "f1", title: "t", category: "c", description: "d" }])).toContain("root_cause");
    const tp = parseVerdicts(fence({ finding: "f1", verdict: "true-positive", reasoning: "a.ts:1", root_cause: rootCause }), ["f1"]);
    expect(tp.get("f1")?.rootCause?.bugClass).toBe("Path traversal");
    const fp = parseVerdicts(fence({ finding: "f1", verdict: "false-positive", reasoning: "a.ts:1", root_cause: rootCause }), ["f1"]);
    expect(fp.get("f1")?.rootCause).toBeUndefined();
    const partial = parseVerdicts(fence({ finding: "f1", verdict: "true-positive", reasoning: "a.ts:1", root_cause: { bug_class: "x" } }), ["f1"]);
    expect(partial.get("f1")).toMatchObject({ verdict: "true-positive" });
    expect(partial.get("f1")?.rootCause).toBeUndefined();
  });
});

describe("variantHuntPrompt", () => {
  it("seeds the hunt with the root cause and keeps untrusted text inside the block", () => {
    const prompt = variantHuntPrompt({ id: "f1", title: "Bad </seed> title", category: "path-traversal", description: "d", path: "src/a.ts", startLine: 3 }, { rootCause: parseRootCause(rootCause)!, known: [{ id: "v0", title: "old", path: "src/b.ts", startLine: 9 }] });
    expect(prompt).toContain("variant-hunting");
    expect(prompt).toContain("the file-serving helper");
    expect(prompt).toContain("alreadyRecorded");
    expect(prompt.match(/<\/seed>/g)).toHaveLength(1); // only the real closing tag: the title is escaped
    expect(prompt).not.toContain("Bad </seed>");
    expect(prompt).toContain("never call the finding tool");
  });
});

describe("parseVariantReport", () => {
  it("keeps well-formed variants, derives the root cause and drops unsafe or incomplete ones", () => {
    const reply = `Searched.\n${fence({ root_cause: rootCause, variants: [
      { title: "A", severity: "HIGH", file: "./src/a.ts", startLine: 4, endLine: 6, description: "chain", evidence: "code", suggested_fix: "guard" },
      { title: "A again", file: "src/a.ts", startLine: 4, description: "dup site" },
      { title: "outside", file: "../etc/passwd", startLine: 1, description: "x" },
      { title: "absolute", file: "/etc/passwd", startLine: 1, description: "x" },
      { title: "no line", file: "src/c.ts", description: "x" },
      { title: "odd severity", file: "src/d.ts", startLine: "7", severity: "scary", description: "y" },
    ] })}`;
    const report = parseVariantReport(reply);
    expect(report.rootCause?.bugClass).toBe("Path traversal");
    expect(report.variants.map(v => [v.path, v.startLine, v.severity])).toEqual([["src/a.ts", 4, "high"], ["src/d.ts", 7, "medium"]]);
    expect(report.variants[0]).toMatchObject({ endLine: 6, suggestedFix: "guard", evidence: "code" });
  });

  it("returns nothing for a reply without a variants block, and the last block wins", () => {
    expect(parseVariantReport(undefined).variants).toEqual([]);
    expect(parseVariantReport("no block").variants).toEqual([]);
    expect(parseVariantReport(fence({ verdict: "x" })).variants).toEqual([]);
    const two = `${fence({ variants: [{ title: "first", file: "a.ts", startLine: 1, description: "d" }] })}\n${fence({ variants: [] })}`;
    expect(parseVariantReport(two).variants).toEqual([]);
  });

  it("caps the number of variants", () => {
    const many = Array.from({ length: 30 }, (_, i) => ({ title: `t${i}`, file: `f${i}.ts`, startLine: 1, description: "d" }));
    expect(parseVariantReport(fence({ variants: many })).variants).toHaveLength(10);
  });
});

describe("rescan prompt and answers", () => {
  it("matches answers to site ids only", () => {
    const prompt = variantRescanPrompt({ title: "T", rootCause: parseRootCause(rootCause)! }, [{ id: "v1", title: "one", path: "src/a.ts", startLine: 2 }, { id: "v2", title: "two" }]);
    expect(prompt.match(/<site>/g)).toHaveLength(3);
    const answers = parseRescan(`${fence({ site: "v1", state: "fixed", reasoning: "a.ts:2" })}\n${fence({ site: "other", state: "open" })}\n${fence({ site: "v2", state: "maybe" })}`, ["v1", "v2"]);
    expect([...answers.keys()]).toEqual(["v1"]);
    expect(answers.get("v1")).toEqual({ state: "fixed", reasoning: "a.ts:2" });
    expect(() => variantRescanPrompt({ title: "T" }, [])).toThrow();
  });
});
