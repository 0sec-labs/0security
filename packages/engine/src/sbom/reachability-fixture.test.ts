import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { findMatchingFindingCandidate } from "../agent/tools-helpers.js";
import { attachJavaUsage, type Advisory } from "./index.js";

/** The dependency-reachability regression folder: commons-text is called, snakeyaml is declared and never imported. */
const fixtureDir = join(import.meta.dirname, "fixtures", "reachability-skill");
interface Expected { id: string; title: string; severity: string; path: string; line: number }
const expected = (JSON.parse(readFileSync(join(fixtureDir, "expected-findings.json"), "utf8")) as { findings: Expected[] }).findings;
const lines = (file: string) => readFileSync(join(fixtureDir, file), "utf8").split("\n");

describe("dependency-reachability regression fixture", () => {
  it("expected findings point at the lines the fixture really has", () => {
    for (const finding of expected) {
      const text = lines(finding.path)[finding.line - 1] ?? "";
      expect(text, finding.id).toContain(finding.title.includes("commons-text") ? "StringSubstitutor" : "snakeyaml");
    }
  });

  it("source reading finds the called dependency and not the unused one", () => {
    const advisory = (purl: string, id: string): Advisory => ({ purl, id, aliases: [], summary: "", severity: "high", malicious: false, fixed: [] });
    const { advisories } = attachJavaUsage([
      advisory("pkg:maven/org.apache.commons/commons-text@1.9", "GHSA-599f-7c49-w659"),
      advisory("pkg:maven/org.yaml/snakeyaml@1.30", "GHSA-3mc7-4q67-w48m"),
    ], fixtureDir);
    expect(advisories[0]!.usage).toMatchObject({ status: "imported", locations: [{ path: "src/main/java/demo/App.java", line: 2, test: false }] });
    expect(advisories[1]!.usage).toMatchObject({ status: "not-imported", locations: [] });
  });

  it("the seven advisories on one manifest line and the called one all survive saving, and a repeat does not", () => {
    const kept: Array<{ id: string; title: string; category: string; evidenceRequest: string; reviewAnnotation: { path: string; startLine: number } }> = [];
    for (const finding of expected) {
      const incoming = { id: finding.id, title: finding.title, category: "supply-chain", evidenceRequest: "advisory check", reviewAnnotation: { path: finding.path, startLine: finding.line } };
      expect(findMatchingFindingCandidate(kept, incoming, { byLocation: true }), finding.id).toBeUndefined();
      kept.push(incoming);
    }
    expect(kept).toHaveLength(8);
    expect(expected.filter(item => item.title.startsWith("[not-reached]"))).toHaveLength(7);
    const again = { ...kept[1]!, id: "again", title: `${kept[1]!.title} (second pass)` };
    expect(findMatchingFindingCandidate(kept, again, { byLocation: true })?.id).toBe("f2");
  });
});
