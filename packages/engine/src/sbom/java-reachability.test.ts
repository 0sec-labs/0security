import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { assessJavaDependencyReachability, dependencyReachabilityToText, mavenComponents } from "./java-reachability.js";
import { advisoriesToSarif, advisoriesToText } from "./check-report.js";
import type { Advisory } from "./osv.js";
const dirs: string[] = [];
afterEach(() => dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true })));
function source(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "0-reach-")); dirs.push(dir);
  for (const [path, text] of Object.entries(files)) { mkdirSync(join(dir, path, ".."), { recursive: true }); writeFileSync(join(dir, path), text); }
  return dir;
}
const purl = (name: string) => `pkg:maven/org.example/${name}@1.0`;
const bom = {
  components: ["entry", "transitive", "unused", "testlib"].map(name => ({ purl: purl(name), "bom-ref": name })),
  dependencies: [{ ref: "entry", dependsOn: ["transitive"] }, { ref: "transitive", dependsOn: ["entry"] }, { ref: "testlib", dependsOn: ["transitive"] }],
};
describe("JVM dependency evidence", () => {
  it("follows resolved graph aliases through a cycle while keeping vulnerable code unknown", () => {
    const folder = source({ "src/main/java/App.java": "import org.example.entry.Client;", "src/test/java/Test.java": "import org.example.testlib.Helper;" });
    const report = assessJavaDependencyReachability(folder, bom);
    const transitive = report.components.find(item => item.purl === purl("transitive"))!;
    expect(transitive).toMatchObject({ evidence: "dependency-path", vulnerableCode: "unknown", source: "main", dependencyPath: [purl("entry"), purl("transitive")] });
    expect(transitive.imports[0]).toMatchObject({ path: "src/main/java/App.java", line: 1 });
    expect(report.components.find(item => item.purl === purl("testlib"))).toMatchObject({ evidence: "source-import", source: "test", vulnerableCode: "unknown" });
    // Group-prefix matching may nominate siblings; it must stay explicitly heuristic.
    expect(report.components.every(item => item.vulnerableCode === "unknown")).toBe(true);
    expect(dependencyReachabilityToText(report.components)).toContain("not vulnerable-method reachability");
  });
  it("does not equate no import or missing graph with unreachable", () => {
    const report = assessJavaDependencyReachability(source({ "App.java": "class App {}" }), bom);
    expect(report.components.every(item => item.evidence === "none" && item.vulnerableCode === "unknown")).toBe(true);
    expect(report.components[0]!.rationale).toContain("Reflection");
  });
  it("exposes incomplete source scans rather than treating oversized files as checked", () => {
    const report = assessJavaDependencyReachability(source({ "App.java": " ".repeat(2 * 1024 * 1024 + 1) }), bom);
    expect(report.usage).toMatchObject({ truncated: true, filesScanned: 0 });
  });
  it("ignores malformed Maven identities and does not execute source", () => {
    expect(mavenComponents({ components: [{ purl: "pkg:maven/a/b@1%zz" }, { purl: "pkg:npm/other@1" }, { purl: "pkg:maven/a%2Fb/c@1" }] })).toEqual([]);
  });
  it("preserves advisory severity and evidence across text and SARIF", () => {
    const evidence = assessJavaDependencyReachability(source({}), bom).components[0]!;
    const advisory: Advisory = { purl: evidence.purl, id: "GHSA-example", aliases: [], summary: "example", severity: "critical", malicious: false, fixed: [], reachability: evidence };
    const sarif = advisoriesToSarif([advisory], { toolVersion: "test", locate: () => "pom.xml" }) as any;
    expect(sarif.runs[0].results[0]).toMatchObject({ level: "error", properties: { severity: "critical", reachability: { vulnerableCode: "unknown", evidence: "none" } } });
    expect(advisoriesToText([advisory], 1)).toContain("vulnerable-code reachability: unknown");
  });
});
