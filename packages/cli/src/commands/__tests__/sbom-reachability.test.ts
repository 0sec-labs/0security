import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCheck, runJavaReachability, type SbomDeps } from "../sbom.js";
const dirs: string[] = [];
afterEach(() => dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true })));
function setup() {
  const root = mkdtempSync(join(tmpdir(), "0-check-source-")); dirs.push(root);
  mkdirSync(join(root, "src/main/java"), { recursive: true });
  writeFileSync(join(root, "src/main/java/App.java"), "import org.apache.commons.text.StringSubstitutor;\nclass App {}\n");
  const purl = "pkg:maven/org.apache.commons/commons-text@1.9";
  const bom = JSON.stringify({ components: [{ purl, "bom-ref": "text" }, { purl: "pkg:maven/org.apache.commons/commons-lang3@3.11", "bom-ref": "lang" }], dependencies: [{ ref: "text", dependsOn: ["lang"] }] });
  const out: string[] = []; const err: string[] = [];
  const deps: SbomDeps = { out: text => out.push(text), err: text => err.push(text), read: () => bom, write: () => {}, fetch: (async url => new Response(JSON.stringify(String(url).includes("querybatch") ? { results: [{ vulns: [{ id: "GHSA-test" }] }, {}] } : { id: "GHSA-test", summary: "test", database_specific: { severity: "HIGH" }, affected: [] }))) as typeof fetch };
  return { root, purl, out, err, deps };
}
describe("sbom reachability evidence in the command path", () => {
  it("inspects a dependency path offline without calling OSV", () => {
    const io = setup(); io.deps.fetch = async () => { throw new Error("must stay offline"); };
    runJavaReachability("bom.json", io.root, { format: "json" }, io.deps);
    const report = JSON.parse(io.out.join(""));
    expect(report.components[1]).toMatchObject({ evidence: "dependency-path", source: "main", vulnerableCode: "unknown" });
  });
  it.each(["json", "sarif", "text"])("attaches source evidence to %s while keeping advisory exit 1", async format => {
    const io = setup();
    expect(await runCheck("bom.json", { format, source: io.root }, io.deps)).toBe(1);
    const output = io.out.join("");
    if (format === "text") expect(output).toContain("vulnerable-code reachability: unknown");
    else {
      const result = JSON.parse(output);
      const advisory = format === "json" ? result.advisories[0] : result.runs[0].results[0].properties;
      expect(advisory.reachability).toMatchObject({ evidence: "source-import", vulnerableCode: "unknown", source: "main" });
      expect(advisory.reachability.imports[0]).toMatchObject({ path: "src/main/java/App.java", line: 1 });
    }
  });
  it("validates the source folder before attempting any advisory lookup", async () => {
    const io = setup(); io.deps.fetch = async () => { throw new Error("must not call"); };
    await expect(runCheck("bom.json", { source: join(io.root, "missing") }, io.deps)).rejects.toThrow("is not a folder");
  });
});
