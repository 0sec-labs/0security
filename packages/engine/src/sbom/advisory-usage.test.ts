import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { advisoriesToSarif, advisoriesToText, attachJavaUsage, checkBomAgainstOsv, scanJavaUsage, scanLimitText, usageSummary, type Advisory } from "./index.js";
import { vulnerableSymbolsFor, vulnerableSymbolsWithLimit } from "./advisory-facts.js";

const fixtures = join(import.meta.dirname, "fixtures", "usage");
const bom = JSON.parse(readFileSync(join(fixtures, "sbom.cdx.json"), "utf8"));
const records = JSON.parse(readFileSync(join(fixtures, "osv-records.hand-built.json"), "utf8")) as Record<string, unknown>;
const byPurl: Record<string, string[]> = {
  "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1": ["GHSA-jfh8-c2jp-5v3q"],
  "pkg:maven/org.apache.commons/commons-text@1.9": ["GHSA-599f-7c49-w659"],
  "pkg:maven/org.yaml/snakeyaml@1.30": ["GHSA-mjmj-j48q-9wg2"],
  "pkg:npm/lodash@4.17.20": ["GHSA-lodash"],
};
/** An OSV that answers from the hand-built records; no network. */
const fakeOsv = (async (url: string | URL | Request, init?: RequestInit) => {
  const text = String(url);
  if (text.endsWith("/v1/querybatch")) {
    const queries = (JSON.parse(String(init?.body)) as { queries: Array<{ package: { purl: string } }> }).queries;
    return new Response(JSON.stringify({ results: queries.map(query => ({ vulns: (byPurl[query.package.purl] ?? []).map(id => ({ id })) })) }));
  }
  const record = records[decodeURIComponent(text.split("/v1/vulns/")[1]!)];
  return record ? new Response(JSON.stringify(record)) : new Response("{}", { status: 404 });
}) as typeof fetch;
const check = async () => (await checkBomAgainstOsv(bom, { fetch: fakeOsv })).advisories;
const find = (list: Advisory[], id: string) => list.find(item => item.id === id)!;

describe("vulnerableSymbolsFor", () => {
  const purl = "pkg:maven/a.b/c@1";
  it("qualifies a bare class name with the entry path and keeps full names", () => {
    const affected = [{ package: { purl: "pkg:maven/a.b/c" }, ecosystem_specific: { imports: [{ path: "a.b.lookup", symbols: ["JndiLookup", "a.b.other.Thing", "Server.Serve"] }] } }];
    expect(vulnerableSymbolsFor(affected, purl)).toEqual(["a.b.lookup.JndiLookup", "a.b.lookup.Server.Serve", "a.b.other.Thing"]);
  });
  it("reads database_specific too and drops names it cannot qualify or that are not identifiers", () => {
    const affected = [{ database_specific: { imports: [{ symbols: ["Bare", "x.y.Z", "../../etc/passwd", "a.b.C; rm -rf /", 7, "a..b"] }] } }];
    expect(vulnerableSymbolsFor(affected, purl)).toEqual(["x.y.Z"]);
  });
  it("ignores entries about other packages and malformed data", () => {
    expect(vulnerableSymbolsFor([{ package: { purl: "pkg:maven/other/x" }, ecosystem_specific: { imports: [{ symbols: ["q.R"] }] } }, { ecosystem_specific: { imports: "no" } }, null as never], purl)).toEqual([]);
  });
});

describe("attachJavaUsage with the OSV schema fixture", () => {
  it("carries the listed symbols onto the advisory and only for Maven", async () => {
    const list = await check();
    expect(find(list, "GHSA-jfh8-c2jp-5v3q").vulnerableSymbols).toEqual(["org.apache.logging.log4j.core.lookup.JndiLookup"]);
    expect(find(list, "GHSA-mjmj-j48q-9wg2").vulnerableSymbols).toBeUndefined();
    expect(find(list, "GHSA-lodash").usage).toBeUndefined();
  });
  it("marks imported (with the line) when application code imports the package", async () => {
    const { advisories, scan } = attachJavaUsage(await check(), join(fixtures, "app"));
    const log4j = find(advisories, "GHSA-jfh8-c2jp-5v3q").usage!;
    expect(log4j.status).toBe("imported");
    expect(log4j.locations[0]).toEqual({ path: "src/main/java/demo/App.java", line: 2, name: "org.apache.logging.log4j.LogManager", test: false });
    expect(log4j.symbols).toEqual(["org.apache.logging.log4j.core.lookup.JndiLookup"]);
    expect(scan).toMatchObject({ mavenAdvisories: 3, truncated: false });
    expect(scan.filesScanned).toBe(2);
  });
  it("marks test-only when only test code imports it, and keeps the severity", async () => {
    const before = await check();
    const { advisories } = attachJavaUsage(before, join(fixtures, "app"));
    const text = find(advisories, "GHSA-599f-7c49-w659");
    expect(text.usage).toMatchObject({ status: "test-only", locations: [{ path: "src/test/java/demo/AppTest.java", line: 2, test: true }] });
    expect(text.severity).toBe(find(before, "GHSA-599f-7c49-w659").severity);
    expect(text.severity).toBe("critical");
  });
  it("marks not-imported with the honest wording, and never uses the word unreachable", async () => {
    const { advisories } = attachJavaUsage(await check(), join(fixtures, "app"));
    const snake = find(advisories, "GHSA-mjmj-j48q-9wg2");
    expect(snake.usage).toMatchObject({ status: "not-imported", locations: [], note: "No import found in the scanned source: a transitive or reflection use is not ruled out." });
    expect(snake.severity).toBe("high");
    expect(JSON.stringify(advisories)).not.toMatch(/unreachable|not reachable/i);
  });
  it("marks symbol-imported only when a listed class is written out in full in application code", async () => {
    const { advisories } = attachJavaUsage(await check(), join(fixtures, "app-symbol"));
    const usage = find(advisories, "GHSA-jfh8-c2jp-5v3q").usage!;
    expect(usage.status).toBe("symbol-imported");
    expect(usage.locations).toEqual([{ path: "src/main/java/demo/Lookups.java", line: 6, name: "org.apache.logging.log4j.core.lookup.JndiLookup", test: false }]);
    expect(find(advisories, "GHSA-599f-7c49-w659").usage?.status).toBe("not-imported");
  });
  it("counts a listed class in an import statement", async () => {
    const dir = mkdtempSync(join(tmpdir(), "0-usage-sym-"));
    mkdirSync(join(dir, "src/main/java"), { recursive: true });
    writeFileSync(join(dir, "src/main/java/A.java"), "import org.apache.logging.log4j.core.lookup.JndiLookup;\nclass A {}\n");
    const usage = find(attachJavaUsage(await check(), dir).advisories, "GHSA-jfh8-c2jp-5v3q").usage!;
    expect(usage).toMatchObject({ status: "symbol-imported", locations: [{ line: 1, name: "org.apache.logging.log4j.core.lookup.JndiLookup" }] });
  });
  it("keeps the package-level status when a listed class appears only in test code", async () => {
    const dir = mkdtempSync(join(tmpdir(), "0-usage-symtest-"));
    mkdirSync(join(dir, "src/main/java"), { recursive: true }); mkdirSync(join(dir, "src/test/java"), { recursive: true });
    writeFileSync(join(dir, "src/main/java/A.java"), "import org.apache.logging.log4j.LogManager;\n");
    writeFileSync(join(dir, "src/test/java/T.java"), "import org.apache.logging.log4j.core.lookup.JndiLookup;\n");
    expect(find(attachJavaUsage(await check(), dir).advisories, "GHSA-jfh8-c2jp-5v3q").usage?.status).toBe("imported");
  });
  it("leaves a malicious-package advisory without a usage verdict", () => {
    const malicious: Advisory = { purl: "pkg:maven/evil/pkg@1", id: "MAL-1", aliases: [], summary: "", severity: "critical", malicious: true, fixed: [] };
    const { advisories } = attachJavaUsage([malicious], join(fixtures, "app"));
    expect(advisories[0]!.usage).toBeUndefined();
  });
  it("does nothing, and reads no files, when no advisory is for Maven", () => {
    const npm: Advisory = { purl: "pkg:npm/x@1", id: "G", aliases: [], summary: "", severity: "high", malicious: false, fixed: [] };
    expect(attachJavaUsage([npm], join(fixtures, "app"))).toEqual({ advisories: [npm], scan: { filesScanned: 0, truncated: false, skipped: 0, mavenAdvisories: 0 } });
  });
});

describe("reports", () => {
  it("shows the usage in text, SARIF properties and a summary", async () => {
    const { advisories, scan } = attachJavaUsage(await check(), join(fixtures, "app"));
    const text = advisoriesToText(advisories, 4);
    expect(text).toContain("usage: imported");
    expect(text).toContain("src/main/java/demo/App.java:2  org.apache.logging.log4j.LogManager");
    expect(text).toContain("usage: test-only");
    expect(text).toContain("No import found in the scanned source: a transitive or reflection use is not ruled out.");
    const sarif = advisoriesToSarif(advisories, { toolVersion: "0", locate: () => "sbom.cdx.json" }) as { runs: Array<{ results: Array<{ ruleId: string; properties: Record<string, unknown> }> }> };
    const result = (id: string) => sarif.runs[0]!.results.find(item => item.ruleId === id)!.properties;
    expect(result("GHSA-mjmj-j48q-9wg2")).toMatchObject({ usage: "not-imported", severity: "high" });
    expect(result("GHSA-jfh8-c2jp-5v3q")).toMatchObject({ usage: "imported", usageLocations: ["src/main/java/demo/App.java:2", "src/main/java/demo/App.java:3"] });
    expect(result("GHSA-lodash")).not.toHaveProperty("usage");
    expect(usageSummary(advisories, scan, false)).toBe("Usage (2 source files read): 1 imported, 1 test-only, 1 not-imported. This is import evidence, not reachability; severity is unchanged.");
    expect(usageSummary(advisories, scan, true)).toContain("1 not-imported advisories are listed but do not set the exit code.");
  });
  it("leaves the text and SARIF of a plain check unchanged", async () => {
    const list = await check();
    expect(advisoriesToText(list, 4)).not.toContain("usage:");
    expect(JSON.stringify(advisoriesToSarif(list, { toolVersion: "0", locate: () => "x" }))).not.toContain("usageNote");
  });
});

describe("hostile source trees", () => {
  const log4jAdvisory = (): Advisory => ({ purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", id: "X", aliases: [], summary: "", severity: "high", malicious: false, fixed: [], vulnerableSymbols: ["org.apache.logging.log4j.core.lookup.JndiLookup"] });
  const statusIn = (dir: string) => attachJavaUsage([log4jAdvisory()], dir).advisories[0]!.usage!.status;
  const fresh = () => { const dir = mkdtempSync(join(tmpdir(), "0-usage-host-")); mkdirSync(join(dir, "src/main/java"), { recursive: true }); return dir; };

  it("does not follow a symbolic link to a folder or a file outside the tree", () => {
    const outside = mkdtempSync(join(tmpdir(), "0-usage-out-"));
    writeFileSync(join(outside, "Secret.java"), "import org.apache.logging.log4j.LogManager;\n");
    const dir = fresh();
    symlinkSync(outside, join(dir, "src/main/java/linked"));
    symlinkSync(join(outside, "Secret.java"), join(dir, "src/main/java/Linked.java"));
    const { scan } = attachJavaUsage([log4jAdvisory()], dir);
    expect(scan.filesScanned).toBe(0);
    expect(scan.skipped).toBe(2);
    expect(statusIn(dir)).toBe("unknown");
  });
  it("skips a file over the size cap", () => {
    const dir = fresh();
    writeFileSync(join(dir, "src/main/java/Big.java"), `import org.apache.logging.log4j.LogManager;\n${"// padding\n".repeat(220_000)}`);
    expect(statusIn(dir)).toBe("unknown");
    expect(attachJavaUsage([log4jAdvisory()], dir).scan.skipped).toBe(1);
  });
  it("does not search a very long line for symbols, finishes fast, and calls the result unknown", () => {
    const dir = fresh();
    writeFileSync(join(dir, "src/main/java/Min.java"), `class M { ${"a.".repeat(100_000)}org.apache.logging.log4j.core.lookup.JndiLookup }\n`);
    const started = Date.now();
    expect(statusIn(dir)).toBe("unknown");
    expect(Date.now() - started).toBeLessThan(3000);
  });
  it("does not count look-alike names, longer identifiers or comments as a listed class", () => {
    const dir = fresh();
    writeFileSync(join(dir, "src/main/java/Fake.java"), [
      "class Fake {",
      "  Object a = new evil.org.apache.logging.log4j.core.lookup.JndiLookup();",
      "  Object b = new org.apache.logging.log4j.core.lookup.JndiLookupFactory();",
      "  // new org.apache.logging.log4j.core.lookup.JndiLookup();",
      "  /* org.apache.logging.log4j.core.lookup.JndiLookup */",
      "  String s = \"x\";",
      "}",
    ].join("\n"));
    expect(statusIn(dir)).toBe("not-imported");
  });
  it("survives binary garbage, invalid UTF-8 and an empty file with a source extension", () => {
    const dir = fresh();
    writeFileSync(join(dir, "src/main/java/Bin.java"), Buffer.from([0, 255, 254, 0, 1, 2, 0xc3, 0x28, 10, 0, 0]));
    writeFileSync(join(dir, "src/main/java/Empty.kt"), "");
    writeFileSync(join(dir, "src/main/java/Ok.java"), "import org.apache.logging.log4j.LogManager;\n");
    expect(statusIn(dir)).toBe("imported");
  });
  it("shows a path with control characters without them", () => {
    const dir = fresh();
    const name = "Bad\u001b[31m\nname.java";
    writeFileSync(join(dir, "src/main/java", name), "import org.apache.logging.log4j.LogManager;\n");
    const place = attachJavaUsage([log4jAdvisory()], dir).advisories[0]!.usage!.locations[0]!;
    // eslint-disable-next-line no-control-regex
    expect(place.path).not.toMatch(/[\u0000-\u001f]/);
    expect(place.path).toContain("src/main/java/Bad");
  });
  it("stops at a bounded depth instead of walking forever", () => {
    const dir = fresh();
    let deep = dir;
    for (let level = 0; level < 60; level += 1) deep = join(deep, "d");
    mkdirSync(deep, { recursive: true });
    writeFileSync(join(deep, "Deep.java"), "import org.apache.logging.log4j.LogManager;\n");
    expect(existsSync(join(deep, "Deep.java"))).toBe(true);
    const { advisories, scan } = attachJavaUsage([log4jAdvisory()], dir);
    expect(scan.truncated).toBe(true);
    expect(advisories[0]!.usage!.status).toBe("unknown");
  });
  it("lists at most ten locations", () => {
    const dir = fresh();
    for (let index = 0; index < 30; index += 1) writeFileSync(join(dir, "src/main/java", `F${index}.java`), "import org.apache.logging.log4j.Logger;\n");
    expect(attachJavaUsage([log4jAdvisory()], dir).advisories[0]!.usage!.locations).toHaveLength(10);
  });
  it("shows application code before test code when many test files import the package", () => {
    const dir = fresh();
    mkdirSync(join(dir, "src/test/java"), { recursive: true });
    for (let index = 0; index < 80; index += 1) writeFileSync(join(dir, "src/test/java", `A${String(index).padStart(2, "0")}T.java`), "import org.apache.logging.log4j.Logger;\n");
    writeFileSync(join(dir, "src/main/java/Z.java"), "import org.apache.logging.log4j.Logger;\n");
    const usage = attachJavaUsage([log4jAdvisory()], dir).advisories[0]!.usage!;
    expect(usage.status).toBe("imported");
    expect(usage.locations[0]).toMatchObject({ path: "src/main/java/Z.java", test: false });
  });
  it("counts an unreadable directory as skipped, so the scan is not complete", () => {
    const dir = fresh();
    const locked = join(dir, "src/locked");
    mkdirSync(locked);
    chmodSync(locked, 0o000);
    try {
      const { scan } = attachJavaUsage([log4jAdvisory()], dir);
      // A process that ignores permissions (root) can read the folder; then nothing was skipped.
      if (process.getuid?.() !== 0) expect(scan.skipped).toBeGreaterThanOrEqual(1);
    } finally { chmodSync(locked, 0o755); }
  });
  it("keeps an application symbol hit when many test files name the same symbol first", () => {
    const dir = fresh();
    mkdirSync(join(dir, "src/test/java"), { recursive: true });
    for (let index = 0; index < 60; index += 1) writeFileSync(join(dir, "src/test/java", `A${String(index).padStart(2, "0")}.java`), "import org.apache.logging.log4j.core.lookup.JndiLookup;\n");
    writeFileSync(join(dir, "src/main/java/Z.java"), "import org.apache.logging.log4j.core.lookup.JndiLookup;\n");
    expect(statusIn(dir)).toBe("symbol-imported");
  });
  it("marks the scan incomplete when one file has more imports than the per-file cap", () => {
    const dir = fresh();
    writeFileSync(join(dir, "src/main/java/Many.java"), Array.from({ length: 6000 }, (_, index) => `import a.b.C${index};`).join("\n"));
    const { scan } = attachJavaUsage([log4jAdvisory()], dir);
    expect(scan.truncated).toBe(true);
    expect(scan.skipped).toBeGreaterThanOrEqual(1);
  });
  it("marks the scan incomplete when an advisory lists more symbols than are searched", () => {
    const dir = fresh();
    const many: Advisory = { ...log4jAdvisory(), vulnerableSymbols: Array.from({ length: 20 }, (_, index) => `a.b.C${index}`) };
    const others = Array.from({ length: 12 }, (_, index): Advisory => ({ ...many, id: `Y${index}`, vulnerableSymbols: Array.from({ length: 20 }, (_, n) => `p${index}.q.C${n}`) }));
    expect(attachJavaUsage([many, ...others], dir).scan.truncated).toBe(true);
  });
});

describe("a scan that hit a limit never says not-imported", () => {
  const advisory = (symbols?: string[], truncated?: boolean): Advisory => ({ purl: "pkg:maven/org.yaml/snakeyaml@1.30", id: "S", aliases: [], summary: "", severity: "high", malicious: false, fixed: [], ...(symbols ? { vulnerableSymbols: symbols } : {}), ...(truncated ? { vulnerableSymbolsTruncated: true } : {}) });
  const tree = (count: number, bytesEach = 40) => {
    const dir = mkdtempSync(join(tmpdir(), "0-usage-cap-"));
    mkdirSync(join(dir, "src/main/java"), { recursive: true });
    for (let index = 0; index < count; index += 1) writeFileSync(join(dir, "src/main/java", `F${String(index).padStart(3, "0")}.java`), `import java.util.List;\n${"//".padEnd(bytesEach, "x")}\n`);
    return dir;
  };
  it("file cap: files beyond it are counted, and a missing import is unknown", () => {
    const dir = tree(30);
    const { advisories, scan } = attachJavaUsage([advisory()], dir, { maxFiles: 10 });
    expect(advisories[0]!.usage).toMatchObject({ status: "unknown" });
    expect(advisories[0]!.usage!.note).toContain("No import was found in the part that was scanned");
    expect(advisories[0]!.usage!.note).toContain("Scan limit reached: 20 files not scanned.");
    expect(scan).toMatchObject({ truncated: true, skipped: 20 });
  });
  it("file cap with a lowered limit reports the files left out in plain words", () => {
    const dir = tree(30);
    const report = scanJavaUsage(dir, [{ name: "org.yaml/snakeyaml", version: "1", purl: "pkg:maven/org.yaml/snakeyaml@1" }], { limits: { maxFiles: 10 } });
    expect(report).toMatchObject({ truncated: true, skipped: 20, filesScanned: 10 });
    expect(scanLimitText({ filesScanned: 10, truncated: true, skipped: 20, mavenAdvisories: 1 })).toBe("Scan limit reached: 20 files not scanned.");
    expect(report.usage[0]!.verdict).toBe("no-import-found");
  });
  it("byte cap: the files after it are counted and the verdict is unknown", () => {
    const dir = tree(30, 1000);
    const report = scanJavaUsage(dir, [], { limits: { maxTotalBytes: 5000 } });
    expect(report.truncated).toBe(true);
    expect(report.skipped).toBeGreaterThan(15);
    expect(report.filesScanned + report.skipped).toBe(30);
  });
  it("advisory symbol cap: a record with more symbols than are kept makes not-imported unknown", () => {
    const dir = tree(1);
    const usage = attachJavaUsage([advisory(["a.b.C"], true)], dir).advisories[0]!.usage!;
    expect(usage.status).toBe("unknown");
    expect(usage.note).toContain("more vulnerable symbols than were searched");
  });
  it("scan symbol cap: symbols beyond it are never searched, so the scan is incomplete", () => {
    const report = scanJavaUsage(tree(1), [], { symbols: ["a.b.C", "a.b.D", "a.b.E"], limits: { maxSymbols: 2 } });
    expect(report.truncated).toBe(true);
  });
  it("still reports imported when the import is in the part that was scanned", () => {
    const dir = tree(5);
    writeFileSync(join(dir, "src/main/java/A.java"), "import org.yaml.snakeyaml.Yaml;\n");
    expect(attachJavaUsage([advisory()], dir).advisories[0]!.usage!.status).toBe("imported");
  });
  it("a complete scan still says not-imported", () => {
    expect(attachJavaUsage([advisory()], tree(3)).advisories[0]!.usage!.status).toBe("not-imported");
  });
  it("a hostile tree of many small files is cut at the file cap without reading them all", () => {
    const dir = tree(2000, 10);
    const started = Date.now();
    const report = scanJavaUsage(dir, [], { limits: { maxFiles: 100 } });
    expect(report.filesScanned).toBe(100);
    expect(report.skipped).toBe(1900);
    expect(Date.now() - started).toBeLessThan(5000);
  });
  it("stops walking once the directory-entry limit is reached", () => {
    const dir = mkdtempSync(join(tmpdir(), "0-usage-entries-"));
    for (let index = 0; index < 40; index += 1) { mkdirSync(join(dir, `d${String(index).padStart(2, "0")}`)); writeFileSync(join(dir, `d${String(index).padStart(2, "0")}`, "A.java"), "class A {}\n"); }
    const report = scanJavaUsage(dir, [], { limits: { maxEntries: 10 } });
    expect(report.truncated).toBe(true);
    expect(report.filesScanned).toBeLessThan(10);
  });
  it("bounds the cumulative symbol search and says the scan is incomplete", () => {
    const dir = tree(20, 80);
    const report = scanJavaUsage(dir, [], { symbols: ["a.b.C", "a.b.D"], limits: { maxSymbolChecks: 10 } });
    expect(report.truncated).toBe(true);
    expect(report.skipped).toBeGreaterThan(0);
    const advisoryWithSymbol: Advisory = { ...advisory(["a.b.C"]) };
    expect(attachJavaUsage([advisoryWithSymbol], dir, { maxSymbolChecks: 1 }).advisories[0]!.usage!.status).toBe("unknown");
  });
  it("counts import-line symbol matching against the same work budget", () => {
    const dir = mkdtempSync(join(tmpdir(), "0-usage-imports-"));
    mkdirSync(join(dir, "src/main/java"), { recursive: true });
    writeFileSync(join(dir, "src/main/java/I.java"), Array.from({ length: 50 }, (_, index) => `import x.y.C${index};`).join("\n"));
    const report = scanJavaUsage(dir, [], { symbols: ["a.b.C", "a.b.D"], limits: { maxSymbolChecks: 20 } });
    expect(report.truncated).toBe(true);
  });
  it("gives up matching components past the work budget and calls the scan incomplete", () => {
    const dir = tree(5);
    const report = scanJavaUsage(dir, Array.from({ length: 50 }, (_, index) => ({ name: `g${index}/a`, version: "1", purl: `pkg:maven/g${index}/a@1` })), { limits: { maxMatchWork: 20 } });
    expect(report.truncated).toBe(true);
    expect(report.usage).toHaveLength(50);
  });
  it("bounds the symbols copied out of a crafted OSV record", () => {
    const symbols = Array.from({ length: 5000 }, (_, index) => `a.b.C${index}`);
    const affected = [{ ecosystem_specific: { imports: Array.from({ length: 200 }, () => ({ path: "x".repeat(300), symbols })) } }];
    expect(vulnerableSymbolsFor(affected, "pkg:maven/a/b@1").length).toBeLessThanOrEqual(100);
    const ok = [{ ecosystem_specific: { imports: Array.from({ length: 200 }, () => ({ path: "p.q", symbols })) } }];
    expect(vulnerableSymbolsFor(ok, "pkg:maven/a/b@1").length).toBeLessThanOrEqual(100);
  });
  it("reports that a record had more symbols than were read, even when few valid names were kept", () => {
    const junk = Array.from({ length: 12_000 }, () => "not valid");
    const affected = [{ ecosystem_specific: { imports: [{ path: "p.q", symbols: junk }, { path: "p.q", symbols: ["Real"] }] } }];
    expect(vulnerableSymbolsWithLimit(affected, "pkg:maven/a/b@1").more).toBe(true);
    const many = [{ ecosystem_specific: { imports: [{ path: "p.q", symbols: Array.from({ length: 300 }, (_, index) => `S${index}`) }] } }];
    expect(vulnerableSymbolsWithLimit(many, "pkg:maven/a/b@1").more).toBe(true);
    expect(vulnerableSymbolsWithLimit([{ ecosystem_specific: { imports: [{ path: "p.q", symbols: ["One"] }] } }], "pkg:maven/a/b@1")).toEqual({ symbols: ["p.q.One"], more: false });
  });
});
