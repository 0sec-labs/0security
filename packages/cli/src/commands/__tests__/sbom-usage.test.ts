import { mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { UsageError } from "../output.js";
import { runCheck, type SbomDeps } from "../sbom.js";

// The SBOM, the sources and the OSV records are shared with the engine tests. The records are hand-built in the OSV schema.
const fixtures = join(import.meta.dirname, "..", "..", "..", "..", "engine", "src", "sbom", "fixtures", "usage");
const sbom = readFileSync(join(fixtures, "sbom.cdx.json"), "utf8");
const records = JSON.parse(readFileSync(join(fixtures, "osv-records.hand-built.json"), "utf8")) as Record<string, unknown>;
const byPurl: Record<string, string[]> = {
  "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1": ["GHSA-jfh8-c2jp-5v3q"],
  "pkg:maven/org.apache.commons/commons-text@1.9": ["GHSA-599f-7c49-w659"],
  "pkg:maven/org.yaml/snakeyaml@1.30": ["GHSA-mjmj-j48q-9wg2"],
  "pkg:npm/lodash@4.17.20": ["GHSA-lodash"],
};
const run = (only?: string[]) => {
  const urls: string[] = [];
  const fetchFake: typeof fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    const text = String(url); urls.push(text);
    if (text.endsWith("/v1/querybatch")) {
      const queries = (JSON.parse(String(init?.body)) as { queries: Array<{ package: { purl: string } }> }).queries;
      return new Response(JSON.stringify({ results: queries.map(query => ({ vulns: (byPurl[query.package.purl] ?? []).filter(id => !only || only.includes(id)).map(id => ({ id })) })) }));
    }
    return new Response(JSON.stringify(records[decodeURIComponent(text.split("/v1/vulns/")[1]!)]));
  }) as typeof fetch;
  const out: string[] = []; const err: string[] = [];
  const deps = { out: (t: string) => out.push(t), err: (t: string) => err.push(t), write: () => undefined, read: () => sbom, fetch: fetchFake } as unknown as SbomDeps;
  return { out, err, urls, deps };
};

describe("0 sbom check --usage", () => {
  it("adds a usage label, places and the caveat to each Maven advisory in text", async () => {
    const io = run();
    expect(await runCheck("sbom.json", { usage: join(fixtures, "app") }, io.deps)).toBe(1);
    const text = io.out.join("");
    expect(text).toContain("usage: imported");
    expect(text).toContain("src/main/java/demo/App.java:2  org.apache.logging.log4j.LogManager");
    expect(text).toContain("usage: test-only");
    expect(text).toContain("usage: not-imported");
    expect(text).toContain("No import found in the scanned source: a transitive or reflection use is not ruled out.");
    expect(text).toContain("This is import evidence, not reachability; severity is unchanged.");
    expect(text).toContain("GHSA-mjmj-j48q-9wg2 (CVE-2022-1471)  high  Fixed in 2.0.");
  });
  it("adds the usage field to JSON with the scan size", async () => {
    const io = run();
    await runCheck("sbom.json", { usage: join(fixtures, "app-symbol"), format: "json" }, io.deps);
    const json = JSON.parse(io.out.join("")) as { advisories: Array<{ id: string; usage?: { status: string } }>; usageScan: { filesScanned: number; ignoreNotImported: boolean } };
    expect(json.advisories.find(item => item.id === "GHSA-jfh8-c2jp-5v3q")?.usage?.status).toBe("symbol-imported");
    expect(json.advisories.find(item => item.id === "GHSA-lodash")?.usage).toBeUndefined();
    expect(json.usageScan).toEqual({ filesScanned: 1, truncated: false, skipped: 0, mavenAdvisories: 3, ignoreNotImported: false });
  });
  it("adds usage to SARIF properties", async () => {
    const io = run();
    await runCheck("sbom.json", { usage: join(fixtures, "app"), format: "sarif" }, io.deps);
    const sarif = JSON.parse(io.out.join("")) as { runs: Array<{ results: Array<{ ruleId: string; level: string; properties: Record<string, unknown> }> }> };
    const snake = sarif.runs[0]!.results.find(item => item.ruleId === "GHSA-mjmj-j48q-9wg2")!;
    expect(snake.properties.usage).toBe("not-imported");
    expect(snake.level).toBe("error");
  });
  it("keeps exit 1 for a not-imported advisory by default", async () => {
    const io = run(["GHSA-mjmj-j48q-9wg2"]);
    expect(await runCheck("sbom.json", { usage: join(fixtures, "app") }, io.deps)).toBe(1);
  });
  it("--ignore-not-imported lists the advisory but leaves the exit code at 0 when only not-imported ones remain", async () => {
    const io = run(["GHSA-mjmj-j48q-9wg2"]);
    expect(await runCheck("sbom.json", { usage: join(fixtures, "app"), ignoreNotImported: true }, io.deps)).toBe(0);
    expect(io.out.join("")).toContain("GHSA-mjmj-j48q-9wg2");
    expect(io.out.join("")).toContain("1 not-imported advisories are listed but do not set the exit code.");
  });
  it("--ignore-not-imported still exits 1 for an imported, test-only or non-Maven advisory", async () => {
    for (const id of ["GHSA-jfh8-c2jp-5v3q", "GHSA-599f-7c49-w659", "GHSA-lodash"]) {
      expect(await runCheck("sbom.json", { usage: join(fixtures, "app"), ignoreNotImported: true }, run([id]).deps)).toBe(1);
    }
  });
  it("--ignore-not-imported is not applied when the scan skipped a file, so a hidden import cannot turn the exit code to 0", async () => {
    const dir = mkdtempSync(join(tmpdir(), "0-usage-cli-"));
    mkdirSync(join(dir, "src"), { recursive: true });
    writeFileSync(join(dir, "src", "Big.java"), `import org.yaml.snakeyaml.Yaml;\n${"// padding\n".repeat(220_000)}`);
    const io = run(["GHSA-mjmj-j48q-9wg2"]);
    expect(await runCheck("sbom.json", { usage: dir, ignoreNotImported: true }, io.deps)).toBe(1);
    expect(io.err.join("\n")).toContain("never ignores unknown");
    expect(io.out.join("")).toContain("Scan limit reached: 1 files not scanned.");
    expect(io.out.join("")).toContain("usage: unknown");
    expect(io.out.join("")).toContain("1 unknown advisories still set it.");
    const json = run(["GHSA-mjmj-j48q-9wg2"]);
    await runCheck("sbom.json", { usage: dir, ignoreNotImported: true, format: "sarif" }, json.deps);
    expect((JSON.parse(json.out.join("")) as { runs: Array<{ results: Array<{ properties: { usage: string } }> }> }).runs[0]!.results[0]!.properties.usage).toBe("unknown");
    const link = mkdtempSync(join(tmpdir(), "0-usage-cli-"));
    symlinkSync(dir, join(link, "linked"));
    expect(await runCheck("sbom.json", { usage: link, ignoreNotImported: true }, run(["GHSA-mjmj-j48q-9wg2"]).deps)).toBe(1);
  });
  it("--ignore-not-imported needs --usage and --usage needs a folder, both before any request", async () => {
    const io = run();
    await expect(runCheck("sbom.json", { ignoreNotImported: true }, io.deps)).rejects.toBeInstanceOf(UsageError);
    await expect(runCheck("sbom.json", { usage: join(fixtures, "sbom.cdx.json") }, io.deps)).rejects.toThrow("is not a folder");
    await expect(runCheck("sbom.json", { usage: "/no/such/folder" }, io.deps)).rejects.toThrow("is not a folder");
    expect(io.urls).toEqual([]);
  });
  it("makes no request beyond the OSV lookup a plain check already makes", async () => {
    const plain = run(); await runCheck("sbom.json", {}, plain.deps);
    const withUsage = run(); await runCheck("sbom.json", { usage: join(fixtures, "app") }, withUsage.deps);
    expect(withUsage.urls).toEqual(plain.urls);
  });
  it("leaves a plain check without any usage output", async () => {
    const io = run(); await runCheck("sbom.json", {}, io.deps);
    expect(io.out.join("")).not.toContain("usage");
  });
});
