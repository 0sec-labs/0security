import { describe, expect, it } from "vitest";
import { parseSarif } from "../shared/sarif-import.js";
import { bandOfScore, compareVersions, cvss3BaseScore, fixesFor, severityOf } from "./advisory-facts.js";
import { advisoriesToSarif, advisoriesToText } from "./check-report.js";
import { checkBomAgainstOsv, type Advisory } from "./osv.js";
import { checkOutdated, depsDevName, gap, outdatedToText } from "./outdated.js";

describe("severity", () => {
  it("scores a CVSS 3 vector the way the specification does", () => {
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe(9.8);
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H")).toBe(7.4);
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N")).toBe(7.2);
    expect(cvss3BaseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")).toBeUndefined();
    expect(bandOfScore(9.8)).toBe("critical");
  });
  it("prefers the database label, falls back to CVSS 3, and leaves the rest unknown", () => {
    expect(severityOf({ database_specific: { severity: "MODERATE" } }).severity).toBe("medium");
    expect(severityOf({ severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }] })).toEqual({ severity: "critical", cvss: 9.8 });
    expect(severityOf({ database_specific: { severity: "weird" } }).severity).toBe("unknown");
    expect(severityOf({ severity: [{ type: "CVSS_V4", score: "CVSS:4.0/AV:N" }] }).severity).toBe("unknown");
    expect(severityOf({}).severity).toBe("unknown");
  });
});

describe("fixed version", () => {
  const affected = [
    { package: { name: "lodash", ecosystem: "npm", purl: "pkg:npm/lodash" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.12" }, { introduced: "4.18.0" }, { fixed: "4.18.2" }] }] },
    { package: { name: "lodash-es", ecosystem: "npm", purl: "pkg:npm/lodash-es" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "9.9.9" }] }] },
    { package: { name: "lodash", ecosystem: "npm", purl: "pkg:npm/lodash" }, ranges: [{ type: "GIT", events: [{ fixed: "abc123" }] }] },
  ];
  it("picks the lowest fix above the installed version, for this package only", () => {
    expect(fixesFor(affected, "pkg:npm/lodash@4.17.5")).toEqual({ fixed: ["4.17.12", "4.18.2"], fixedVersion: "4.17.12" });
    expect(fixesFor(affected, "pkg:npm/lodash@4.18.1").fixedVersion).toBe("4.18.2");
  });
  it("says nothing when no fix is above the installed version or none is named", () => {
    expect(fixesFor(affected, "pkg:npm/lodash@5.0.0").fixedVersion).toBeUndefined();
    expect(fixesFor([{ package: { purl: "pkg:cargo/x" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }] }], "pkg:cargo/x@1.0.0")).toEqual({ fixed: [] });
  });
  it("orders versions with pre-releases below releases", () => {
    expect(compareVersions("1.2.10", "1.2.9")).toBe(1);
    expect(compareVersions("2.0.0-rc.1", "2.0.0")).toBe(-1);
    expect(compareVersions("v0.9.0", "0.10.0")).toBe(-1);
    expect(compareVersions("1.0", "1.0.0")).toBe(0);
  });
});

describe("malicious packages", () => {
  const bom = { components: [{ purl: "pkg:cargo/rustdecimal@1.0.0" }] };
  const fetcher = (async (url: string | URL | Request) => {
    const href = String(url);
    if (href.endsWith("/v1/querybatch")) return new Response(JSON.stringify({ results: [{ vulns: [{ id: "MAL-2022-1" }] }] }));
    return new Response(JSON.stringify({ id: "MAL-2022-1", summary: "Malicious code in rustdecimal (crates.io)", affected: [{ package: { name: "rustdecimal", ecosystem: "crates.io", purl: "pkg:cargo/rustdecimal" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }] }] }));
  }) as typeof fetch;
  it("labels a MAL- record as a critical malicious package", async () => {
    const { advisories } = await checkBomAgainstOsv(bom, { fetch: fetcher, baseUrl: "https://osv.test" });
    expect(advisories[0]).toMatchObject({ id: "MAL-2022-1", malicious: true, severity: "critical", fixed: [] });
    const text = advisoriesToText(advisories, 1);
    expect(text).toContain("MALICIOUS PACKAGE FOUND");
    expect(text).toContain("MALICIOUS PACKAGE  MAL-2022-1");
  });
});

describe("SARIF", () => {
  const advisories: Advisory[] = [
    { purl: "pkg:npm/lodash@4.17.15", id: "GHSA-35jh-r3h4-6jhm", aliases: ["CVE-2021-23337"], summary: "Command Injection in lodash", severity: "high", cvss: 7.2, malicious: false, fixed: ["4.17.21"], fixedVersion: "4.17.21" },
    { purl: "pkg:npm/evil@1.0.0", id: "MAL-2025-9", aliases: [], summary: "Malicious code in evil", severity: "critical", malicious: true, fixed: [] },
    { purl: "pkg:npm/odd@1.0.0", id: "GHSA-x", aliases: [], summary: "", severity: "unknown", malicious: false, fixed: [] },
  ];
  const sarif = advisoriesToSarif(advisories, { toolVersion: "1", locate: purl => purl.includes("evil") ? "sbom.json" : "package-lock.json" });
  it("imports with the rule id, location, severity, fix and a stable fingerprint", () => {
    const { findings } = parseSarif(JSON.stringify(sarif));
    expect(findings.map(finding => [finding.ruleId, finding.path, finding.severity])).toEqual([
      ["MAL-2025-9", "sbom.json", "critical"], ["GHSA-35jh-r3h4-6jhm", "package-lock.json", "high"], ["GHSA-x", "package-lock.json", "medium"],
    ]);
    expect(findings[0]!.description).toContain("MALICIOUS PACKAGE");
    expect(findings[1]!.description).toContain("Fixed in 4.17.21.");
    expect(findings[2]!.description).toContain("No fixed version known.");
    expect(parseSarif(JSON.stringify(sarif)).findings.map(finding => finding.fingerprint)).toEqual(findings.map(finding => finding.fingerprint));
  });
});

describe("outdated", () => {
  const bom = { components: [{ purl: "pkg:npm/lodash@4.17.15" }, { purl: "pkg:npm/current@2.0.0" }, { purl: "pkg:composer/a/b@1.0.0" }, { purl: "pkg:maven/org.x/y@1.0.0", scope: "excluded" }] };
  const versions = (installed: string[], latest: string) => ({ versions: [...installed, latest, "9.0.0-beta.1"].map(version => ({ versionKey: { version }, isDefault: version === latest })) });
  it("reports a newer default version as information and skips ecosystems deps.dev lacks", async () => {
    const urls: string[] = [];
    const fetcher = (async (url: string | URL | Request) => {
      urls.push(String(url));
      if (String(url).endsWith("/lodash")) return new Response(JSON.stringify(versions(["4.17.15", "4.17.20"], "4.18.1")));
      if (String(url).endsWith("/current")) return new Response(JSON.stringify(versions(["1.0.0"], "2.0.0")));
      return new Response("nope", { status: 404 });
    }) as typeof fetch;
    const result = await checkOutdated(bom, { fetch: fetcher, baseUrl: "https://deps.test" });
    expect(result).toMatchObject({ checked: 3, unsupported: 1, failed: 1, overCap: 0 });
    expect(result.notes).toEqual([{ purl: "pkg:npm/lodash@4.17.15", installed: "4.17.15", latest: "4.18.1", behind: { major: 0, minor: 1, patch: 0 }, releasesBehind: 2 }]);
    expect(urls[0]).toContain("/v3/systems/npm/packages/");
    expect(outdatedToText(result)).toContain("information only");
  });
  it("stops at the cap and says so", async () => {
    const many = { components: Array.from({ length: 5 }, (_, index) => ({ purl: `pkg:npm/p${index}@1.0.0` })) };
    const result = await checkOutdated(many, { fetch: (async () => new Response(JSON.stringify(versions([], "2.0.0")))) as typeof fetch, cap: 2 });
    expect(result).toMatchObject({ checked: 2, overCap: 3, cap: 2 });
    expect(outdatedToText(result)).toContain("3 were not checked");
  });
  it("names packages the way deps.dev does and measures the gap", () => {
    expect(depsDevName("pkg:maven/org.x/y@1.0.0")).toEqual({ system: "maven", name: "org.x:y" });
    expect(depsDevName("pkg:npm/%40types/node@1.0.0")).toEqual({ system: "npm", name: "@types/node" });
    expect(gap("1.2.3", "3.0.0")).toEqual({ major: 2, minor: 0, patch: 0 });
    expect(gap("1.2.3", "1.2.9")).toEqual({ major: 0, minor: 0, patch: 6 });
  });
});
