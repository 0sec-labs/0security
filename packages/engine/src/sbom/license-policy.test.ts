import { describe, expect, it } from "vitest";
import { checkBomLicenses, judgeComponent, licensesToSarif, mergePolicies, parseLicenseExpression, policyFromDocument, PRESETS, validatePolicy, type LicensePolicy, type Verdict } from "./license-policy.js";

const policy = (extra: Partial<LicensePolicy>): LicensePolicy => ({ allow: [], deny: [], allowByPackage: [], unknown: "warn", ...extra });
const component = (licenses: unknown, extra: Record<string, unknown> = {}) => ({ name: "pkg", version: "1.0.0", purl: "pkg:npm/pkg@1.0.0", licenses, ...extra });
const expr = (expression: string) => [{ expression }];
const id = (value: string) => [{ license: { id: value } }];
const verdictOf = (licenses: unknown, p: LicensePolicy): Verdict => judgeComponent(component(licenses), p).verdict;

describe("parseLicenseExpression", () => {
  it.each(["MIT", "MIT OR Apache-2.0", "GPL-2.0-only AND MIT", "(MIT OR Apache-2.0) AND BSD-3-Clause", "GPL-2.0-only WITH Classpath-exception-2.0", "Apache-2.0+", "LicenseRef-Custom-1"])("accepts %s", text => {
    expect(parseLicenseExpression(text)).toBeDefined();
  });
  it.each(["", "MIT OR", "OR MIT", "MIT Apache-2.0", "mit or apache-2.0", "MIT OR (Apache-2.0", "MIT)", "SEE LICENSE IN LICENSE.txt", "Not-A-License", "MIT WITH", "MIT WITH Not-Real", "MIT AND AND ISC"])("rejects %s", text => {
    expect(parseLicenseExpression(text)).toBeUndefined();
  });
  it("binds AND tighter than OR and WITH tighter than AND", () => {
    expect(parseLicenseExpression("MIT OR ISC AND Zlib")).toMatchObject({ k: "or", right: { k: "and" } });
    expect(parseLicenseExpression("GPL-2.0-only WITH Classpath-exception-2.0 AND MIT")).toMatchObject({ k: "and", left: { exception: "Classpath-exception-2.0" } });
  });
});

describe("expression evaluation against an allow list", () => {
  const cases: Array<[string, string[], Verdict]> = [
    ["MIT", ["MIT"], "allowed"],
    ["MIT", ["Apache-2.0"], "not-allowed"],
    ["MIT OR Apache-2.0", ["MIT"], "allowed"],
    ["MIT OR Apache-2.0", ["Apache-2.0"], "allowed"],
    ["MIT OR Apache-2.0", ["ISC"], "not-allowed"],
    ["GPL-2.0-only AND MIT", ["MIT"], "not-allowed"],
    ["GPL-2.0-only AND MIT", ["GPL-2.0-only"], "not-allowed"],
    ["GPL-2.0-only AND MIT", ["GPL-2.0-only", "MIT"], "allowed"],
    ["(MIT OR GPL-3.0-only) AND ISC", ["MIT", "ISC"], "allowed"],
    ["(MIT OR GPL-3.0-only) AND ISC", ["GPL-3.0-only"], "not-allowed"],
    ["GPL-2.0-only WITH Classpath-exception-2.0", ["GPL-2.0-only"], "allowed"],
    ["GPL-2.0-only WITH Classpath-exception-2.0", ["GPL-2.0-only WITH Classpath-exception-2.0"], "allowed"],
    ["GPL-2.0-only", ["GPL-2.0-only WITH Classpath-exception-2.0"], "not-allowed"],
    ["GPL-2.0-or-later", ["GPL-2.0+"], "allowed"],
    ["GPL-2.0+", ["GPL-2.0-or-later"], "allowed"],
    ["GPL-2.0", ["GPL-2.0-only"], "allowed"],
    ["GPL-2.0-only", ["GPL-2.0-or-later"], "not-allowed"],
    ["Apache-2.0+", ["Apache-2.0"], "allowed"],
    ["LicenseRef-Custom", ["MIT"], "not-allowed"],
    ["LicenseRef-Custom", ["LicenseRef-Custom"], "allowed"],
  ];
  it.each(cases)("%s with allow %j is %s", (expression, allow, expected) => {
    expect(verdictOf(expr(expression), policy({ allow }))).toBe(expected);
  });
});

describe("expression evaluation against a deny list", () => {
  const cases: Array<[string, string[], Verdict]> = [
    ["MIT", ["GPL-*"], "allowed"],
    ["GPL-3.0-only", ["GPL-*"], "denied"],
    ["GPL-3.0+", ["GPL-*"], "denied"],
    ["AGPL-3.0-only", ["GPL-*"], "allowed"],
    ["AGPL-3.0-only", ["AGPL-*"], "denied"],
    ["LGPL-2.1-or-later", ["LGPL-*"], "denied"],
    ["MIT OR GPL-3.0-only", ["GPL-*"], "allowed"],
    ["GPL-3.0-only OR AGPL-3.0-only", ["GPL-*", "AGPL-*"], "denied"],
    ["MIT AND GPL-3.0-only", ["GPL-*"], "denied"],
    ["GPL-2.0-only WITH Classpath-exception-2.0", ["GPL-*"], "denied"],
    ["GPL-2.0-only WITH Classpath-exception-2.0", ["GPL-2.0-only WITH Classpath-exception-2.0"], "denied"],
    ["GPL-2.0-only", ["GPL-2.0-only WITH Classpath-exception-2.0"], "allowed"],
    ["GPL-2.0", ["GPL-2.0-only"], "denied"],
  ];
  it.each(cases)("%s with deny %j is %s", (expression, deny, expected) => {
    expect(verdictOf(expr(expression), policy({ deny }))).toBe(expected);
  });
  it("lets an entry that names the exception beat a deny of the license", () => {
    const p = policy({ deny: ["GPL-*"], allow: ["MIT", "GPL-2.0-only WITH Classpath-exception-2.0"] });
    expect(verdictOf(expr("GPL-2.0-only WITH Classpath-exception-2.0"), p)).toBe("allowed");
    expect(verdictOf(id("GPL-2.0-only"), p)).toBe("denied");
  });
  it("lets deny win over allow for the same id", () => {
    expect(verdictOf(id("MIT"), policy({ allow: ["MIT"], deny: ["MIT"] }))).toBe("denied");
  });
  it("without an allow list, everything not denied is allowed", () => {
    expect(verdictOf(id("Zlib"), policy({ deny: ["GPL-*"] }))).toBe("allowed");
  });
});

describe("unknown licenses", () => {
  const p = policy({ allow: ["MIT"] });
  it("is unknown without a license, for a free-text name, and for an id not on the SPDX list", () => {
    expect(verdictOf(undefined, p)).toBe("unknown");
    expect(verdictOf([], p)).toBe("unknown");
    expect(verdictOf([{ license: { name: "MIT" } }], p)).toBe("unknown");
    expect(verdictOf([{ license: { name: "MIT License" } }], p)).toBe("unknown");
    expect(verdictOf(id("mit"), p)).toBe("unknown");
    expect(verdictOf(expr("SEE LICENSE IN LICENSE.txt"), p)).toBe("unknown");
    expect(judgeComponent(component([{ license: { name: "Custom" } }]), p).reason).toContain("Custom");
  });
  it("applies the unknown mode to the exit decision only", () => {
    expect(judgeComponent(component(undefined), policy({ allow: ["MIT"], unknown: "warn" })).violation).toBe(false);
    expect(judgeComponent(component(undefined), policy({ allow: ["MIT"], unknown: "allow" })).violation).toBe(false);
    expect(judgeComponent(component(undefined), policy({ allow: ["MIT"], unknown: "fail" })).violation).toBe(true);
  });
  it("treats several license entries as all applying, and a violation outranks an unknown part", () => {
    expect(verdictOf([...id("MIT"), ...id("Apache-2.0")], policy({ allow: ["MIT"] }))).toBe("not-allowed");
    expect(verdictOf([...id("MIT"), { license: { name: "weird" } }], p)).toBe("unknown");
    expect(verdictOf([...id("GPL-3.0-only"), { license: { name: "weird" } }], p)).toBe("not-allowed");
  });
});

describe("package exceptions", () => {
  const bad = policy({ allow: ["MIT"] });
  it("waives a component by name, by package URL with or without version, and respects a version", () => {
    for (const target of ["pkg", "pkg:npm/pkg", "pkg:npm/pkg@1.0.0"]) {
      const result = judgeComponent(component(id("GPL-3.0-only")), { ...bad, allowByPackage: [{ package: target, reason: "linked dynamically" }] });
      expect(result.verdict).toBe("allowed");
      expect(result.exception).toEqual({ reason: "linked dynamically", waived: true });
    }
    expect(judgeComponent(component(id("GPL-3.0-only")), { ...bad, allowByPackage: [{ package: "pkg", version: "2.0.0", reason: "x" }] }).verdict).toBe("not-allowed");
  });
  it("waives a component with no license, and with `licenses` allows only those ids", () => {
    expect(judgeComponent(component(undefined), { ...bad, allowByPackage: [{ package: "pkg", reason: "vendored, checked by hand" }] }).verdict).toBe("allowed");
    const only = { ...bad, allowByPackage: [{ package: "pkg", licenses: ["GPL-3.0-only"], reason: "approved" }] };
    expect(judgeComponent(component(id("GPL-3.0-only")), only).verdict).toBe("allowed");
    expect(judgeComponent(component(id("AGPL-3.0-only")), only).verdict).toBe("not-allowed");
  });
  it("requires a reason and valid ids", () => {
    expect(() => policyFromDocument({ allowByPackage: [{ package: "x" }] })).toThrow("reason is required");
    expect(validatePolicy(policy({ allowByPackage: [{ package: "x", reason: " " }] }))).toEqual(["allowByPackage[0] (x): a reason is required."]);
  });
});

describe("policy documents, validation and presets", () => {
  it("rejects typos and bad ids instead of weakening the policy", () => {
    expect(() => policyFromDocument({ alow: ["MIT"] })).toThrow("Unknown policy key: alow");
    expect(() => policyFromDocument({ unknown: "ignore" })).toThrow("warn, fail or allow");
    expect(() => policyFromDocument([])).toThrow("must be an object");
    expect(validatePolicy(policy({ allow: ["mit"], deny: ["Nothing-*"] })).join("\n")).toMatch(/allow: 'mit'[\s\S]*deny: 'Nothing-\*'/);
    expect(() => checkBomLicenses({ components: [] }, policy({ allow: ["Apache2"] }))).toThrow("not an SPDX license id");
  });
  it("merges a preset, a file and flags: lists join and the latest unknown mode wins", () => {
    const merged = mergePolicies([{ preset: "permissive" }, { allow: ["MPL-2.0"], unknown: "fail" }, { deny: ["MIT"] }]);
    expect(merged.allow).toContain("MPL-2.0");
    expect(merged.allow).toContain("MIT");
    expect(merged.deny).toEqual(["MIT"]);
    expect(merged.unknown).toBe("fail");
    expect(mergePolicies([{ preset: "no-copyleft" }]).unknown).toBe("warn");
  });
  it("permissive allows its eleven licenses and nothing else", () => {
    const p = mergePolicies([{ preset: "permissive" }]);
    expect(PRESETS.permissive.allow).toHaveLength(11);
    for (const licenseId of PRESETS.permissive.allow) expect(verdictOf(id(licenseId), p)).toBe("allowed");
    for (const licenseId of ["MPL-2.0", "GPL-3.0-only", "CC-BY-4.0", "BSD-4-Clause", "EPL-2.0"]) expect(verdictOf(id(licenseId), p)).toBe("not-allowed");
    expect(verdictOf(expr("MIT OR GPL-3.0-only"), p)).toBe("allowed");
  });
  it("no-copyleft denies the GPL, AGPL, LGPL, SSPL and EUPL families and allows weak copyleft", () => {
    const p = mergePolicies([{ preset: "no-copyleft" }]);
    for (const licenseId of ["GPL-2.0-only", "GPL-3.0-or-later", "GPL-3.0", "AGPL-3.0-only", "LGPL-2.1-only", "LGPL-3.0-or-later", "SSPL-1.0", "EUPL-1.2"]) expect(verdictOf(id(licenseId), p)).toBe("denied");
    for (const licenseId of ["MIT", "MPL-2.0", "EPL-2.0", "CC-BY-SA-4.0"]) expect(verdictOf(id(licenseId), p)).toBe("allowed");
  });
});

describe("checkBomLicenses and SARIF", () => {
  const bom = {
    components: [
      { name: "a", version: "1", purl: "pkg:npm/a@1", licenses: id("MIT") },
      { name: "b", version: "1", purl: "pkg:npm/b@1", licenses: id("GPL-3.0-only") },
      { name: "c", version: "1", purl: "pkg:npm/c@1" },
      { name: "d", version: "1", purl: "pkg:npm/d@1", licenses: id("Beerware"), scope: "excluded" },
      { name: "e", version: "1", purl: "pkg:npm/e@1", licenses: expr("MIT AND Beerware"), components: [{ name: "n", version: "1", purl: "pkg:npm/n@1", licenses: id("ISC") }] },
    ],
  };
  const p = mergePolicies([{ preset: "permissive" }]);
  it("counts verdicts, visits nested components and can skip development-only ones", () => {
    const report = checkBomLicenses(bom, p);
    expect(report.summary).toEqual({ total: 6, denied: 0, notAllowed: 3, unknown: 1, allowed: 2, excepted: 0, violations: 3 });
    expect(checkBomLicenses(bom, p, { excludeDev: true }).summary.total).toBe(5);
    expect(checkBomLicenses(bom, { ...p, unknown: "fail" }).summary.violations).toBe(4);
  });
  it("writes one result per violating component with a stable fingerprint and rule license/<id>", () => {
    const report = checkBomLicenses(bom, p);
    const options = { toolVersion: "1.2.3", uri: () => "package-lock.json" };
    const sarif = licensesToSarif(report, options) as { runs: Array<{ results: Array<{ ruleId: string; level: string; partialFingerprints: Record<string, string>; locations: unknown[] }>; tool: { driver: { rules: Array<{ id: string }> } } }> };
    const results = sarif.runs[0]!.results;
    expect(results.map(result => `${result.ruleId}:${result.level}`)).toEqual(["license/GPL-3.0-only:error", "license/unknown:warning", "license/Beerware:error", "license/Beerware:error"]);
    expect(sarif.runs[0]!.tool.driver.rules.map(rule => rule.id)).toEqual(["license/Beerware", "license/GPL-3.0-only", "license/unknown"]);
    const again = licensesToSarif(checkBomLicenses(bom, p), options) as typeof sarif;
    expect(again.runs[0]!.results.map(result => result.partialFingerprints)).toEqual(results.map(result => result.partialFingerprints));
    expect(new Set(results.map(result => result.partialFingerprints["0LicensePolicy/v1"])).size).toBe(4);
  });
  it("omits unknown results when unknown is allow", () => {
    const sarif = licensesToSarif(checkBomLicenses(bom, { ...p, unknown: "allow" }), { toolVersion: "1", uri: () => "x" }) as { runs: Array<{ results: unknown[] }> };
    expect(sarif.runs[0]!.results).toHaveLength(3);
  });
});
