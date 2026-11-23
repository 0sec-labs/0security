import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Command } from "commander";
import { afterEach, describe, expect, it, vi } from "vitest";
import { UsageError } from "../output.js";
import { registerSbomCommand, type SbomDeps } from "../sbom.js";
import { buildPolicy, depsDevKey, runLicenses } from "../sbom-licenses.js";

const dirs: string[] = [];
afterEach(() => { vi.restoreAllMocks(); dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true })); });
const project = (files: Record<string, string>) => { const dir = mkdtempSync(join(tmpdir(), "0-sbomlic-")); dirs.push(dir); for (const [path, content] of Object.entries(files)) { mkdirSync(join(dir, path, ".."), { recursive: true }); writeFileSync(join(dir, path), content); } return dir; };
const io = (extra: Partial<SbomDeps> = {}) => { const out: string[] = []; const err: string[] = []; return { out, err, deps: { out: (t: string) => out.push(t), err: (t: string) => err.push(t), write: () => {}, read: (p: string) => readFileSync(p, "utf8"), ...extra } as SbomDeps }; };

const lock = JSON.stringify({ lockfileVersion: 3, packages: {
  "": { name: "app" },
  "node_modules/ok": { version: "1.0.0", license: "MIT" },
  "node_modules/dual": { version: "1.0.0", license: "(MIT OR GPL-3.0-only)" },
  "node_modules/gpl": { version: "2.0.0", license: "GPL-3.0-only" },
  "node_modules/odd": { version: "1.0.0", license: "SEE LICENSE IN LICENSE" },
  "node_modules/none": { version: "1.0.0" },
} });
const sbom = { bomFormat: "CycloneDX", specVersion: "1.5", components: [
  { type: "library", name: "a", version: "1", purl: "pkg:npm/a@1", licenses: [{ license: { id: "MIT" } }] },
  { type: "library", name: "b", version: "1", purl: "pkg:npm/b@1", licenses: [{ license: { id: "AGPL-3.0-only" } }] },
] };

describe("0 sbom licenses", () => {
  it("reads a folder, groups by verdict and exits 1 on a violation", async () => {
    const dir = project({ "package-lock.json": lock });
    const { out, deps } = io();
    expect(await runLicenses(dir, { preset: "permissive" }, deps)).toBe(1);
    const text = out.join("");
    expect(text).toMatch(/Not allowed \(1\)\n {2}gpl@2\.0\.0 {2}GPL-3\.0-only/);
    expect(text).toMatch(/Unknown \(2\)/);
    expect(text).toContain("SEE LICENSE IN LICENSE");
    expect(text).toContain("5 components: 0 denied, 1 not allowed, 2 unknown, 2 allowed.");
    expect(text).toContain("not legal advice");
    expect(text.match(/not legal advice/g)).toHaveLength(1);
  });
  it("exits 0 when nothing violates, and unknown=fail turns unknown into a violation", async () => {
    const dir = project({ "package-lock.json": lock });
    expect(await runLicenses(dir, { allow: "MIT,GPL-3.0-only" }, io().deps)).toBe(0);
    expect(await runLicenses(dir, { allow: "MIT,GPL-3.0-only", unknown: "fail" }, io().deps)).toBe(1);
    expect(await runLicenses(dir, { allow: "MIT,GPL-3.0-only", unknown: "allow" }, io().deps)).toBe(0);
  });
  it("reads a CycloneDX file and rejects other files", async () => {
    const dir = project({ "sbom.json": JSON.stringify(sbom), "other.json": "{}", "bad.json": "not json" });
    const { out, deps } = io();
    expect(await runLicenses(join(dir, "sbom.json"), { deny: "AGPL-*", format: "json" }, deps)).toBe(1);
    const json = JSON.parse(out.join(""));
    expect(json.summary).toMatchObject({ total: 2, denied: 1, allowed: 1, violations: 1 });
    expect(json.components.find((c: { name: string }) => c.name === "b")).toMatchObject({ verdict: "denied", causes: ["AGPL-3.0-only"] });
    await expect(runLicenses(join(dir, "other.json"), { preset: "permissive" }, io().deps)).rejects.toThrow("not a CycloneDX SBOM");
    await expect(runLicenses(join(dir, "bad.json"), { preset: "permissive" }, io().deps)).rejects.toThrow("not a JSON SBOM");
    await expect(runLicenses(join(dir, "missing.json"), { preset: "permissive" }, io().deps)).rejects.toThrow("does not exist");
  });
  it("writes SARIF located at the lockfile that lists the component", async () => {
    const dir = project({ "package-lock.json": lock, "sub/package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/deep": { version: "1.0.0", license: "GPL-2.0-only" } } }) });
    const { out, deps } = io();
    expect(await runLicenses(dir, { preset: "permissive", format: "sarif" }, deps)).toBe(1);
    const results = JSON.parse(out.join("")).runs[0].results as Array<{ ruleId: string; locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }> }>;
    expect(results.find(result => result.ruleId === "license/GPL-2.0-only")!.locations[0]!.physicalLocation.artifactLocation.uri).toMatch(/sub\/package-lock\.json$/);
    expect(results.find(result => result.ruleId === "license/GPL-3.0-only")!.locations[0]!.physicalLocation.artifactLocation.uri).toMatch(/package-lock\.json$/);
  });
  it("skips development-only components with --exclude-dev", async () => {
    const dir = project({ "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/dev": { version: "1.0.0", license: "GPL-3.0-only", dev: true } } }) });
    expect(await runLicenses(dir, { preset: "permissive" }, io().deps)).toBe(1);
    expect(await runLicenses(dir, { preset: "permissive", excludeDev: true }, io().deps)).toBe(0);
  });
});

describe("policy building and usage errors", () => {
  it("needs a policy, and rejects bad ids, presets, modes and formats", async () => {
    expect(() => buildPolicy({})).toThrow(UsageError);
    expect(() => buildPolicy({ allow: "Apache2" })).toThrow("not an SPDX license id");
    expect(() => buildPolicy({ preset: "strict" })).toThrow("Unknown preset");
    expect(() => buildPolicy({ preset: "permissive", unknown: "ignore" })).toThrow("--unknown");
    await expect(runLicenses(".", { preset: "permissive", format: "xml" }, io().deps)).rejects.toThrow("--format");
    await expect(runLicenses(project({ "readme.md": "x" }), { preset: "permissive" }, io().deps)).rejects.toThrow("No supported lockfile");
  });
  it("reads a JSON or a YAML policy file with an exception, and rejects typos and a missing reason", async () => {
    const dir = project({
      "policy.json": JSON.stringify({ allow: ["MIT"], unknown: "fail", allowByPackage: [{ package: "gpl", reason: "reviewed by legal" }] }),
      "policy.yaml": "preset: no-copyleft\ndeny:\n  - MIT\nunknown: allow\n",
      "typo.yaml": "alow: [MIT]\n",
      "noreason.json": JSON.stringify({ allow: ["MIT"], allowByPackage: [{ package: "x" }] }),
    });
    const json = buildPolicy({ policy: join(dir, "policy.json") });
    expect(json).toMatchObject({ allow: ["MIT"], unknown: "fail", allowByPackage: [{ package: "gpl", reason: "reviewed by legal" }] });
    expect(buildPolicy({ policy: join(dir, "policy.yaml") })).toMatchObject({ deny: expect.arrayContaining(["GPL-*", "MIT"]), unknown: "allow" });
    expect(() => buildPolicy({ policy: join(dir, "typo.yaml") })).toThrow("Unknown policy key");
    expect(() => buildPolicy({ policy: join(dir, "noreason.json") })).toThrow("reason is required");
    expect(() => buildPolicy({ policy: join(dir, "nope.json") })).toThrow("Cannot read the policy file");
    const { out, deps } = io();
    const lockDir = project({ "package-lock.json": lock });
    expect(await runLicenses(lockDir, { policy: join(dir, "policy.json"), unknown: "allow" }, deps)).toBe(0);
    expect(out.join("")).toContain("Allowed by exception (1)");
    expect(out.join("")).toContain("reviewed by legal");
  });
  it("lets a flag extend a preset and the --unknown flag override the file", () => {
    const policy = buildPolicy({ preset: "permissive", allow: "MPL-2.0", deny: "ISC", unknown: "fail" });
    expect(policy.allow).toContain("MPL-2.0");
    expect(policy.deny).toEqual(["ISC"]);
    expect(policy.unknown).toBe("fail");
  });
});

describe("registration and SARIF import", () => {
  it("is a subcommand of sbom, sets the exit code and exits 2 on a usage error", async () => {
    const dir = project({ "package-lock.json": lock });
    const { out, err, deps } = io();
    const program = new Command().exitOverride();
    registerSbomCommand(program, deps);
    const previous = process.exitCode;
    await program.parseAsync(["node", "0", "sbom", "licenses", dir, "--preset", "permissive"]);
    expect(process.exitCode).toBe(1);
    expect(out.join("")).toContain("Not allowed (1)");
    process.exitCode = undefined;
    await program.parseAsync(["node", "0", "sbom", "licenses", dir]);
    expect(process.exitCode).toBe(2);
    expect(err.join("\n")).toContain("Give a policy");
    process.exitCode = previous;
  });
  it("produces SARIF that 0 findings import reads: rule id, path and a fingerprint per result", async () => {
    const { parseSarif } = await import("@0/engine/shared");
    const dir = project({ "package-lock.json": lock });
    vi.spyOn(process, "cwd").mockReturnValue(dir);
    const { out, deps } = io();
    await runLicenses(dir, { preset: "permissive", format: "sarif" }, deps);
    const imported = parseSarif(out.join(""), { roots: [dir] });
    const gpl = imported.findings.find(finding => finding.ruleId === "license/GPL-3.0-only");
    expect(gpl).toMatchObject({ severity: "high", path: "package-lock.json" });
    expect(imported.findings.map(finding => finding.ruleId).sort()).toEqual(["license/GPL-3.0-only", "license/unknown", "license/unknown"]);
    expect(new Set(imported.findings.map(finding => finding.fingerprint)).size).toBe(3);
    const again = io();
    await runLicenses(dir, { preset: "permissive", format: "sarif" }, again.deps);
    expect(parseSarif(again.out.join("")).findings.map(finding => finding.fingerprint)).toEqual(imported.findings.map(finding => finding.fingerprint));
  });
});

describe("--resolve", () => {
  const body = (status: number, json?: unknown) => ({ status, ok: status >= 200 && status < 300, json: async () => json });
  it("maps package URLs to deps.dev keys", () => {
    expect(depsDevKey("pkg:npm/%40scope/name@1.2.3")).toEqual({ system: "npm", name: "@scope/name", version: "1.2.3" });
    expect(depsDevKey("pkg:golang/golang.org/x/net@v0.17.0")).toEqual({ system: "go", name: "golang.org/x/net", version: "v0.17.0" });
    expect(depsDevKey("pkg:maven/junit/junit@4.13.2")).toEqual({ system: "maven", name: "junit:junit", version: "4.13.2" });
    expect(depsDevKey("pkg:cargo/base64@0.22.1")).toEqual({ system: "cargo", name: "base64", version: "0.22.1" });
    expect(depsDevKey("pkg:hex/plug@1.0.0")).toBeUndefined();
    expect(depsDevKey("pkg:npm/noversion")).toBeUndefined();
  });
  it("looks up only components with no license, counts the outcomes and judges the result", async () => {
    const dir = project({ "sbom.json": JSON.stringify({ bomFormat: "CycloneDX", components: [
      { name: "has", version: "1", purl: "pkg:npm/has@1", licenses: [{ license: { id: "MIT" } }] },
      { name: "mit", version: "1", purl: "pkg:cargo/mit@1" },
      { name: "gpl", version: "1", purl: "pkg:pypi/gpl@1" },
      { name: "gone", version: "1", purl: "pkg:npm/gone@1" },
      { name: "weird", version: "1", purl: "pkg:npm/weird@1" },
      { name: "down", version: "1", purl: "pkg:npm/down@1" },
      { name: "mix", version: "1", purl: "pkg:hex/mix@1" },
    ] }) });
    const urls: string[] = [];
    const fetch = vi.fn(async (url: string) => {
      urls.push(url);
      if (url.includes("/cargo/")) return body(200, { licenses: ["Apache-2.0 OR MIT"] });
      if (url.includes("/pypi/")) return body(200, { licenses: ["GPL-3.0-only"] });
      if (url.includes("/gone/")) return body(404);
      if (url.includes("/weird/")) return body(200, { licenses: ["non-standard"] });
      return body(500);
    });
    const { out, err, deps } = io({ fetch: fetch as unknown as typeof globalThis.fetch });
    expect(await runLicenses(join(dir, "sbom.json"), { preset: "permissive", resolve: true, format: "json" }, deps)).toBe(1);
    expect(urls).toHaveLength(5);
    expect(urls.some(url => url.includes("/has/"))).toBe(false);
    expect(urls.find(url => url.includes("/cargo/"))).toBe("https://api.deps.dev/v3/systems/cargo/packages/mit/versions/1");
    const json = JSON.parse(out.join(""));
    const verdict = (name: string) => json.components.find((c: { name: string }) => c.name === name);
    expect(verdict("mit")).toMatchObject({ verdict: "allowed", resolved: true });
    expect(verdict("gpl")).toMatchObject({ verdict: "not-allowed", resolved: true });
    expect(verdict("gone").verdict).toBe("unknown");
    expect(verdict("weird").verdict).toBe("unknown");
    expect(verdict("has").resolved).toBeUndefined();
    expect(err.join("\n")).toContain("Looked up 5 components on deps.dev: 3 with license data, 1 not found or without one, 1 failed. 1 are in ecosystems deps.dev does not cover.");
  });
  it("stops at --resolve-limit and never calls the network without --resolve", async () => {
    const dir = project({ "sbom.json": JSON.stringify({ bomFormat: "CycloneDX", components: [1, 2, 3].map(n => ({ name: `p${n}`, version: "1", purl: `pkg:npm/p${n}@1` })) }) });
    const fetch = vi.fn(async () => body(404));
    const limited = io({ fetch: fetch as unknown as typeof globalThis.fetch });
    await runLicenses(join(dir, "sbom.json"), { preset: "permissive", resolve: true, resolveLimit: "2" }, limited.deps);
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(limited.err.join("\n")).toContain("1 were not looked up because of --resolve-limit 2");
    fetch.mockClear();
    await runLicenses(join(dir, "sbom.json"), { preset: "permissive" }, io({ fetch: fetch as unknown as typeof globalThis.fetch }).deps);
    expect(fetch).not.toHaveBeenCalled();
    await expect(runLicenses(join(dir, "sbom.json"), { preset: "permissive", resolve: true, resolveLimit: "0" }, io().deps)).rejects.toThrow("--resolve-limit");
  });
});
