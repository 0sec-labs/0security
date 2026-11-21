import { describe, expect, it } from "vitest";
import { classifyLicense, generateSbom, parseCargoLock, parseComposerLock, parseGemfileLock, parseNpmLock, parsePnpmLock, parsePoetryLock, parseYarnLock, sriToHashes } from "./index.js";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const LODASH_SRI = "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==";
const LODASH_HEX = Buffer.from(LODASH_SRI.slice(7), "base64").toString("hex");
const SHA256_HEX = "a".repeat(64);
const SHA1_HEX = "b".repeat(40);
const find = <T extends { name: string }>(list: T[], name: string): T => list.find(item => item.name === name)!;
const refsOf = (list: Array<{ name: string; version: string }> | undefined) => (list ?? []).map(item => `${item.name}@${item.version}`).sort();

describe("integrity values", () => {
  it("converts a Subresource Integrity string to hex, and only when the length fits the algorithm", () => {
    expect(sriToHashes(LODASH_SRI)).toEqual([{ alg: "SHA-512", content: LODASH_HEX }]);
    expect(LODASH_HEX).toHaveLength(128);
    expect(sriToHashes(`sha1-${Buffer.alloc(20, 1).toString("base64")}`)).toEqual([{ alg: "SHA-1", content: "01".repeat(20) }]);
    expect(sriToHashes("sha512-AAAA")).toEqual([]);          // too short for SHA-512
    expect(sriToHashes("md5-AAAAAAAAAAAAAAAAAAAAAA==")).toEqual([]); // unsupported algorithm
    expect(sriToHashes("sha256-not base64!")).toEqual([]);
    expect(sriToHashes(undefined)).toEqual([]);
  });
});

describe("npm lockfile v3: hashes, graph, licenses", () => {
  const lock = JSON.stringify({
    name: "app", lockfileVersion: 3,
    packages: {
      "": { name: "app", dependencies: { express: "^4" } },
      "node_modules/express": { version: "4.18.2", integrity: LODASH_SRI, license: "MIT", dependencies: { qs: "6.11.0", debug: "2.6.9" }, optionalDependencies: { missing: "1" } },
      "node_modules/qs": { version: "6.11.0", license: "BSD-3-Clause" },
      "node_modules/debug": { version: "4.3.4", license: "MIT" },
      "node_modules/express/node_modules/debug": { version: "2.6.9", license: "MIT" },
      "node_modules/weird": { version: "1.0.0", license: "SEE LICENSE IN LICENSE.txt" },
    },
  });
  it("resolves each dependency the way node does (nested folder first)", () => {
    const components = parseNpmLock(lock);
    expect(refsOf(find(components, "express").dependsOn)).toEqual(["debug@2.6.9", "qs@6.11.0"]);
    expect(find(components, "qs").dependsOn).toEqual([]);
    expect(find(components, "express").hashes).toEqual([{ alg: "SHA-512", content: LODASH_HEX }]);
    expect(find(components, "express").licenses).toEqual(["MIT"]);
  });
});

describe("pnpm lockfile", () => {
  it("v9: reads hashes from packages and the graph from snapshots, stripping peer suffixes", () => {
    const lock = [
      "lockfileVersion: '9.0'", "packages:",
      `  react-dom@18.2.0:`, `    resolution: {integrity: ${LODASH_SRI}}`,
      `  react@18.2.0:`, `    resolution: {integrity: ${LODASH_SRI}}`,
      `  scheduler@0.23.0:`, `    resolution: {tarball: https://example.test/s.tgz}`,
      "snapshots:",
      "  react-dom@18.2.0(react@18.2.0):", "    dependencies:", "      react: 18.2.0", "      scheduler: 0.23.0",
      "  react@18.2.0: {}", "  scheduler@0.23.0: {}", "",
    ].join("\n");
    const components = parsePnpmLock(lock);
    expect(refsOf(find(components, "react-dom").dependsOn)).toEqual(["react@18.2.0", "scheduler@0.23.0"]);
    expect(find(components, "react-dom").hashes).toEqual([{ alg: "SHA-512", content: LODASH_HEX }]);
    expect(find(components, "scheduler").hashes).toBeUndefined();
    expect(find(components, "scheduler").dependsOn).toEqual([]);
  });
  it("v6: dependencies sit on the package, values may be /name@version", () => {
    const lock = "lockfileVersion: '6.0'\npackages:\n  /a@1.0.0:\n    resolution: {integrity: " + LODASH_SRI + "}\n    dependencies:\n      b: 2.0.0\n      c: /c-alias@3.0.0\n      d: link:../d\n  /b@2.0.0:\n    resolution: {integrity: " + LODASH_SRI + "}\n  /c-alias@3.0.0:\n    resolution: {integrity: " + LODASH_SRI + "}\n";
    expect(refsOf(find(parsePnpmLock(lock), "a").dependsOn)).toEqual(["b@2.0.0", "c-alias@3.0.0"]);
  });
});

describe("yarn.lock", () => {
  it("classic: integrity and the graph through the version ranges", () => {
    const lock = `# yarn lockfile v1\n\n\nexpress@^4.18.0:\n  version "4.18.2"\n  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz#abc"\n  integrity ${LODASH_SRI}\n  dependencies:\n    qs "6.11.0"\n    ms "^2.0.0"\n\nqs@6.11.0:\n  version "6.11.0"\n  integrity ${LODASH_SRI}\n\n"ms@^2.0.0", ms@^2.1.1:\n  version "2.1.3"\n`;
    const components = parseYarnLock(lock);
    expect(refsOf(find(components, "express").dependsOn)).toEqual(["ms@2.1.3", "qs@6.11.0"]);
    expect(find(components, "express").hashes?.[0]?.content).toBe(LODASH_HEX);
    expect(find(components, "ms").hashes).toBeUndefined();
  });
  it("berry: the graph resolves, and checksum (a hash of Yarn's archive, not the tarball) is not reported", () => {
    const lock = `__metadata:\n  version: 6\n\n"chalk@npm:^4.0.0":\n  version: 4.1.2\n  resolution: "chalk@npm:4.1.2"\n  dependencies:\n    ansi-styles: ^4.1.0\n  checksum: ${"c".repeat(128)}\n  languageName: node\n  linkType: hard\n\n"ansi-styles@npm:^4.1.0":\n  version: 4.3.0\n  resolution: "ansi-styles@npm:4.3.0"\n  languageName: node\n  linkType: hard\n`;
    const components = parseYarnLock(lock);
    expect(refsOf(find(components, "chalk").dependsOn)).toEqual(["ansi-styles@4.3.0"]);
    expect(find(components, "chalk").hashes).toBeUndefined();
  });
});

describe("Cargo.lock", () => {
  const registry = 'source = "registry+https://github.com/rust-lang/crates.io-index"';
  const lock = `version = 3\n\n[[package]]\nname = "mine"\nversion = "0.1.0"\ndependencies = [\n "serde",\n]\n\n[[package]]\nname = "serde"\nversion = "1.0.190"\n${registry}\nchecksum = "${SHA256_HEX}"\ndependencies = [\n "serde_derive",\n "rand 0.8.5",\n]\n\n[[package]]\nname = "serde_derive"\nversion = "1.0.190"\n${registry}\nchecksum = "not-hex"\n\n[[package]]\nname = "rand"\nversion = "0.8.5"\n${registry}\n\n[[package]]\nname = "rand"\nversion = "0.7.3"\n${registry}\n`;
  it("reads the sha256 checksum and resolves bare and versioned dependency names", () => {
    const components = parseCargoLock(lock);
    expect(find(components, "serde").hashes).toEqual([{ alg: "SHA-256", content: SHA256_HEX }]);
    expect(refsOf(find(components, "serde").dependsOn)).toEqual(["rand@0.8.5", "serde_derive@1.0.190"]);
    expect(find(components, "serde_derive").hashes).toBeUndefined();   // not a valid digest
    expect(components.some(component => component.name === "mine")).toBe(false);
  });
});

describe("poetry.lock", () => {
  const lock = `[[package]]\nname = "requests"\nversion = "2.31.0"\ndescription = "x"\noptional = false\npython-versions = ">=3.7"\nfiles = [\n    {file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:${SHA256_HEX}"},\n    {file = "requests-2.31.0.tar.gz", hash = "sha256:${"d".repeat(64)}"},\n]\n\n[package.dependencies]\ncertifi = ">=2017.4.17"\nurllib3 = {version = ">=1.21.1,<3", extras = ["x"]}\n"charset_normalizer" = ">=2,<4"\n\n[[package]]\nname = "certifi"\nversion = "2023.7.22"\nfiles = [\n    {file = "certifi-2023.7.22.tar.gz", hash = "sha256:${SHA256_HEX}"},\n]\n\n[[package]]\nname = "urllib3"\nversion = "2.0.7"\nfiles = []\n\n[package.extras]\nsocks = ["PySocks"]\n\n[metadata]\nlock-version = "2.0"\n`;
  it("resolves dependencies by normalised name, and gives a hash only for a single-file package", () => {
    const components = parsePoetryLock(lock);
    expect(refsOf(find(components, "requests").dependsOn)).toEqual(["certifi@2023.7.22", "urllib3@2.0.7"]);
    expect(find(components, "requests").hashes).toBeUndefined();   // two files: no single artifact
    expect(find(components, "certifi").hashes).toEqual([{ alg: "SHA-256", content: SHA256_HEX }]);
    expect(find(components, "urllib3").dependsOn).toEqual([]);
  });
});

describe("Gemfile.lock", () => {
  const lock = `GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.2)\n      actionpack (= 7.1.2)\n      rack\n    actionpack (7.1.2)\n      rack (>= 2.2.4)\n    rack (3.0.8)\n    nokogiri (1.15.5-x86_64-linux)\n    nokogiri (1.15.5-arm64-darwin)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails\n\nCHECKSUMS\n  actionpack (7.1.2) sha256=${SHA256_HEX}\n  nokogiri (1.15.5-x86_64-linux) sha256=${"e".repeat(64)}\n  nokogiri (1.15.5-arm64-darwin) sha256=${"f".repeat(64)}\n  rack (3.0.8) sha256=${"1".repeat(64)}\n  rails (7.1.2)\n\nBUNDLED WITH\n   2.5.3\n`;
  it("nests dependencies from the spec lines, and reads CHECKSUMS only where one build is unambiguous", () => {
    const components = parseGemfileLock(lock);
    expect(refsOf(find(components, "rails").dependsOn)).toEqual(["actionpack@7.1.2", "rack@3.0.8"]);
    expect(find(components, "actionpack").hashes).toEqual([{ alg: "SHA-256", content: SHA256_HEX }]);
    expect(find(components, "rails").hashes).toBeUndefined();       // no checksum recorded
    expect(find(components, "nokogiri").hashes).toBeUndefined();    // two platform builds
    expect(components.filter(component => component.name === "nokogiri")).toHaveLength(1);
  });
});

describe("composer.lock", () => {
  const lock = JSON.stringify({ packages: [
    { name: "monolog/monolog", version: "3.5.0", dist: { type: "zip", url: "https://x", shasum: "" }, require: { php: ">=8.1", "psr/log": "^2" }, license: ["MIT"] },
    { name: "psr/log", version: "2.0.0", dist: { type: "zip", url: "https://x", shasum: SHA1_HEX }, license: ["MIT", "Custom Terms"] },
  ] });
  it("takes dist.shasum (SHA-1), require edges (not php) and the license list", () => {
    const components = parseComposerLock(lock);
    expect(find(components, "psr/log").hashes).toEqual([{ alg: "SHA-1", content: SHA1_HEX }]);
    expect(find(components, "monolog/monolog").hashes).toBeUndefined();
    expect(refsOf(find(components, "monolog/monolog").dependsOn)).toEqual(["psr/log@2.0.0"]);
    expect(find(components, "psr/log").licenses).toEqual(["MIT", "Custom Terms"]);
  });
});

describe("license classification", () => {
  it("id for a valid SPDX id, expression for a valid expression, the stated name otherwise", () => {
    expect(classifyLicense("MIT")).toEqual({ license: { id: "MIT" } });
    expect(classifyLicense("(MIT OR Apache-2.0)")).toEqual({ expression: "(MIT OR Apache-2.0)" });
    expect(classifyLicense("GPL-2.0-only WITH Classpath-exception-2.0")).toEqual({ expression: "GPL-2.0-only WITH Classpath-exception-2.0" });
    expect(classifyLicense("mit")).toEqual({ license: { name: "mit" } });   // wrong case: not guessed
    expect(classifyLicense("SEE LICENSE IN LICENSE.txt")).toEqual({ license: { name: "SEE LICENSE IN LICENSE.txt" } });
    expect(classifyLicense("MIT OR")).toEqual({ license: { name: "MIT OR" } });
    expect(classifyLicense("MIT AND Nope-1.0")).toEqual({ license: { name: "MIT AND Nope-1.0" } });
  });
});

describe("generateSbom with hashes, graph and licenses", () => {
  const dirs: string[] = [];
  const folder = (files: Record<string, string>) => { const dir = mkdtempSync(join(tmpdir(), "0-depth-")); dirs.push(dir); for (const [path, content] of Object.entries(files)) { mkdirSync(join(dir, path, ".."), { recursive: true }); writeFileSync(join(dir, path), content); } return dir; };
  it("emits sorted hashes, licenses and a dependencies array whose refs all exist", () => {
    try {
      const dir = folder({ "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/b": { version: "1.0.0", integrity: LODASH_SRI, license: "MIT", dependencies: { a: "1", gone: "1" } }, "node_modules/a": { version: "1.0.0", license: "(MIT OR Apache-2.0)" } } }) });
      const { bom } = generateSbom(dir, { toolVersion: "0", now: new Date(0) });
      const b = bom.components.find(component => component.name === "b")!;
      expect(b).toMatchObject({ hashes: [{ alg: "SHA-512", content: LODASH_HEX }], licenses: [{ license: { id: "MIT" } }] });
      expect(bom.components.find(component => component.name === "a")).toMatchObject({ licenses: [{ expression: "(MIT OR Apache-2.0)" }] });
      expect(bom.dependencies).toEqual([{ ref: "pkg:npm/a@1.0.0", dependsOn: [] }, { ref: "pkg:npm/b@1.0.0", dependsOn: ["pkg:npm/a@1.0.0"] }]);
      const refs = new Set(bom.components.map(component => component["bom-ref"]));
      for (const dependency of bom.dependencies!) for (const ref of [dependency.ref, ...dependency.dependsOn]) expect(refs.has(ref)).toBe(true);
    } finally { dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true })); }
  });
  it("omits dependencies when no lockfile records a graph", () => {
    try {
      expect(generateSbom(folder({ "go.mod": "module x\nrequire github.com/a/b v1.0.0\n" }), { toolVersion: "0" }).bom.dependencies).toBeUndefined();
    } finally { dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true })); }
  });
  it("drops a hash that two lockfiles disagree on and unions their edges", () => {
    try {
      const entry = (integrity: string, deps: Record<string, string>) => JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/a": { version: "1.0.0", integrity, dependencies: deps }, "node_modules/x": { version: "1.0.0" }, "node_modules/y": { version: "1.0.0" } } });
      const other = `sha512-${Buffer.alloc(64, 7).toString("base64")}`;
      const { bom } = generateSbom(folder({ "package-lock.json": entry(LODASH_SRI, { x: "1" }), "sub/package-lock.json": entry(other, { y: "1" }) }), { toolVersion: "0" });
      expect(bom.components.find(component => component.name === "a")).not.toHaveProperty("hashes");
      expect(bom.dependencies!.find(dependency => dependency.ref === "pkg:npm/a@1.0.0")!.dependsOn).toEqual(["pkg:npm/x@1.0.0", "pkg:npm/y@1.0.0"]);
    } finally { dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true })); }
  });
});
