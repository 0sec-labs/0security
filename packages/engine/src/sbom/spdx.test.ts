import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Ajv from "ajv";
import { afterEach, describe, expect, it } from "vitest";
import { generateSbom, toSpdx } from "./index.js";

// The official SPDX 2.3 JSON schema (Apache-2.0, from the spdx-spec repository, tag v2.3), vendored so this check needs no network.
const schema = JSON.parse(readFileSync(join(import.meta.dirname, "..", "..", "test-fixtures", "spdx", "spdx-2.3-schema.json"), "utf8"));
const validate = new Ajv({ strict: false, allErrors: true, validateFormats: false }).compile(schema);
const problems = () => (validate.errors ?? []).slice(0, 5).map(error => `${error.instancePath} ${error.message}`);

const dirs: string[] = [];
afterEach(() => dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true })));
const folder = (files: Record<string, string>) => { const dir = mkdtempSync(join(tmpdir(), "0-spdx-")); dirs.push(dir); for (const [path, content] of Object.entries(files)) { mkdirSync(join(dir, path, ".."), { recursive: true }); writeFileSync(join(dir, path), content); } return dir; };
const sri = `sha512-${Buffer.alloc(64, 9).toString("base64")}`;

describe("toSpdx", () => {
  const lock = JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/a": { version: "1.0.0", integrity: sri, license: "MIT", dependencies: { b: "1" } }, "node_modules/b": { version: "2.0.0", license: "(MIT OR Apache-2.0)" }, "node_modules/@s/c": { version: "3.0.0", license: "SEE LICENSE IN X" } } });
  const build = () => toSpdx(generateSbom(folder({ "package-lock.json": lock, "go.mod": "module x\nrequire example.com/a/b v1.0.0\n" }), { name: "my app", toolVersion: "1.2.3", now: new Date("2026-01-02T03:04:05.678Z") }).bom);

  it("is valid SPDX 2.3 JSON by the official schema", () => {
    expect(validate(build()), problems().join("; ")).toBe(true);
  });
  it("describes the application, lists purls, checksums and licenses, and writes DEPENDS_ON from the graph", () => {
    const doc = build();
    expect(doc).toMatchObject({ spdxVersion: "SPDX-2.3", dataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", name: "my app", creationInfo: { created: "2026-01-02T03:04:05Z", creators: ["Tool: 0-1.2.3"] } });
    expect(doc.documentNamespace).toMatch(/^https:\/\/spdx\.org\/spdxdocs\/my%20app-[0-9a-f-]{36}$/);
    const a = doc.packages.find(item => item.name === "a")!;
    expect(a.externalRefs).toEqual([{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: "pkg:npm/a@1.0.0" }]);
    expect(a.checksums).toEqual([{ algorithm: "SHA512", checksumValue: Buffer.alloc(64, 9).toString("hex") }]);
    expect(a.licenseDeclared).toBe("MIT");
    expect(doc.packages.find(item => item.name === "b")!.licenseDeclared).toBe("(MIT OR Apache-2.0)");
    expect(doc.packages.find(item => item.name === "@s/c")!.licenseDeclared).toBe("NOASSERTION");
    const id = (name: string) => doc.packages.find(item => item.name === name)!.SPDXID;
    expect(doc.relationships).toContainEqual({ spdxElementId: "SPDXRef-DOCUMENT", relatedSpdxElement: "SPDXRef-RootPackage", relationshipType: "DESCRIBES" });
    expect(doc.relationships).toContainEqual({ spdxElementId: id("a"), relatedSpdxElement: id("b"), relationshipType: "DEPENDS_ON" });
    // b is depended on by a, so the application does not list it directly; a and the Go module (no graph) are top level.
    expect(doc.relationships).not.toContainEqual({ spdxElementId: "SPDXRef-RootPackage", relatedSpdxElement: id("b"), relationshipType: "DEPENDS_ON" });
    expect(doc.relationships).toContainEqual({ spdxElementId: "SPDXRef-RootPackage", relatedSpdxElement: id("a"), relationshipType: "DEPENDS_ON" });
    expect(doc.relationships).toContainEqual({ spdxElementId: "SPDXRef-RootPackage", relatedSpdxElement: id("example.com/a/b"), relationshipType: "DEPENDS_ON" });
    const ids = doc.packages.map(item => item.SPDXID);
    expect(new Set(ids).size).toBe(ids.length);
  });
  it("the validator is real: a package without a download location is rejected", () => {
    expect(validate({ ...build(), packages: [{ SPDXID: "SPDXRef-x", name: "x" }] })).toBe(false);
  });
});
