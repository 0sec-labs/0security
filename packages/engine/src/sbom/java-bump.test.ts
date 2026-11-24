import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { bumpJavaDependency, parseDependencyFinding } from "./java-bump.js";

const project = (files: Record<string, string>): string => {
  const dir = mkdtempSync(join(tmpdir(), "0-bump-"));
  for (const [name, text] of Object.entries(files)) { mkdirSync(join(dir, name, ".."), { recursive: true }); writeFileSync(join(dir, name), text); }
  return dir;
};
const dep = (g: string, a: string, v?: string, extra = "") => `<dependency><groupId>${g}</groupId><artifactId>${a}</artifactId>${v ? `<version>${v}</version>` : ""}${extra}</dependency>`;
const pom = (body: string, props = "") => `<project><modelVersion>4.0.0</modelVersion>${props ? `<properties>${props}</properties>` : ""}${body}</project>`;
const text = (dir: string, name: string) => readFileSync(join(dir, name), "utf8");
const CT = { name: "org.apache.commons/commons-text", fixedVersion: "1.10.0" };

describe("bumpJavaDependency: Maven", () => {
  it("changes a literal version and nothing else", () => {
    const dir = project({ "pom.xml": pom(`<dependencies>${dep("org.apache.commons", "commons-text", "1.9")}${dep("junit", "junit", "4.13.2")}</dependencies>`) });
    const result = bumpJavaDependency(dir, CT);
    expect(result).toEqual({ applied: true, edits: [{ path: "pom.xml", line: 1, was: "1.9", now: "1.10.0", where: "version" }] });
    expect(text(dir, "pom.xml")).toContain("<version>1.10.0</version>");
    expect(text(dir, "pom.xml")).toContain("<version>4.13.2</version>");
  });
  it("changes the property a version points at, in the pom that defines it, not a second version", () => {
    const dir = project({
      "pom.xml": pom("<modules><module>app</module></modules>", "<text.version>1.9</text.version>"),
      "app/pom.xml": pom(`<dependencies>${dep("org.apache.commons", "commons-text", "${text.version}")}</dependencies>`),
    });
    const result = bumpJavaDependency(dir, CT);
    expect(result).toMatchObject({ applied: true, edits: [{ path: "pom.xml", was: "1.9", now: "1.10.0", where: "property text.version" }] });
    expect(text(dir, "pom.xml")).toContain("<text.version>1.10.0</text.version>");
    expect(text(dir, "app/pom.xml")).toContain("${text.version}");
  });
  it("changes a dependencyManagement entry for a dependency that declares no version", () => {
    const dir = project({ "pom.xml": pom(`<dependencyManagement><dependencies>${dep("org.apache.commons", "commons-text", "1.9")}</dependencies></dependencyManagement><dependencies>${dep("org.apache.commons", "commons-text")}</dependencies>`) });
    expect(bumpJavaDependency(dir, CT)).toMatchObject({ applied: true });
    expect(text(dir, "pom.xml").match(/1\.10\.0/g)).toHaveLength(1);
  });
  it("never lowers a version and says it is already fixed", () => {
    const dir = project({ "pom.xml": pom(`<dependencies>${dep("org.apache.commons", "commons-text", "1.11.0")}</dependencies>`) });
    expect(bumpJavaDependency(dir, CT)).toEqual({ applied: false, reason: "org.apache.commons/commons-text is already at 1.10.0 or newer." });
    expect(text(dir, "pom.xml")).toContain("1.11.0");
  });
  it("declines a transitive package, an outside property and a range, and writes nothing", () => {
    const transitive = project({ "pom.xml": pom(`<dependencies>${dep("g", "other", "1")}</dependencies>`) });
    expect(bumpJavaDependency(transitive, CT)).toMatchObject({ applied: false, reason: expect.stringContaining("not declared") });
    const outside = project({ "pom.xml": pom(`<dependencies>${dep("org.apache.commons", "commons-text", "${external.version}")}</dependencies>`) });
    expect(bumpJavaDependency(outside, CT)).toMatchObject({ applied: false, reason: expect.stringContaining("outside it") });
    const range = project({ "pom.xml": pom(`<dependencies>${dep("org.apache.commons", "commons-text", "[1.0,2.0)")}</dependencies>`) });
    expect(bumpJavaDependency(range, CT)).toMatchObject({ applied: false, reason: expect.stringContaining("range") });
    expect(text(range, "pom.xml")).toContain("[1.0,2.0)");
  });
  it("leaves another version of the same package alone when the finding names the one it means", () => {
    const dir = project({ "pom.xml": pom(`<dependencies>${dep("org.apache.commons", "commons-text", "1.9")}</dependencies>`) });
    expect(bumpJavaDependency(dir, { ...CT, currentVersion: "1.8" })).toMatchObject({ applied: false });
  });
  it("refuses a fixed version that is not a version", () => {
    expect(bumpJavaDependency(project({ "pom.xml": pom("") }), { name: "a/b", fixedVersion: "1.0 && rm" })).toMatchObject({ applied: false });
  });
});

describe("bumpJavaDependency: Gradle", () => {
  it("changes a literal in build.gradle and build.gradle.kts", () => {
    const dir = project({
      "build.gradle": "dependencies {\n  implementation 'org.apache.commons:commons-text:1.9'\n  implementation 'junit:junit:4.13.2'\n}\n",
      "app/build.gradle.kts": 'dependencies { implementation("org.apache.commons:commons-text:1.9") }\n',
    });
    const result = bumpJavaDependency(dir, CT);
    expect(result).toMatchObject({ applied: true });
    expect(text(dir, "build.gradle")).toContain("'org.apache.commons:commons-text:1.10.0'");
    expect(text(dir, "build.gradle")).toContain("junit:junit:4.13.2");
    expect(text(dir, "app/build.gradle.kts")).toContain('"org.apache.commons:commons-text:1.10.0"');
  });
  it("changes a version catalog version through version.ref and a literal module version", () => {
    const viaRef = project({ "gradle/libs.versions.toml": '[versions]\ntext = "1.9"\n[libraries]\ncommons-text = { module = "org.apache.commons:commons-text", version.ref = "text" }\n' });
    expect(bumpJavaDependency(viaRef, CT)).toMatchObject({ applied: true, edits: [{ path: "gradle/libs.versions.toml", line: 2, where: "version text" }] });
    expect(text(viaRef, "gradle/libs.versions.toml")).toContain('text = "1.10.0"');
    const literal = project({ "gradle/libs.versions.toml": '[libraries]\ncommons-text = { group = "org.apache.commons", name = "commons-text", version = "1.9" }\nshort = "org.apache.commons:commons-text:1.9"\n' });
    expect(bumpJavaDependency(literal, CT)).toMatchObject({ applied: true });
    expect(text(literal, "gradle/libs.versions.toml")).toContain('version = "1.10.0"');
  });
  it("declines a variable version", () => {
    const dir = project({ "build.gradle": "dependencies { implementation \"org.apache.commons:commons-text:$textVersion\" }\n" });
    expect(bumpJavaDependency(dir, CT)).toMatchObject({ applied: false, reason: expect.stringContaining("variable") });
  });
});

describe("parseDependencyFinding", () => {
  it("reads the package, version and fixed version of an imported dependency finding", () => {
    expect(parseDependencyFinding("org.apache.commons/commons-text 1.9 has GHSA-599f-7c49-w659: Arbitrary code execution. Fixed in 1.10.0.")).toEqual({ name: "org.apache.commons/commons-text", currentVersion: "1.9", fixedVersion: "1.10.0" });
  });
  it("gives nothing for a finding that is not a dependency finding or has no fixed version", () => {
    expect(parseDependencyFinding("SQL injection in users.js")).toBeUndefined();
    expect(parseDependencyFinding("a/b 1.0 has GHSA-x: bad. No fixed version known.")).toBeUndefined();
  });
});
