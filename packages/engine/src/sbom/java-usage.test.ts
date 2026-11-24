import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { javaUsageToText, parseDependencyReport, parseImports, resolveJvmDependencies, scanJavaUsage } from "./index.js";

const real = join(import.meta.dirname, "fixtures", "jvm", "real");
const text = (name: string) => readFileSync(join(real, name), "utf8");

// maven-dependency-tree.txt and gradle-dependencies.txt are the unedited output of Maven 3.9 (`dependency:tree -DoutputType=text`)
// and Gradle 9 (`dependencies --configuration runtimeClasspath`) on two small projects that pull log4j-core 2.14.1 and commons-text 1.9.
describe("parseDependencyReport on real tool output", () => {
  it("reads a Maven dependency:tree file, with test scope marked dev", () => {
    const report = parseDependencyReport(text("maven-dependency-tree.txt"));
    expect(report.tool).toBe("mvn");
    const byName = new Map(report.components.map(component => [component.name, component]));
    expect([...byName.keys()].sort()).toEqual(["junit/junit", "org.apache.commons/commons-lang3", "org.apache.commons/commons-text", "org.apache.logging.log4j/log4j-api", "org.apache.logging.log4j/log4j-core", "org.hamcrest/hamcrest-core"]);
    expect(byName.get("org.apache.logging.log4j/log4j-core")).toMatchObject({ version: "2.14.1", resolved: true, dependsOn: [{ name: "org.apache.logging.log4j/log4j-api", version: "2.14.1" }] });
    expect(byName.get("junit/junit")?.dev).toBe(true);
    expect(byName.get("org.hamcrest/hamcrest-core")?.dev).toBe(true);
  });
  it("reads a Gradle dependency report", () => {
    const report = parseDependencyReport(text("gradle-dependencies.txt"));
    expect(report.tool).toBe("gradle");
    expect(report.components.map(component => `${component.name}@${component.version}`)).toContain("org.apache.commons/commons-lang3@3.11");
    expect(report.components.find(component => component.name === "com.google.guava/guava")?.dependsOn).toHaveLength(5);
  });
  it("gives nothing for text that is neither", () => {
    expect(parseDependencyReport("hello\n<html>")).toEqual({ tool: "unknown", components: [] });
  });
});

describe("parseImports", () => {
  it("reads Java, static, Kotlin and Scala imports and skips comments", () => {
    const source = ["package a;", "import java.util.List;", "import static org.junit.Assert.assertTrue;", "// import org.fake.Line;", "/* import org.fake.Block;", "import org.fake.InBlock; */", "import org.apache.commons.text.*;", "import kotlinx.coroutines.launch", "class X { String s = \"import not.a.Thing;\"; }"].join("\n");
    expect(parseImports(source).map(item => item.name)).toEqual(["java.util.List", "org.junit.Assert.assertTrue", "org.apache.commons.text.*", "kotlinx.coroutines.launch"]);
  });
});

describe("scanJavaUsage", () => {
  const components = [
    { name: "org.apache.logging.log4j/log4j-core", version: "2.14.1", purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" },
    { name: "org.apache.commons/commons-text", version: "1.9", purl: "pkg:maven/org.apache.commons/commons-text@1.9" },
    { name: "org.apache.commons/commons-lang3", version: "3.11", purl: "pkg:maven/org.apache.commons/commons-lang3@3.11" },
    { name: "org.hamcrest/hamcrest-core", version: "1.3", purl: "pkg:maven/org.hamcrest/hamcrest-core@1.3" },
  ];
  const report = scanJavaUsage(join(real, "app"), components);
  const get = (name: string) => report.usage.find(item => item.name === name)!;
  it("finds the log4j import in main code with its line", () => {
    expect(get("org.apache.logging.log4j/log4j-core")).toMatchObject({ verdict: "imported" });
    expect(get("org.apache.logging.log4j/log4j-core").imports[0]).toMatchObject({ path: "src/main/java/demo/App.java", line: 2, test: false });
  });
  it("marks an import that only test code makes", () => {
    expect(get("org.apache.commons/commons-text").imports).toEqual([{ path: "src/test/java/demo/AppTest.java", line: 3, import: "org.apache.commons.text.StringSubstitutor", test: true }]);
  });
  it("reports no import for a transitive dependency and does not credit it to a sibling in the same group", () => {
    expect(get("org.apache.commons/commons-lang3").verdict).toBe("no-import-found");
    expect(get("org.hamcrest/hamcrest-core").verdict).toBe("no-import-found");
  });
  it("says an import is not a call", () => {
    expect(javaUsageToText(report)).toContain("An import is not a call");
  });
});

describe("resolve options for mirrors", () => {
  it("passes the operator's settings file to mvn and init script to gradle", async () => {
    const root = mkdtempSync(join(tmpdir(), "0-mirror-"));
    const bin = join(root, "bin"); mkdirSync(bin);
    const log = join(root, "calls.log");
    writeFileSync(join(bin, "mvn"), `#!/bin/sh\necho "mvn $*" >> "${log}"\nfor a in "$@"; do case "$a" in -DoutputFile=*) cp "${join(real, "maven-dependency-tree.txt")}" "\${a#-DoutputFile=}";; esac; done\n`);
    writeFileSync(join(bin, "gradle"), `#!/bin/sh\necho "gradle $*" >> "${log}"\ncat "${join(real, "gradle-dependencies.txt")}"\n`);
    chmodSync(join(bin, "mvn"), 0o755); chmodSync(join(bin, "gradle"), 0o755);
    const dir = mkdtempSync(join(tmpdir(), "0-mirror-proj-"));
    writeFileSync(join(dir, "pom.xml"), "<project/>"); writeFileSync(join(dir, "build.gradle"), "");
    await resolveJvmDependencies(dir, { env: { PATH: `${bin}:/usr/bin:/bin` }, mavenSettings: "/ops/settings.xml", gradleInitScript: "/ops/mirror.init.gradle" });
    const calls = readFileSync(log, "utf8");
    expect(calls).toContain("-s /ops/settings.xml dependency:tree");
    expect(calls).toContain("-I /ops/mirror.init.gradle -p");
  });
});
