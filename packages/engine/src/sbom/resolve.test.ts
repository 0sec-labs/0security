import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildToolEnv, generateSbom, LOCKFILES, mergeComponents, parseGradleTree, parseMavenTree, ResolveFailedError, resolveJvmDependencies } from "./index.js";

const MAVEN_TREE = [
  "com.example:api:jar:1.0.0",
  "+- com.google.guava:guava:jar:32.1.3-jre:compile",
  "|  +- com.google.guava:failureaccess:jar:1.0.1:compile",
  "|  \\- org.checkerframework:checker-qual:jar:3.37.0:compile",
  "+- com.example:worker:jar:1.0.0:compile",
  "|  \\- org.slf4j:slf4j-api:jar:2.0.12:compile",
  "\\- junit:junit:jar:4.13.2:test",
  "   \\- org.hamcrest:hamcrest-core:jar:1.3:test",
  "com.example:worker:jar:1.0.0",
  "\\- org.slf4j:slf4j-api:jar:2.0.12:compile",
  "",
].join("\n");

const GRADLE_TREE = [
  "------------------------------------------------------------",
  "Root project 'app'",
  "------------------------------------------------------------",
  "",
  "runtimeClasspath - Runtime classpath of source set 'main'.",
  "+--- org.apache.commons:commons-text:1.9",
  "|    \\--- org.apache.commons:commons-lang3:3.11",
  "+--- org.slf4j:slf4j-api:2.0.9 -> 2.0.12",
  "+--- com.fasterxml.jackson.core:jackson-databind -> 2.15.2",
  "|    +--- com.fasterxml.jackson.core:jackson-core:2.15.2 (*)",
  "|    \\--- org.apache.commons:commons-lang3:3.11 (*)",
  "+--- org.example:bom:1.0 (c)",
  "+--- org.example:strict:{strictly 1.4} -> 1.4",
  "+--- project :lib",
  "|    \\--- org.example:from-lib:3.0",
  "\\--- org.example:broken:1.0 FAILED",
  "",
  "(c) - A dependency constraint, not a dependency.",
].join("\n");

describe("parseMavenTree", () => {
  const components = parseMavenTree(MAVEN_TREE);
  const find = (name: string) => components.find(component => component.name === name);
  it("lists third-party components only, with their scope and edges", () => {
    expect(components.map(component => `${component.name}@${component.version}`)).toEqual([
      "com.google.guava/guava@32.1.3-jre", "com.google.guava/failureaccess@1.0.1", "org.checkerframework/checker-qual@3.37.0",
      "org.slf4j/slf4j-api@2.0.12", "junit/junit@4.13.2", "org.hamcrest/hamcrest-core@1.3",
    ]);
    expect(find("com.google.guava/guava")?.dependsOn).toEqual([{ name: "com.google.guava/failureaccess", version: "1.0.1" }, { name: "org.checkerframework/checker-qual", version: "3.37.0" }]);
    expect(find("junit/junit")?.dev).toBe(true);
    expect(find("org.hamcrest/hamcrest-core")?.dev).toBe(true);
    expect(find("org.slf4j/slf4j-api")?.dev).toBeUndefined();
  });
  it("drops modules of the build and edges to them", () => {
    expect(components.some(component => component.name.startsWith("com.example/"))).toBe(false);
  });
  it("reads a tree printed in the build log and ignores noise", () => {
    expect(parseMavenTree("[INFO] --- dependency:3.7.0:tree ---\n[INFO] demo:app:jar:1.0\n[INFO] \\- org.apache.commons:commons-text:jar:1.9:compile\n[INFO] BUILD SUCCESS").map(component => component.name)).toEqual(["org.apache.commons/commons-text"]);
    expect(parseMavenTree("not a tree\n<html>")).toEqual([]);
  });
});

describe("parseGradleTree", () => {
  const components = parseGradleTree(GRADLE_TREE);
  it("reads versions, forced versions and resolved ranges", () => {
    expect(components.map(component => `${component.name}@${component.version}`).sort()).toEqual([
      "com.fasterxml.jackson.core/jackson-core@2.15.2", "com.fasterxml.jackson.core/jackson-databind@2.15.2",
      "org.apache.commons/commons-lang3@3.11", "org.apache.commons/commons-text@1.9", "org.example/from-lib@3.0", "org.example/strict@1.4", "org.slf4j/slf4j-api@2.0.12",
    ]);
  });
  it("skips constraints, failures and project references, and keeps the edges that remain", () => {
    expect(components.find(component => component.name === "org.apache.commons/commons-text")?.dependsOn).toEqual([{ name: "org.apache.commons/commons-lang3", version: "3.11" }]);
    expect(components.find(component => component.name === "com.fasterxml.jackson.core/jackson-databind")?.dependsOn).toHaveLength(2);
    expect(components.some(component => component.name.includes("bom") || component.name.includes("broken"))).toBe(false);
  });
});

describe("mergeComponents", () => {
  it("unions edges and keeps dev only when every tree says dev", () => {
    const merged = mergeComponents([
      [{ ecosystem: "maven", name: "a/b", version: "1", dev: true, dependsOn: [{ name: "c/d", version: "1" }] }],
      [{ ecosystem: "maven", name: "a/b", version: "1", dependsOn: [{ name: "e/f", version: "2" }] }],
    ]);
    expect(merged).toHaveLength(1);
    expect(merged[0]!.dev).toBeUndefined();
    expect(merged[0]!.dependsOn).toHaveLength(2);
  });
});

/** A folder with fake `mvn` and `gradle` programs that print the shapes above. Nothing real runs. */
function fakeTools(options: { mvn?: string; gradle?: string } = {}): { bin: string; log: string } {
  const root = mkdtempSync(join(tmpdir(), "0-fake-jvm-"));
  const bin = join(root, "bin");
  mkdirSync(bin);
  const log = join(root, "calls.log");
  const mvnTree = join(root, "mvn-tree.txt");
  const gradleTree = join(root, "gradle-tree.txt");
  writeFileSync(mvnTree, MAVEN_TREE);
  writeFileSync(gradleTree, GRADLE_TREE);
  writeFileSync(join(bin, "mvn"), options.mvn ?? `#!/bin/sh\necho "mvn $* [$OPENAI_API_KEY]" >> "${log}"\nfor a in "$@"; do case "$a" in -DoutputFile=*) cp "${mvnTree}" "\${a#-DoutputFile=}";; esac; done\n`);
  writeFileSync(join(bin, "gradle"), options.gradle ?? `#!/bin/sh\necho "gradle $* [$OPENAI_API_KEY]" >> "${log}"\ncat "${gradleTree}"\n`);
  chmodSync(join(bin, "mvn"), 0o755);
  chmodSync(join(bin, "gradle"), 0o755);
  return { bin, log };
}
const project = (files: Record<string, string>): string => {
  const dir = mkdtempSync(join(tmpdir(), "0-jvm-project-"));
  for (const [name, text] of Object.entries(files)) { mkdirSync(join(dir, name, ".."), { recursive: true }); writeFileSync(join(dir, name), text); }
  return dir;
};

describe("resolveJvmDependencies with fake tools", () => {
  it("runs mvn with an argument array and a filtered environment, and parses the tree", async () => {
    const { bin, log } = fakeTools();
    const dir = project({ "pom.xml": "<project/>" });
    const result = await resolveJvmDependencies(dir, { env: { PATH: `${bin}:/usr/bin:/bin`, OPENAI_API_KEY: "must-not-reach-the-tool" }, offline: true });
    expect(result.tools).toEqual(["mvn"]);
    expect(result.components.map(component => component.name)).toContain("com.google.guava/guava");
    const call = readFileSync(log, "utf8");
    expect(call).toContain("-o dependency:tree -DoutputType=text");
    expect(call).toContain("[]"); // the key was filtered out of the tool's environment
    expect(call).not.toContain("must-not-reach-the-tool");
  });
  it("runs gradle once per project folder and merges the trees", async () => {
    const { bin, log } = fakeTools();
    const dir = project({ "build.gradle": "", "app/build.gradle.kts": "", "docs/readme.md": "x" });
    const result = await resolveJvmDependencies(dir, { env: { PATH: `${bin}:/usr/bin:/bin` } });
    expect(result.tools).toEqual(["gradle (.)", "gradle (app)"]);
    expect(readFileSync(log, "utf8").trim().split("\n")).toHaveLength(2);
    expect(readFileSync(log, "utf8")).toContain("dependencies --configuration runtimeClasspath");
    expect(result.components.filter(component => component.name === "org.slf4j/slf4j-api")).toHaveLength(1);
  });
  it("never runs a wrapper script from the project", async () => {
    const { bin } = fakeTools();
    const dir = project({ "pom.xml": "<project/>", "mvnw": "#!/bin/sh\ntouch pwned\n" });
    chmodSync(join(dir, "mvnw"), 0o755);
    await resolveJvmDependencies(dir, { env: { PATH: `${bin}:/usr/bin:/bin` } });
    expect(() => readFileSync(join(dir, "pwned"))).toThrow();
  });
  it("fails with the tool's error lines when the build fails", async () => {
    const { bin } = fakeTools({ mvn: "#!/bin/sh\necho '[ERROR] Could not resolve dependencies for project demo:app' >&2\nexit 1\n" });
    await expect(resolveJvmDependencies(project({ "pom.xml": "<project/>" }), { env: { PATH: `${bin}:/usr/bin:/bin` } })).rejects.toThrow(/mvn failed \(exit 1\):\n.*Could not resolve dependencies/);
  });
  it("says so when the tool is not installed", async () => {
    await expect(resolveJvmDependencies(project({ "pom.xml": "<project/>" }), { env: { PATH: "/nonexistent" } })).rejects.toThrow(/mvn is not installed/);
  });
  it("fails with gradle error lines when a single-project build fails", async () => {
    const { bin } = fakeTools({ gradle: "#!/bin/sh\necho '[ERROR] Could not resolve dependencies for project demo' >&2\nexit 1\n" });
    await expect(resolveJvmDependencies(project({ "build.gradle": "" }), { env: { PATH: `${bin}:/usr/bin:/bin` } })).rejects.toThrow(/gradle failed \(exit 1\):\n.*Could not resolve dependencies/);
  });
  it("preserves missing-tool diagnostic when gradle is not installed in a multi-project build", async () => {
    const dir = project({ "build.gradle": "", "app/build.gradle": "" });
    await expect(resolveJvmDependencies(dir, { env: { PATH: "/nonexistent" } })).rejects.toThrow(/gradle is not installed \(or not on PATH\)/);
  });
  it("preserves actual gradle error lines when all projects fail in a multi-project build", async () => {
    const { bin } = fakeTools({ gradle: "#!/bin/sh\necho '[ERROR] Could not resolve all dependencies' >&2\nexit 1\n" });
    const dir = project({ "build.gradle": "", "app/build.gradle": "" });
    await expect(resolveJvmDependencies(dir, { env: { PATH: `${bin}:/usr/bin:/bin` } })).rejects.toThrow(/gradle failed \(exit 1\):\n.*Could not resolve all dependencies/);
  });
  it("returns components and preserves failed project warning when one project fails and another succeeds", async () => {
    const { bin } = fakeTools({
      gradle: `#!/bin/sh
case "$*" in
  *app*) echo "+--- org.slf4j:slf4j-api:2.0.12";;
  *) echo "[ERROR] Configuration 'runtimeClasspath' not found in root project" >&2; exit 1;;
esac
`,
    });
    const dir = project({ "build.gradle": "", "app/build.gradle": "" });
    const result = await resolveJvmDependencies(dir, { env: { PATH: `${bin}:/usr/bin:/bin` } });
    expect(result.tools).toEqual(["gradle (app)"]);
    expect(result.components.map(c => c.name)).toContain("org.slf4j/slf4j-api");
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain("gradle (.): gradle failed (exit 1)");
    expect(result.warnings[0]).toContain("Configuration 'runtimeClasspath' not found");
  });
  it("stops a tool that runs too long", async () => {
    const { bin } = fakeTools({ mvn: "#!/bin/sh\nexec sleep 30\n" });
    await expect(resolveJvmDependencies(project({ "pom.xml": "<project/>" }), { env: { PATH: `${bin}:/usr/bin:/bin` }, timeoutMs: 300 })).rejects.toThrow(/did not finish within/);
  });
  it("refuses a folder with no build file", async () => {
    await expect(resolveJvmDependencies(project({ "readme.md": "x" }), { env: { PATH: "/usr/bin" } })).rejects.toBeInstanceOf(ResolveFailedError);
  });
  it("is refused under ZERO_ENTERPRISE before anything runs", async () => {
    const { bin, log } = fakeTools();
    await expect(resolveJvmDependencies(project({ "pom.xml": "<project/>" }), { env: { PATH: `${bin}:/usr/bin`, ZERO_ENTERPRISE: "1" } })).rejects.toThrow(/ZERO_ENTERPRISE/);
    expect(() => readFileSync(log)).toThrow();
  });
});

describe("buildToolEnv", () => {
  it("keeps what a JDK build needs and drops credentials", () => {
    const env = buildToolEnv({ PATH: "/bin", HOME: "/h", JAVA_HOME: "/j", MAVEN_OPTS: "-Xmx1g", GRADLE_USER_HOME: "/g", HTTPS_PROXY: "http://p", OPENAI_API_KEY: "x", GITHUB_TOKEN: "y", AWS_SECRET_ACCESS_KEY: "z" });
    expect(Object.keys(env).sort()).toEqual(["GRADLE_USER_HOME", "HOME", "HTTPS_PROXY", "JAVA_HOME", "MAVEN_OPTS", "PATH"]);
  });
});

describe("generateSbom with resolved components", () => {
  const fixture = join(import.meta.dirname, "fixtures", "jvm", "maven-multimodule");
  const resolved = parseMavenTree(MAVEN_TREE);
  it("lets the resolved set win, marks it, and keeps the transitive graph", () => {
    const declared = generateSbom(fixture, { toolVersion: "0", now: new Date(0) });
    const merged = generateSbom(fixture, { toolVersion: "0", now: new Date(0), resolved });
    expect(declared.bom.components.some(component => component.purl === "pkg:maven/com.google.guava/guava@32.1.3-jre")).toBe(true);
    const guava = merged.bom.components.find(component => component.purl === "pkg:maven/com.google.guava/guava@32.1.3-jre");
    expect(guava && "properties" in guava ? guava.properties : []).toContainEqual({ name: "0:resolved", value: "true" });
    // The declarations named slf4j-api 2.0.9 and 2.0.12; the build resolved one version.
    expect(merged.bom.components.filter(component => component.purl.startsWith("pkg:maven/org.slf4j/slf4j-api"))).toHaveLength(1);
    expect(merged.bom.dependencies?.find(entry => entry.ref === "pkg:maven/com.google.guava/guava@32.1.3-jre")?.dependsOn).toEqual(["pkg:maven/com.google.guava/failureaccess@1.0.1", "pkg:maven/org.checkerframework/checker-qual@3.37.0"]);
    // Declared components the build did not mention stay, without the resolved mark.
    const lang3 = merged.bom.components.find(component => component.purl === "pkg:maven/org.apache.commons/commons-lang3@3.14.0");
    expect(lang3 && "properties" in lang3 ? lang3.properties?.some(property => property.name === "0:resolved") : undefined).toBe(false);
  });
  it("points a resolved component at the file that declared it", () => {
    const merged = generateSbom(fixture, { toolVersion: "0", now: new Date(0), resolved });
    const guava = merged.bom.components.find(component => component.purl === "pkg:maven/com.google.guava/guava@32.1.3-jre");
    expect(guava && "properties" in guava ? guava.properties?.find(property => property.name === "0:source")?.value : "").toBe("modules/api/pom.xml");
  });
  it("attributes resolved dependency with mismatched version to the submodule that declared it (Test A)", () => {
    const dir = project({
      "pom.xml": [
        "<project>",
        "  <modelVersion>4.0.0</modelVersion>",
        "  <groupId>com.example</groupId>",
        "  <artifactId>root</artifactId>",
        "  <version>1.0.0</version>",
        "  <packaging>pom</packaging>",
        "  <modules><module>sub</module></modules>",
        "</project>",
      ].join("\n"),
      "sub/pom.xml": [
        "<project>",
        "  <modelVersion>4.0.0</modelVersion>",
        "  <parent><groupId>com.example</groupId><artifactId>root</artifactId><version>1.0.0</version></parent>",
        "  <artifactId>sub</artifactId>",
        "  <dependencies>",
        "    <dependency><groupId>foo</groupId><artifactId>bar</artifactId><version>1.0.0</version></dependency>",
        "  </dependencies>",
        "</project>",
      ].join("\n"),
    });
    const resolved = [{ ecosystem: "maven" as const, name: "foo/bar", version: "1.1.0" }];
    const result = generateSbom(dir, { toolVersion: "0", now: new Date(0), resolved });
    const bar = result.bom.components.find(c => c.name === "foo/bar");
    expect(bar).toBeDefined();
    expect(bar?.version).toBe("1.1.0");
    const source = bar && "properties" in bar ? bar.properties?.find(p => p.name === "0:source")?.value : undefined;
    expect(source).toBe("sub/pom.xml");
  });
  it("attributes resolved dependency with exact version match to declaring submodule (Test B)", () => {
    const dir = project({
      "pom.xml": [
        "<project>",
        "  <modelVersion>4.0.0</modelVersion>",
        "  <groupId>com.example</groupId>",
        "  <artifactId>root</artifactId>",
        "  <version>1.0.0</version>",
        "  <packaging>pom</packaging>",
        "  <modules><module>sub</module></modules>",
        "</project>",
      ].join("\n"),
      "sub/pom.xml": [
        "<project>",
        "  <modelVersion>4.0.0</modelVersion>",
        "  <parent><groupId>com.example</groupId><artifactId>root</artifactId><version>1.0.0</version></parent>",
        "  <artifactId>sub</artifactId>",
        "  <dependencies>",
        "    <dependency><groupId>foo</groupId><artifactId>bar</artifactId><version>1.0.0</version></dependency>",
        "  </dependencies>",
        "</project>",
      ].join("\n"),
    });
    const resolved = [{ ecosystem: "maven" as const, name: "foo/bar", version: "1.0.0" }];
    const result = generateSbom(dir, { toolVersion: "0", now: new Date(0), resolved });
    const bar = result.bom.components.find(c => c.name === "foo/bar");
    expect(bar).toBeDefined();
    expect(bar?.version).toBe("1.0.0");
    const source = bar && "properties" in bar ? bar.properties?.find(p => p.name === "0:source")?.value : undefined;
    expect(source).toBe("sub/pom.xml");
  });
  it("falls back to top-level build file when multiple modules declare the same artifact (Test C)", () => {
    const dir = project({
      "pom.xml": [
        "<project>",
        "  <modelVersion>4.0.0</modelVersion>",
        "  <groupId>com.example</groupId>",
        "  <artifactId>root</artifactId>",
        "  <version>1.0.0</version>",
        "  <packaging>pom</packaging>",
        "  <modules><module>mod-a</module><module>mod-b</module></modules>",
        "</project>",
      ].join("\n"),
      "mod-a/pom.xml": [
        "<project>",
        "  <modelVersion>4.0.0</modelVersion>",
        "  <parent><groupId>com.example</groupId><artifactId>root</artifactId><version>1.0.0</version></parent>",
        "  <artifactId>mod-a</artifactId>",
        "  <dependencies>",
        "    <dependency><groupId>foo</groupId><artifactId>bar</artifactId><version>1.0.0</version></dependency>",
        "  </dependencies>",
        "</project>",
      ].join("\n"),
      "mod-b/pom.xml": [
        "<project>",
        "  <modelVersion>4.0.0</modelVersion>",
        "  <parent><groupId>com.example</groupId><artifactId>root</artifactId><version>1.0.0</version></parent>",
        "  <artifactId>mod-b</artifactId>",
        "  <dependencies>",
        "    <dependency><groupId>foo</groupId><artifactId>bar</artifactId><version>2.0.0</version></dependency>",
        "  </dependencies>",
        "</project>",
      ].join("\n"),
    });
    const resolved = [{ ecosystem: "maven" as const, name: "foo/bar", version: "3.0.0" }];
    const result = generateSbom(dir, { toolVersion: "0", now: new Date(0), resolved });
    const bar = result.bom.components.find(c => c.name === "foo/bar");
    expect(bar).toBeDefined();
    const source = bar && "properties" in bar ? bar.properties?.find(p => p.name === "0:source")?.value : undefined;
    expect(source).toBe("pom.xml");
  });
  it("keeps the declared license but not the version-specific hash when the resolved version differs (Test D)", () => {
    const gradleLock = LOCKFILES.find(candidate => candidate.file === "gradle.lockfile");
    expect(gradleLock).toBeDefined();
    const originalParse = gradleLock!.parse;
    try {
      (gradleLock as any).parse = () => [{
        ecosystem: "maven" as const,
        name: "org.example/lib",
        version: "1.0.0",
        licenses: ["Apache-2.0"],
        hashes: [{ alg: "SHA-256" as const, content: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }],
      }];
      const dir = project({
        "gradle.lockfile": "org.example:lib:1.0.0=runtimeClasspath\n",
        "build.gradle": "// root",
      });
      const resolved = [{ ecosystem: "maven" as const, name: "org.example/lib", version: "2.0.0" }];
      const result = generateSbom(dir, { toolVersion: "0", now: new Date(0), resolved });
      const lib = result.bom.components.find(c => c.name === "org.example/lib");
      expect(lib).toBeDefined();
      expect(lib?.version).toBe("2.0.0");
      const source = lib && "properties" in lib ? lib.properties?.find(p => p.name === "0:source")?.value : undefined;
      expect(source).toBe("gradle.lockfile");
      expect(lib?.licenses).toEqual([{ license: { id: "Apache-2.0" } }]);
      // A hash belongs to 1.0.0 only, so it must not be attached to the resolved 2.0.0.
      expect(lib?.hashes).toBeUndefined();
    } finally {
      (gradleLock as any).parse = originalParse;
    }
  });
  it("attributes transitive dependency not in any build file to top-level build file (Test E)", () => {
    const dir = project({
      "pom.xml": [
        "<project>",
        "  <modelVersion>4.0.0</modelVersion>",
        "  <groupId>com.example</groupId>",
        "  <artifactId>root</artifactId>",
        "  <version>1.0.0</version>",
        "  <packaging>pom</packaging>",
        "  <modules><module>sub</module></modules>",
        "</project>",
      ].join("\n"),
      "sub/pom.xml": [
        "<project>",
        "  <modelVersion>4.0.0</modelVersion>",
        "  <parent><groupId>com.example</groupId><artifactId>root</artifactId><version>1.0.0</version></parent>",
        "  <artifactId>sub</artifactId>",
        "  <dependencies>",
        "    <dependency><groupId>foo</groupId><artifactId>bar</artifactId><version>1.0.0</version></dependency>",
        "  </dependencies>",
        "</project>",
      ].join("\n"),
    });
    const resolved = [
      { ecosystem: "maven" as const, name: "foo/bar", version: "1.0.0" },
      { ecosystem: "maven" as const, name: "transitive/dep", version: "9.9.9" },
    ];
    const result = generateSbom(dir, { toolVersion: "0", now: new Date(0), resolved });
    const trans = result.bom.components.find(c => c.name === "transitive/dep");
    expect(trans).toBeDefined();
    const source = trans && "properties" in trans ? trans.properties?.find(p => p.name === "0:source")?.value : undefined;
    expect(source).toBe("pom.xml");
  });
});
