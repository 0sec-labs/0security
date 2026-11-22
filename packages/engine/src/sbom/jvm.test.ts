import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeMaven, checkBomAgainstOsv, generateSbom, parseCatalog, parseGradleBuild, parseXml } from "./index.js";

const fixtures = join(import.meta.dirname, "fixtures", "jvm");
const sbom = (name: string) => generateSbom(join(fixtures, name), { toolVersion: "0", now: new Date(0) });
const purls = (name: string) => sbom(name).bom.components.map(component => component.purl);
const unresolved = (name: string) => sbom(name).unresolved.map(item => `${item.source}: ${item.name}`);

describe("Maven pom.xml", () => {
  it("resolves properties, dependencyManagement, an in-repo parent and an imported in-repo BOM across modules", () => {
    expect(purls("maven-multimodule")).toEqual([
      "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.2",
      "pkg:maven/com.google.guava/guava@32.1.3-jre",
      "pkg:maven/junit/junit@4.13.2",
      "pkg:maven/org.apache.commons/commons-lang3@3.14.0",
      // the worker module overrides the parent's property, so each module gets its own version
      "pkg:maven/org.slf4j/slf4j-api@2.0.12",
      "pkg:maven/org.slf4j/slf4j-api@2.0.9",
    ]);
    const junit = sbom("maven-multimodule").bom.components.find(component => component.name === "junit/junit");
    expect(junit?.scope).toBe("excluded"); // test scope
  });
  it("does not list a module of the repository as a third-party component", () => {
    expect(purls("maven-multimodule").some(purl => purl.includes("com.example"))).toBe(false);
  });
  it("lists profiles, missing modules, missing parents and BOMs, ranges and undefined properties as unresolved", () => {
    expect(unresolved("maven-multimodule")).toEqual([
      "pom.xml: commons-collections:commons-collections",
      "pom.xml: module:modules/missing",
    ]);
    expect(purls("maven-unresolved")).toEqual(["pkg:maven/org.apache.commons/commons-text@1.11.0"]);
    expect(unresolved("maven-unresolved")).toEqual([
      "pom.xml: org.example.external:external-bom",
      "pom.xml: org.example:ci-only",
      "pom.xml: org.example:from-env",
      "pom.xml: org.example:profile-only-version",
      "pom.xml: org.example:ranged",
      "pom.xml: org.springframework.boot:spring-boot-starter-web",
      "pom.xml: parent:org.springframework.boot:spring-boot-starter-parent:3.2.0",
    ]);
  });
  it("does not use a BOM whose version differs from the one requested", () => {
    const pom = (body: string) => `<project><modelVersion>4.0.0</modelVersion>${body}</project>`;
    const result = analyzeMaven([
      { path: "/r/bom/pom.xml", rel: "bom/pom.xml", source: pom("<groupId>g</groupId><artifactId>bom</artifactId><version>2.0</version><dependencyManagement><dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId><version>1</version></dependency></dependencies></dependencyManagement>") },
      { path: "/r/pom.xml", rel: "pom.xml", source: pom("<groupId>g</groupId><artifactId>app</artifactId><version>1</version><dependencyManagement><dependencies><dependency><groupId>g</groupId><artifactId>bom</artifactId><version>1.0</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement><dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId></dependency></dependencies>") },
    ]);
    expect(result.files.flatMap(file => file.components)).toEqual([]);
    expect(result.unresolved.map(item => item.reason).join("\n")).toContain("is not the version in the repository (2.0)");
  });
  it("reads text only: a DOCTYPE entity is not expanded and malformed XML gives nothing", () => {
    const node = parseXml('<?xml version="1.0"?><!DOCTYPE project [<!ENTITY x SYSTEM "file:///etc/passwd">]><project><a>&x;</a><!-- c --><b><![CDATA[<v>]]></b></project>');
    expect(node?.children.map(item => item.text)).toEqual(["&x;", "<v>"]);
    expect(analyzeMaven([{ path: "/r/pom.xml", rel: "pom.xml", source: "<<<not xml" }])).toEqual({ files: [], unresolved: [] });
  });
});

describe("Gradle", () => {
  it("reads the lockfile, the version catalog and literal build-script versions; the lockfile wins over a declared version", () => {
    expect(purls("gradle-project")).toEqual([
      "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.2",
      "pkg:maven/com.google.guava/guava@32.1.3-jre",
      "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0",
      "pkg:maven/org.apache.commons/commons-lang3@3.14.0",
      "pkg:maven/org.junit.jupiter/junit-jupiter@5.10.1",
      "pkg:maven/org.mockito/mockito-core@5.8.0",
      "pkg:maven/org.slf4j/slf4j-api@2.0.9",
    ]);
    expect(sbom("gradle-project").bom.components.find(component => component.name === "org.mockito/mockito-core")?.scope).toBe("excluded");
    expect(unresolved("gradle-project")).toEqual([
      "gradle/libs.versions.toml: org.example:dyn",
      "gradle/libs.versions.toml: org.example:managed",
      "gradle/libs.versions.toml: org.example:missing-ref",
    ]);
  });
  it("reports variables, dynamic versions, missing versions and platforms as unresolved, and skips comments and project dependencies", () => {
    expect(purls("gradle-unresolved")).toEqual(["pkg:maven/org.apache.commons/commons-lang3@3.14.0", "pkg:maven/org.postgresql/postgresql@42.7.1", "pkg:maven/org.yaml/snakeyaml@2.2"]);
    expect(unresolved("gradle-unresolved")).toEqual([
      "build.gradle: com.fasterxml.jackson.core:jackson-core",
      "build.gradle: junit:junit",
      "build.gradle: org.example:dynamic",
      "build.gradle: org.example:latest",
      "build.gradle: org.example:unversioned",
      "build.gradle: org.springframework.boot:spring-boot-dependencies",
    ]);
    expect(parseGradleBuild("// implementation 'a:b:1'\n/* api 'c:d:2' */\nimplementation 'e:f:3'", "b.gradle").components.map(component => component.name)).toEqual(["e/f"]);
  });
  it("parses catalog tables in table form and with rich versions", () => {
    const catalog = parseCatalog('[versions]\nv = { require = "1.0", prefer = "1.1" }\n[libraries.lib]\nmodule = "g:a"\nversion.ref = "v"\n');
    expect(catalog.versions.v).toEqual({ require: "1.0", prefer: "1.1" });
    expect(catalog.libraries.lib).toEqual({ module: "g:a", version: { ref: "v" } });
  });
});

describe("output", () => {
  it("is deterministic, records unresolved items as sorted metadata properties, and counts them", () => {
    const one = sbom("maven-unresolved"); const two = sbom("maven-unresolved");
    expect(JSON.stringify(one.bom)).toBe(JSON.stringify(two.bom));
    const props = one.bom.metadata.properties ?? [];
    expect(props).toHaveLength(7);
    expect(props.every(property => property.name === "0:unresolved")).toBe(true);
    expect(props.map(property => property.value)).toContain("org.example:ranged (version '[1.0,2.0)' is a range or a moving version, not one release) in pom.xml");
  });
  it("sbom check hands the unresolved items back, with OSV mocked and asked for Maven package URLs", async () => {
    const bodies: string[] = [];
    const mock = (async (url: string | URL | Request, init?: RequestInit) => {
      if (String(url).endsWith("/v1/querybatch")) { bodies.push(String(init?.body)); return new Response(JSON.stringify({ results: [{}] })); }
      return new Response("no", { status: 500 });
    }) as typeof fetch;
    const result = await checkBomAgainstOsv(sbom("maven-unresolved").bom, { fetch: mock, baseUrl: "https://osv.test" });
    expect(bodies[0]).toContain("pkg:maven/org.apache.commons/commons-text@1.11.0");
    expect(result.checked).toBe(1);
    expect(result.unresolved).toHaveLength(7);
  });
});
