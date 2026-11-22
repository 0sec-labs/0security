import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
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

  const testPollutionKeys = [
    "testPollutedVersions",
    "testPollutedLibraries",
    "testPollutedInlineQ",
    "testPollutedInlineB",
    "testPollutedKey",
    "testPollutedBareDotted",
    "testPollutedQuotedDotted",
    "testPollutedSubtableKey",
  ];
  afterEach(() => {
    for (const key of testPollutionKeys) {
      delete (Object.prototype as any)[key];
    }
  });

  it("safely handles special property keys (__proto__) without mutating Object.prototype", () => {
    for (const key of testPollutionKeys) {
      expect((Object.prototype as any)[key]).toBeUndefined();
    }

    const maliciousCatalog = `
[versions.__proto__]
testPollutedVersions = "evil_subtable"

[libraries.__proto__]
testPollutedLibraries = "evil_lib_subtable"

[versions]
__proto__ = "evil_version"
__proto__.testPollutedBareDotted = "evil_bare_dotted"
"__proto__".testPollutedQuotedDotted = "evil_quoted_dotted"
safe_ver = "1.2.3"
inline_evil = { "__proto__.testPollutedInline" = "safe_inline_prop", "__proto__".testPollutedInlineQ = "evil_inline_q", __proto__.testPollutedInlineB = "evil_inline_b", normal_field = "valid" }
"__proto__.testPollutedKey" = "safe_dotted_key"

[libraries.evil_lib]
module = "com.example:evil"
"__proto__".testPollutedSubtableKey = "evil_subtable_key"
version.ref = "safe_ver"
`;

    const catalog = parseCatalog(maliciousCatalog);

    for (const key of testPollutionKeys) {
      expect((Object.prototype as any)[key]).toBeUndefined();
      expect(({} as any)[key]).toBeUndefined();
    }

    expect(catalog.versions.safe_ver).toBe("1.2.3");
    expect(catalog.versions["__proto__.testPollutedKey"]).toBe("safe_dotted_key");
    expect((catalog.versions.inline_evil as any)["__proto__.testPollutedInline"]).toBe("safe_inline_prop");
    expect((catalog.versions.inline_evil as any).normal_field).toBe("valid");
    expect((catalog.versions.inline_evil as any).testPollutedInlineQ).toBeUndefined();
    expect((catalog.versions.inline_evil as any).testPollutedInlineB).toBeUndefined();
    expect((catalog.libraries.evil_lib as any).testPollutedSubtableKey).toBeUndefined();
    expect(catalog.libraries.evil_lib).toEqual({ module: "com.example:evil", version: { ref: "safe_ver" } });
  });

  it("correctly parses quoted keys with dots, escaped characters, and genuinely dotted paths", () => {
    const catalogSource = `
[versions."my.version"]
require = "1.2.3"
prefer = "1.2.4"

[versions]
inline_ver = { "my.version" = "2.3.4", normal = "ok" }
"__proto__.polluted" = "safe_value"
"escaped \\" quote" = "val_with_escaped_quote"
"escaped \\\\ backslash" = "val_with_escaped_backslash"
'literal.version' = "3.4.5"
version.ref = "v1"

[libraries]
"my.library" = "com.example:my-library:1.0.0"

[libraries.my_lib]
module = "com.example:my-lib"
version.ref = "my.version"
`;

    const catalog = parseCatalog(catalogSource);

    // "my.version" in a sub-table
    expect(catalog.versions["my.version"]).toEqual({ require: "1.2.3", prefer: "1.2.4" });

    // "my.version" in an inline table
    expect((catalog.versions.inline_ver as any)["my.version"]).toBe("2.3.4");
    expect((catalog.versions.inline_ver as any).normal).toBe("ok");

    // "my.library" as a top-level key
    expect(catalog.libraries["my.library"]).toBe("com.example:my-library:1.0.0");

    // version.ref as a genuinely dotted key
    expect(catalog.versions.version).toEqual({ ref: "v1" });
    expect(catalog.libraries.my_lib).toEqual({
      module: "com.example:my-lib",
      version: { ref: "my.version" },
    });

    // Quoted literal keys containing dots and escaped characters
    expect(catalog.versions["__proto__.polluted"]).toBe("safe_value");
    expect(catalog.versions['escaped " quote']).toBe("val_with_escaped_quote");
    expect(catalog.versions["escaped \\ backslash"]).toBe("val_with_escaped_backslash");
    expect(catalog.versions["literal.version"]).toBe("3.4.5");
  });

  it("preserves ordinary Object.prototype inheritance and standard object methods on returned tables", () => {
    const catalog = parseCatalog(`
[versions]
safe_ver = "1.0.0"
v = { require = "1.0", prefer = "1.1" }

[libraries.lib]
module = "g:a"
version.ref = "v"
`);

    // Returned versions and libraries have Object.prototype as their prototype
    expect(Object.getPrototypeOf(catalog.versions)).toBe(Object.prototype);
    expect(Object.getPrototypeOf(catalog.libraries)).toBe(Object.prototype);
    expect(Object.getPrototypeOf(catalog.versions.v)).toBe(Object.prototype);
    expect(Object.getPrototypeOf(catalog.libraries.lib)).toBe(Object.prototype);

    // .hasOwnProperty() works
    expect(catalog.versions.hasOwnProperty("safe_ver")).toBe(true);
    expect(catalog.versions.hasOwnProperty("v")).toBe(true);
    expect(catalog.libraries.hasOwnProperty("lib")).toBe(true);
    expect((catalog.versions.v as any).hasOwnProperty("require")).toBe(true);
    expect((catalog.libraries.lib as any).hasOwnProperty("module")).toBe(true);

    // toString() and valueOf() remain available
    expect(catalog.versions.toString()).toBe("[object Object]");
    expect(catalog.libraries.toString()).toBe("[object Object]");
    expect(typeof catalog.versions.valueOf()).toBe("object");
    expect(typeof catalog.libraries.valueOf()).toBe("object");

    // Existing deep and strict equality expectations remain valid
    expect(catalog.versions.v).toEqual({ require: "1.0", prefer: "1.1" });
    expect(catalog.libraries.lib).toEqual({ module: "g:a", version: { ref: "v" } });

    // Safe own properties are preserved and enumerable
    expect(Object.keys(catalog.versions)).toEqual(["safe_ver", "v"]);
    expect(Object.keys(catalog.libraries)).toEqual(["lib"]);
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
