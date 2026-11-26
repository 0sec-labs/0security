/**
 * Real Maven run of the verifier lane, with a setup step. Skipped unless a container runtime answers and
 * ZERO_MAVEN_IMAGE names a digest-pinned Maven and JDK image (about 800 MB, so it is never pulled for you):
 *
 *   ZERO_MAVEN_IMAGE=maven@sha256:<digest> npx vitest run src/verifier/docker-runner.maven.integration.test.ts
 *
 * The setup step runs with the network on and fills the Maven cache. The checks then run in the same container with
 * the network cut. The canary is a planted failing test that the offline build must report.
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { OciRunner } from "./docker-runner.js";
import { runVerifier } from "./runner.js";
import { parseVerifySpec } from "./spec.js";

const IMAGE = process.env["ZERO_MAVEN_IMAGE"] ?? "";
const hasDocker = ["docker", "podman"].some((bin) => spawnSync(bin, ["info"], { stdio: "ignore", timeout: 10_000 }).status === 0);
const dirs: string[] = [];
afterAll(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

const pom = (version: string) => `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>demo</groupId><artifactId>tiny</artifactId><version>1.0.0</version>
  <properties><maven.compiler.release>21</maven.compiler.release><project.build.sourceEncoding>UTF-8</project.build.sourceEncoding></properties>
  <dependencies>
    <dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>${version}</version></dependency>
    <dependency><groupId>org.junit.jupiter</groupId><artifactId>junit-jupiter</artifactId><version>5.10.2</version><scope>test</scope></dependency>
  </dependencies>
  <build><plugins><plugin><artifactId>maven-surefire-plugin</artifactId><version>3.2.5</version></plugin></plugins></build>
</project>
`;
const project = (version: string): string => {
  const dir = mkdtempSync(join(tmpdir(), "maven-it-"));
  dirs.push(dir);
  const put = (file: string, text: string) => { mkdirSync(dirname(join(dir, file)), { recursive: true }); writeFileSync(join(dir, file), text); };
  put("pom.xml", pom(version));
  put("src/main/java/demo/Greeter.java", 'package demo;\nimport java.util.Map;\nimport org.apache.commons.text.StringSubstitutor;\npublic class Greeter { public static String greet(String n) { return new StringSubstitutor(Map.of("name", n)).replace("Hello, ${name}!"); } }\n');
  put("src/test/java/demo/GreeterTest.java", 'package demo;\nimport static org.junit.jupiter.api.Assertions.assertEquals;\nimport org.junit.jupiter.api.Test;\nclass GreeterTest { @Test void greets() { assertEquals("Hello, Ada!", Greeter.greet("Ada")); } }\n');
  return dir;
};
const CANARY = 'package demo;\nimport static org.junit.jupiter.api.Assertions.fail;\nimport org.junit.jupiter.api.Test;\nclass CanaryTest { @Test void planted() { fail("planted canary"); } }\n';

describe.skipIf(!hasDocker || !IMAGE)("OciRunner with a real Maven image", () => {
  const runner = new OciRunner();
  const spec = (run: string, extra: Record<string, unknown> = {}) => {
    const parsed = parseVerifySpec({ steps: [{ name: "test", run }], image: IMAGE, setup: "mvn -q test -Dtest=GreeterTest", timeout: 600, ...extra });
    if (!parsed.ok) throw new Error(parsed.error);
    return parsed.spec;
  };

  it("passes the bumped dependency offline, and proves the check ran with a planted failing test", async () => {
    const dir = project("1.10.0");
    const result = await runVerifier({ spec: spec("mvn -o test", { canary: { step: "test", file: "src/test/java/demo/CanaryTest.java", content: CANARY, expect: "planted canary" } }), afterDir: dir, runner });
    expect(result).toMatchObject({ status: "pass", reason: expect.any(String), canary: "ok", isolation: "container" });
    expect(result.logTail).toContain("Tests run:");
    expect(spawnSync("docker", ["ps", "-aq", "--filter", "label=0.verify=1"], { encoding: "utf8" }).stdout.trim()).toBe("");
  }, 900_000);

  it("fails a real test failure, and cannot download once the network is cut", async () => {
    const failing = await runVerifier({ spec: spec("mvn -o test -Dtest=NoSuchTest"), afterDir: project("1.10.0"), runner });
    expect(failing.status).toBe("fail");
    const online = await runVerifier({ spec: spec("! curl -sS -m 5 -o /dev/null https://repo.maven.apache.org/maven2/"), afterDir: project("1.10.0"), runner });
    expect(online.status).toBe("pass");
  }, 900_000);
});
