import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { applySandboxProfile, makeSandboxCache, NETWORK_CANARY, dockerRunArgs, JAVA_VERIFIER_IMAGE, runInSandbox, validateMavenSettingsFile } from "../fix-sandbox.js";
import { sandboxSpec } from "../fix.js";

describe("Java verification profile", () => {
  it("opts in to a pinned image, online setup and offline verify; preserves explicit tests", () => {
    expect(applySandboxProfile({})).toEqual({});
    expect(applySandboxProfile({ sandboxProfile: "java" })).toMatchObject({ sandbox: "docker", sandboxImage: JAVA_VERIFIER_IMAGE, sandboxSetup: [expect.stringContaining("dependency:go-offline")], test: [expect.stringContaining("mvn -o")] });
    expect(JAVA_VERIFIER_IMAGE).toMatch(/^docker.io\/library\/maven@sha256:[a-f0-9]{64}$/);
    expect(applySandboxProfile({ sandboxProfile: "java", test: ["mvn -o -pl api verify"] }).test).toEqual(["mvn -o -pl api verify"]);
    expect(() => sandboxSpec({ budget: "1", timeout: "60", pr: true, sandboxProfile: "java" }, { ZERO_ENTERPRISE: "1" })).toThrow(/Blocked/);
    for (const extra of [{ sandboxImage: "untrusted:latest" }, { sandboxNetwork: true }, { sandboxProfile: "other" }]) expect(() => applySandboxProfile({ sandboxProfile: "java", ...extra })).toThrow();
  });

  it("mounts explicit credentials for setup only, withholding output and removing the temporary copy", async () => {
    const root = mkdtempSync(join(tmpdir(), "0-java-secret-"));
    try {
      const repo = join(root, "repo"); mkdirSync(repo);
      const settings = join(root, "settings.xml");
      const secret = "short-lived-read-only-secret";
      writeFileSync(settings, `<settings><servers><server><password>${secret}</password></server></servers></settings>`, { mode: 0o600 });
      expect(validateMavenSettingsFile(settings, repo)).toBe(settings);
      const options = applySandboxProfile({ sandboxProfile: "java", sandboxMavenSettings: settings });
      expect(options.sandboxSetup![0]).toContain("-s /run/secrets/maven-settings.xml");
      const bin = join(root, "bin"); mkdirSync(bin);
      const log = join(root, "mount.txt");
      writeFileSync(join(bin, "docker"), `#!/bin/sh\nfor a in "$@"; do case "$a" in *:/run/secrets/maven-settings.xml:ro) f="\${a%:/run/secrets/maven-settings.xml:ro}"; printf '%s' "$f" > '${log}'; cat "$f";; esac; done\nexit 0\n`, { mode: 0o700 });
      const result = await runInSandbox(repo, options.sandboxSetup![0]!, { image: JAVA_VERIFIER_IMAGE, network: true, mavenSettingsFile: settings }, { env: { PATH: `${bin}:/usr/bin:/bin` } });
      expect(result.code).toBe(0);
      expect(JSON.stringify(result)).not.toContain(secret);
      expect(JSON.stringify(result)).not.toContain(settings);
      expect(result.output).toContain("withheld");
      expect(existsSync(readFileSync(log, "utf8"))).toBe(false);
      const offline = await runInSandbox(repo, "true", { image: JAVA_VERIFIER_IMAGE, network: false, mavenSettingsFile: settings }, { env: { PATH: `${bin}:/usr/bin:/bin` } });
      expect(offline.code).not.toBe(0);
      expect(dockerRunArgs({ image: JAVA_VERIFIER_IMAGE, network: false }, "t", repo, "mvn -o verify").join(" ")).not.toContain("/run/secrets");
      const inRepo = join(repo, "settings.xml"); writeFileSync(inRepo, "secret", { mode: 0o600 });
      expect(() => validateMavenSettingsFile(inRepo, repo)).toThrow(/outside/);
      chmodSync(settings, 0o644); expect(() => validateMavenSettingsFile(settings)).toThrow(/owner-only/);
      chmodSync(settings, 0o600); const link = join(root, "link"); symlinkSync(settings, link);
      expect(() => validateMavenSettingsFile(link)).toThrow(/symlink/);
    } finally { rmSync(root, { force: true, recursive: true }); }
  });
});


describe.skipIf(process.env["ZERO_TEST_JAVA_DOCKER"] !== "1")("real pinned Maven container", () => {
  it("mounts a dummy private artifact credential for setup and never for offline checks", async () => {
    const root = mkdtempSync(join(tmpdir(), "0-java-live-secret-"));
    const fixture = join(root, "project"); mkdirSync(fixture);
    const settings = join(root, "private-settings.xml");
    writeFileSync(settings, "<settings><!-- dummy-expiring-read-token --></settings>", { mode: 0o600 });
    try {
      const mounted = await runInSandbox(fixture, "grep -q dummy-expiring-read-token /run/secrets/maven-settings.xml", { image: JAVA_VERIFIER_IMAGE, network: true, mavenSettingsFile: settings });
      expect(mounted.code, mounted.output).toBe(0);
      expect(mounted.output).not.toContain("dummy-expiring-read-token");
      expect((await runInSandbox(fixture, "test ! -e /run/secrets/maven-settings.xml", { image: JAVA_VERIFIER_IMAGE, network: false })).code).toBe(0);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }, 60_000);

  it("prepares dependencies, proves offline checks, and rejects the vulnerable negative control", async () => {
    const root = mkdtempSync(join(tmpdir(), "0-java-docker-"));
    const cache = makeSandboxCache();
    const fixture = join(root, "project");
    cpSync(new URL("../__fixtures__/java-verifier", import.meta.url), fixture, { recursive: true, filter: path => !path.includes("/target") });
    const profile = applySandboxProfile({ sandboxProfile: "java" });
    const online = { image: JAVA_VERIFIER_IMAGE, network: true, cache };
    const offline = { ...online, network: false };
    try {
      const setup = await runInSandbox(fixture, profile.sandboxSetup![0]!, online);
      expect(setup.output, "online dependency setup").not.toContain("BUILD FAILURE");
      expect(setup.code, setup.output).toBe(0);
      expect((await runInSandbox(fixture, NETWORK_CANARY, offline)).code).toBe(0);
      expect((await runInSandbox(fixture, NETWORK_CANARY, online)).code).not.toBe(0);
      const checked = await runInSandbox(fixture, profile.test![0]!, offline);
      expect(checked.code, checked.output).toBe(0);
      expect(checked.output).toContain("Tests run: 3, Failures: 0");
      const source = join(fixture, "src/main/java/example/DownloadPath.java");
      writeFileSync(source, readFileSync(source, "utf8").split("\n").filter(line => !line.includes("if (!result.startsWith(base))")).join("\n"));
      const rejected = await runInSandbox(fixture, profile.test![0]!, offline);
      expect(rejected.code, rejected.output).not.toBe(0);
      expect(rejected.output).toContain("Failures: 2");
    } finally { rmSync(cache, { recursive: true, force: true }); rmSync(root, { recursive: true, force: true }); }
  }, 600_000);
});
