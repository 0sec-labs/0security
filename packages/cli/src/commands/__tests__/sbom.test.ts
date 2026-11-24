import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { UsageError } from "../output.js";
import { runAgentConfig, runCheck, runGenerate, runGenerateWith, runJavaUsage, runScanModels, type SbomDeps } from "../sbom.js";

const dirs: string[] = [];
afterEach(() => dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true })));
const project = (files: Record<string, string>) => { const dir = mkdtempSync(join(tmpdir(), "0-sbomcli-")); dirs.push(dir); for (const [path, content] of Object.entries(files)) { mkdirSync(join(dir, path, ".."), { recursive: true }); writeFileSync(join(dir, path), content); } return dir; };
const deps = (extra: Partial<SbomDeps> = {}) => { const out: string[] = []; const err: string[] = []; const written: Record<string, string> = {}; return { out, err, written, deps: { out: (t: string) => out.push(t), err: (t: string) => err.push(t), write: (p: string, t: string) => { written[p] = t; }, read: (p: string) => written[p] ?? "", ...extra } as SbomDeps }; };

describe("0 sbom generate", () => {
  it("writes the SBOM and says which lockfiles it read", () => {
    const dir = project({ "package-lock.json": JSON.stringify({ packages: { "node_modules/lodash": { version: "4.17.20" } } }) });
    const io = deps();
    runGenerate(dir, {}, io.deps);
    expect(JSON.parse(io.out.join("")).components[0].purl).toBe("pkg:npm/lodash@4.17.20");
    expect(io.err.join("\n")).toContain("1 components from 1 lockfile: package-lock.json (npm, 1)");
  });
  it("is a usage error, with the supported lockfiles and the fallback, when there is nothing to read", () => {
    const io = deps();
    expect(() => runGenerate(project({ "readme.md": "x" }), {}, io.deps)).toThrow(/package-lock\.json.*--generator syft, cdxgen or trivy/);
    expect(() => runGenerate("/no/such/folder", {}, io.deps)).toThrow("is not a folder");
  });
});

describe("0 sbom resolved and unresolved summary", () => {
  const pom = "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>app</artifactId><version>1</version><dependencies>"
    + "<dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>1.11.0</version></dependency>"
    + "<dependency><groupId>org.example</groupId><artifactId>unmanaged</artifactId></dependency></dependencies></project>";
  it("generate prints 'resolved N, unresolved M' and what was not analysed, and the SBOM carries it to check", async () => {
    const io = deps();
    runGenerate(project({ "pom.xml": pom }), {}, io.deps);
    const err = io.err.join("\n");
    expect(err).toContain("resolved 1, unresolved 1");
    expect(err).toContain("not analysed: org.example:unmanaged (no version");
    const bom = io.out.join("");
    const calls: string[] = [];
    const fetcher = (async (url: string | URL | Request) => { calls.push(String(url)); return new Response(JSON.stringify({ results: [{}] })); }) as typeof fetch;
    const check = deps({ read: () => bom, fetch: fetcher });
    expect(await runCheck("sbom.json", {}, check.deps)).toBe(0);
    expect(check.out.join("")).toContain("resolved 1, unresolved 1");
    expect(check.out.join("")).toContain("org.example:unmanaged");
    expect(calls).toHaveLength(1);
  });
  it("a folder whose only content is unresolved still produces an SBOM instead of an error", () => {
    const io = deps();
    runGenerate(project({ "build.gradle": "dependencies { implementation 'a:b' }" }), {}, io.deps);
    expect(io.err.join("\n")).toContain("resolved 0, unresolved 1");
  });
});

describe("0 sbom generate --resolve", () => {
  const pom = "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>app</artifactId><version>1</version><dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>1.9</version></dependency></dependencies></project>";
  /** A fake mvn that writes a tree to the requested file. Nothing real runs. */
  const fakeBin = () => {
    const bin = mkdtempSync(join(tmpdir(), "0-fakemvn-")); dirs.push(bin);
    writeFileSync(join(bin, "mvn"), "#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in -DoutputFile=*) printf 'g:app:jar:1\\n+- org.apache.commons:commons-text:jar:1.9:compile\\n\\\\- org.example:extra:jar:2.0:compile\\n' > \"${a#-DoutputFile=}\";; esac; done\n", { mode: 0o755 });
    return bin;
  };
  const env = (bin: string) => ({ PATH: `${bin}:/usr/bin:/bin` });
  it("warns, runs the build tool with --allow-build-tools, and marks resolved components", async () => {
    const io = deps({ env: env(fakeBin()) });
    await runGenerateWith(project({ "pom.xml": pom }), { resolve: true, allowBuildTools: true }, io.deps);
    expect(io.err.join("\n")).toContain("warning: --resolve runs the project's own build tool");
    const bom = JSON.parse(io.out.join(""));
    expect(bom.components.map((c: { purl: string }) => c.purl)).toContain("pkg:maven/org.example/extra@2.0");
    expect(bom.components.find((c: { name: string }) => c.name === "org.example/extra").properties).toContainEqual({ name: "0:resolved", value: "true" });
  });
  it("refuses without --allow-build-tools when nobody can be asked, and does not run anything", async () => {
    const io = deps({ env: env(fakeBin()) });
    await expect(runGenerateWith(project({ "pom.xml": pom }), { resolve: true }, io.deps)).rejects.toThrow(/--allow-build-tools/);
    expect(io.out).toEqual([]);
  });
  it("runs after a yes at the prompt and not after a no", async () => {
    const yes = deps({ env: env(fakeBin()), confirm: async () => true });
    await runGenerateWith(project({ "pom.xml": pom }), { resolve: true }, yes.deps);
    expect(yes.out.join("")).toContain("org.example/extra");
    const no = deps({ env: env(fakeBin()), confirm: async () => false });
    await expect(runGenerateWith(project({ "pom.xml": pom }), { resolve: true }, no.deps)).rejects.toBeInstanceOf(UsageError);
  });
  it("is refused under ZERO_ENTERPRISE, even with the consent flag", async () => {
    const io = deps({ env: { ...env(fakeBin()), ZERO_ENTERPRISE: "1" } });
    await expect(runGenerateWith(project({ "pom.xml": pom }), { resolve: true, allowBuildTools: true }, io.deps)).rejects.toThrow(/ZERO_ENTERPRISE/);
  });
  it("rejects flags that do not fit", async () => {
    const io = deps();
    await expect(runGenerateWith(project({ "pom.xml": pom }), { allowBuildTools: true }, io.deps)).rejects.toThrow(/only apply with --resolve/);
    await expect(runGenerateWith(project({ "pom.xml": pom }), { resolve: true, generator: "syft" }, io.deps)).rejects.toThrow(/builtin generator only/);
  });
  it("turns a failing build tool into a usage error with the tool's message", async () => {
    const bin = mkdtempSync(join(tmpdir(), "0-fakemvn-")); dirs.push(bin);
    writeFileSync(join(bin, "mvn"), "#!/bin/sh\necho '[ERROR] Could not resolve' >&2\nexit 1\n", { mode: 0o755 });
    await expect(runGenerateWith(project({ "pom.xml": pom }), { resolve: true, allowBuildTools: true }, deps({ env: env(bin) }).deps)).rejects.toThrow(/mvn failed.*Could not resolve/s);
  });
});

describe("0 sbom generate --ai", () => {
  it("adds the AI in the folder, and is not an error when there is no lockfile but there is AI", () => {
    const dir = project({ "app.py": 'm = AutoModel.from_pretrained("org/model")\n', ".mcp.json": JSON.stringify({ mcpServers: { files: { command: "npx", args: ["-y", "srv"] } } }) });
    const io = deps();
    runGenerate(dir, { ai: true }, io.deps);
    const bom = JSON.parse(io.out.join(""));
    expect(bom.components.map((component: { type: string }) => component.type)).toEqual(["machine-learning-model"]);
    expect(bom.services.map((service: { name: string }) => service.name)).toEqual(["mcp:files"]);
    expect(io.err.join("\n")).toContain("2 AI components");
    expect(() => runGenerate(dir, {}, deps().deps)).toThrow("No supported lockfile");
  });
});

describe("0 sbom check", () => {
  const bom = JSON.stringify({ components: [{ purl: "pkg:npm/lodash@4.17.20" }] });
  const osv = (vulns: unknown[]) => (async (url: string | URL | Request) => String(url).endsWith("querybatch") ? new Response(JSON.stringify({ results: [{ vulns }] })) : new Response(JSON.stringify({ id: "GHSA-1", aliases: ["CVE-1"], summary: "Bad", database_specific: { severity: "HIGH" }, affected: [{ ranges: [{ type: "SEMVER", events: [{ fixed: "4.17.21" }] }] }] }))) as typeof fetch;
  it("lists advisories per component and returns 1", async () => {
    const io = deps({ read: () => bom, fetch: osv([{ id: "GHSA-1" }]) });
    expect(await runCheck("sbom.json", {}, io.deps)).toBe(1);
    const text = io.out.join("");
    expect(text).toContain("pkg:npm/lodash@4.17.20");
    expect(text).toContain("GHSA-1 (CVE-1)  high  Fixed in 4.17.21.");
  });
  it("returns 0 for a clean SBOM, and prints JSON on request", async () => {
    const clean = deps({ read: () => bom, fetch: osv([]) });
    expect(await runCheck("sbom.json", {}, clean.deps)).toBe(0);
    expect(clean.out.join("")).toContain("No known advisories for 1 components");
    const json = deps({ read: () => bom, fetch: osv([{ id: "GHSA-1" }]) });
    await runCheck("sbom.json", { format: "json" }, json.deps);
    expect(JSON.parse(json.out.join("")).advisories[0].id).toBe("GHSA-1");
  });
  it("writes SARIF located at the lockfile the SBOM names, to a file, and still returns 1", async () => {
    const dir = project({ "package-lock.json": "{}", "sbom.json": "{}" });
    const withSource = JSON.stringify({ components: [{ purl: "pkg:npm/lodash@4.17.20", properties: [{ name: "0:source", value: "package-lock.json" }] }] });
    const io = deps({ read: () => withSource, fetch: osv([{ id: "GHSA-1" }]) });
    expect(await runCheck(join(dir, "sbom.json"), { format: "sarif", output: join(dir, "x.sarif") }, io.deps)).toBe(1);
    const sarif = JSON.parse(io.written[join(dir, "x.sarif")]!);
    expect(sarif.runs[0].results[0].ruleId).toBe("GHSA-1");
    expect(sarif.runs[0].results[0].message.text).toContain("Fixed in 4.17.21.");
    expect(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toMatch(/package-lock\.json$/);
    expect(io.out).toEqual([]);
  });
  it("falls back to the SBOM file when the lockfile is not on disk", async () => {
    const io = deps({ read: () => JSON.stringify({ components: [{ purl: "pkg:npm/lodash@4.17.20", properties: [{ name: "0:source", value: "gone/package-lock.json" }] }] }), fetch: osv([{ id: "GHSA-1" }]) });
    await runCheck("sbom.json", { format: "sarif" }, io.deps);
    expect(JSON.parse(io.out.join("")).runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toMatch(/sbom\.json$/);
  });
  it("rejects an unknown format", async () => {
    await expect(runCheck("x", { format: "xml" }, deps().deps)).rejects.toThrow("--format must be");
  });
  it("refuses a file that is not an SBOM and says when OSV could not be reached", async () => {
    await expect(runCheck("x", {}, deps({ read: () => "not json" }).deps)).rejects.toThrow("not a JSON SBOM");
    await expect(runCheck("x", {}, deps({ read: () => bom, fetch: vi.fn(async () => { throw new Error("offline"); }) as unknown as typeof fetch }).deps)).rejects.toThrow("Could not check against OSV: offline");
  });
});

describe("0 sbom generate --generator and --format", () => {
  const lock = JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/a": { version: "1.0.0", license: "MIT", dependencies: { b: "1" } }, "node_modules/b": { version: "1.0.0" } } });
  const fakeTool = (name: string, body: string) => { const bin = project({}); writeFileSync(join(bin, name), `#!/bin/sh\n${body}\n`); chmodSync(join(bin, name), 0o755); return { PATH: bin } as NodeJS.ProcessEnv; };
  const posix = process.platform === "win32" ? it.skip : it;
  it("writes SPDX 2.3 with --format spdx", async () => {
    const io = deps();
    await runGenerateWith(project({ "package-lock.json": lock }), { format: "spdx" }, io.deps);
    const doc = JSON.parse(io.out.join(""));
    expect(doc).toMatchObject({ spdxVersion: "SPDX-2.3", dataLicense: "CC0-1.0" });
    expect(doc.relationships.filter((relation: { relationshipType: string }) => relation.relationshipType === "DEPENDS_ON").length).toBeGreaterThan(1);
    await expect(runGenerateWith(project({ "package-lock.json": lock }), { format: "spdx", ai: true }, io.deps)).rejects.toThrow("--ai");
  });
  posix("runs an installed syft and writes its CycloneDX output", async () => {
    const env = fakeTool("syft", `printf '%s' '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"x","version":"1"}]}'`);
    const io = deps({ env });
    await runGenerateWith(project({ "readme.md": "x" }), { generator: "syft" }, io.deps);
    expect(JSON.parse(io.out.join("")).components[0].name).toBe("x");
    expect(io.err.join("\n")).toContain("1 components from syft");
  });
  it("is a usage error (exit 2) with install instructions when the tool is missing, and for unknown generators or formats", async () => {
    const io = deps({ env: { PATH: project({}) } });
    const missing = await runGenerateWith(project({ "readme.md": "x" }), { generator: "trivy" }, io.deps).catch((error: unknown) => error);
    expect(missing).toBeInstanceOf(UsageError);
    expect((missing as Error).message).toContain("brew install trivy");
    await expect(runGenerateWith(".", { generator: "nope" }, io.deps)).rejects.toThrow("Unknown generator");
    await expect(runGenerateWith(".", { format: "xml" }, io.deps)).rejects.toThrow("Unknown format");
    await expect(runGenerateWith(".", { generator: "syft", format: "spdx" }, io.deps)).rejects.toThrow("builtin");
  });
  posix("describes an image with syft: the reference goes after -- and the SBOM is written", async () => {
    const bin = project({});
    writeFileSync(join(bin, "syft"), `#!/bin/sh\nprintf '%s\\n' "$@" > '${join(bin, "args")}'\nprintf '%s' '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"musl","version":"1"}]}'\n`);
    chmodSync(join(bin, "syft"), 0o755);
    const io = deps({ env: { PATH: `${bin}:/bin:/usr/bin` } });
    await runGenerateWith(undefined, { generator: "syft", image: "nginx:1.25", output: "img.cdx.json" }, io.deps);
    expect(JSON.parse(Object.values(io.written)[0]!).components[0].name).toBe("musl");
    expect(readFileSync(join(bin, "args"), "utf8").trim().split("\n")).toEqual(["-o", "cyclonedx-json", "--", "nginx:1.25"]);
  });
  it("refuses --image with the builtin generator, cdxgen, a folder, or a value that is not an image", async () => {
    const io = deps();
    await expect(runGenerateWith(undefined, { image: "nginx" }, io.deps)).rejects.toThrow(/builtin generator.*cannot open an image/);
    await expect(runGenerateWith(undefined, { generator: "cdxgen", image: "nginx" }, io.deps)).rejects.toThrow("syft or trivy");
    await expect(runGenerateWith(".", { generator: "syft", image: "nginx" }, io.deps)).rejects.toThrow("not both");
    for (const bad of ["--help", "dir:/etc", "a b", ""]) {
      const error = await runGenerateWith(undefined, { generator: "syft", image: bad }, io.deps).catch((caught: unknown) => caught);
      expect(error, bad).toBeInstanceOf(UsageError);
    }
  });
});
describe("0 sbom scan-models", () => {
  const models = () => project({ "models/evil.pkl": "cos\nsystem\n(S'echo x'\ntR.", "models/ok.pkl": "N.", "models/w.safetensors": "\u0008\u0000\u0000\u0000\u0000\u0000\u0000\u0000{}      " });
  it("lists each file with its verdict and the offending import, and exits 1", () => {
    const io = deps();
    expect(runScanModels(models(), {}, io.deps)).toBe(1);
    const text = io.out.join("");
    expect(text).toContain("evil.pkl  [pickle]");
    expect(text).toContain("DANGEROUS");
    expect(text).toContain("dangerous: os.system (called)");
    expect(text).toContain("ok.pkl  [pickle");
    expect(text).toContain("no dangerous imports found");
    expect(io.err.join("")).toContain("1 dangerous");
  });
  it("exits 0 for a folder with nothing dangerous, without calling the files safe", () => {
    const io = deps();
    const dir = project({ "a.pkl": "N." });
    expect(runScanModels(dir, {}, io.deps)).toBe(0);
    expect(io.err.join("")).toContain("is not a statement that a file is safe");
  });
  it("prints JSON and SARIF", () => {
    const dir = models();
    const json = deps();
    runScanModels(dir, { format: "json" }, json.deps);
    expect(JSON.parse(json.out.join("")).files.map((file: { verdict: string }) => file.verdict).sort()).toEqual(["dangerous", "none-found", "not-pickle"]);
    const sarif = deps();
    expect(runScanModels(dir, { format: "sarif" }, sarif.deps)).toBe(1);
    const parsed = JSON.parse(sarif.out.join(""));
    expect(parsed.version).toBe("2.1.0");
    expect(parsed.runs[0].results).toHaveLength(1);
    expect(parsed.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toMatch(/models\/evil\.pkl$/);
  });
  it("scans a single file whatever it is called, and rejects a missing path or format", () => {
    const dir = project({ "payload.dat": "cos\nsystem\n(S'x'\ntR." });
    expect(() => runScanModels(join(dir, "nope"), {}, deps().deps)).toThrow("does not exist");
    expect(() => runScanModels(dir, { format: "xml" }, deps().deps)).toThrow("--format");
    expect(runScanModels(join(dir, "payload.dat"), {}, deps().deps)).toBe(0); // content is not a recognised pickle container for .dat
  });
});

describe("0 sbom generate --resolve-from and java-usage", () => {
  const tree = "demo:app:jar:1.0\n+- org.apache.logging.log4j:log4j-core:jar:2.14.1:compile\n|  \\- org.apache.logging.log4j:log4j-api:jar:2.14.1:compile\n\\- junit:junit:jar:4.13.2:test\n";
  const pom = "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>app</artifactId><version>1</version></project>";
  const file = (text: string) => join(project({ "report.txt": text }), "report.txt");
  const real = (extra: Partial<SbomDeps> = {}) => deps({ read: (p: string) => readFileSync(p, "utf8"), ...extra });

  it("reads a dependency report without running anything, even under ZERO_ENTERPRISE", async () => {
    const io = real({ env: { ZERO_ENTERPRISE: "1", PATH: "/nonexistent" } });
    await runGenerateWith(project({ "pom.xml": pom }), { resolveFrom: [file(tree)] }, io.deps);
    const bom = JSON.parse(io.out.join(""));
    expect(bom.components.map((c: { purl: string }) => c.purl)).toContain("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
    expect(bom.components.find((c: { name: string }) => c.name.endsWith("log4j-api")).properties).toContainEqual({ name: "0:resolved", value: "true" });
  });
  it("rejects a file that is not a report, and flags that do not fit", async () => {
    await expect(runGenerateWith(project({ "pom.xml": pom }), { resolveFrom: [file("hello")] }, real().deps)).rejects.toThrow(/not a Maven dependency:tree/);
    await expect(runGenerateWith(project({ "pom.xml": pom }), { resolveFrom: [file(tree)], resolve: true }, real().deps)).rejects.toThrow(/cannot be combined/);
    await expect(runGenerateWith(project({ "pom.xml": pom }), { mavenSettings: "/x" }, real().deps)).rejects.toThrow(/only apply with --resolve/);
    await expect(runGenerateWith(project({ "pom.xml": pom }), { resolve: true, allowBuildTools: true, mavenSettings: "/no/such/settings.xml" }, real().deps)).rejects.toThrow(/is not a file/);
  });
  it("java-usage lists the imports of the source for the Maven components of an SBOM", () => {
    const sbom = JSON.stringify({ components: [{ purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" }, { purl: "pkg:maven/junit/junit@4.13.2" }, { purl: "pkg:npm/lodash@4.17.21" }] });
    const dir = project({ "sbom.json": sbom, "src/main/java/A.java": "import org.apache.logging.log4j.LogManager;\nclass A {}\n" });
    const io = real();
    runJavaUsage(join(dir, "sbom.json"), dir, {}, io.deps);
    const text = io.out.join("");
    expect(text).toContain("org.apache.logging.log4j/log4j-core 2.14.1  imported");
    expect(text).toContain("src/main/java/A.java:1");
    expect(text).toContain("1 of 2 Maven components");
    expect(() => runJavaUsage(join(dir, "sbom.json"), dir, { format: "xml" }, io.deps)).toThrow("--format");
    const none = project({ "sbom.json": JSON.stringify({ components: [{ purl: "pkg:npm/a@1" }] }) });
    expect(() => runJavaUsage(join(none, "sbom.json"), none, {}, real().deps)).toThrow(/no Maven components/);
  });
});


describe("0 sbom agent-config", () => {
  const zeroWidth = String.fromCodePoint(0x200b);
  const noisy = () => project({ "CLAUDE.md": `rules${zeroWidth}\n`, ".mcp.json": JSON.stringify({ mcpServers: { s: { command: "npx", args: ["-y", "some-mcp"] } } }), ".claude/settings.json": JSON.stringify({ permissions: { allow: ["Bash(curl:*)"] } }) });
  it("lists findings as text and exits 0 without --fail-on", () => {
    const io = deps();
    expect(runAgentConfig(noisy(), {}, io.deps)).toBe(0);
    const text = io.out.join("");
    expect(text).toContain("agent-config/hidden-unicode");
    expect(text).toContain("agent-config/mcp-unpinned-launcher");
    expect(text).toContain("agent-config/broad-permission");
  });
  it("exits 1 when a finding is at or above --fail-on, and 0 when none is", () => {
    const dir = noisy();
    expect(runAgentConfig(dir, { failOn: "high" }, deps().deps)).toBe(1);
    expect(runAgentConfig(project({ "CLAUDE.md": "plain rules\n" }), { failOn: "info" }, deps().deps)).toBe(0);
    expect(runAgentConfig(project({ ".mcp.json": JSON.stringify({ mcpServers: { s: { command: "npx", args: ["-y", "some-mcp"] } } }) }), { failOn: "high" }, deps().deps)).toBe(0);
  });
  it("writes SARIF and JSON, to a file with --output", () => {
    const dir = noisy();
    const io = deps();
    runAgentConfig(dir, { format: "sarif" }, io.deps);
    const sarif = JSON.parse(io.out.join(""));
    expect(sarif.runs[0].tool.driver.name).toBe("0 sbom agent-config");
    expect(sarif.runs[0].results.length).toBeGreaterThan(2);
    const file = deps();
    runAgentConfig(dir, { format: "json", output: join(dir, "out.json") }, file.deps);
    expect(Object.keys(file.written)).toHaveLength(1);
    expect(JSON.parse(Object.values(file.written)[0]!).findings.length).toBeGreaterThan(2);
    expect(file.out).toEqual([]);
  });
  it("passes --allow-host to the remote server rule", () => {
    const dir = project({ ".mcp.json": JSON.stringify({ mcpServers: { r: { url: "https://other.example.org/mcp" } } }) });
    const io = deps();
    runAgentConfig(dir, { format: "json", allowHost: ["mcp.example.com"] }, io.deps);
    expect(JSON.parse(io.out.join("")).findings.map((item: { ruleId: string }) => item.ruleId)).toContain("agent-config/mcp-remote-insecure");
  });
  it("is a usage error for a missing path, a bad format or a bad severity", () => {
    expect(() => runAgentConfig("/no/such/folder", {}, deps().deps)).toThrow("does not exist");
    expect(() => runAgentConfig(noisy(), { format: "xml" }, deps().deps)).toThrow("--format must be text, json or sarif");
    expect(() => runAgentConfig(noisy(), { failOn: "severe" }, deps().deps)).toThrow("--fail-on must be one of");
  });
});
