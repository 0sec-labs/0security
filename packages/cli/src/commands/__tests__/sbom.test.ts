import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { UsageError } from "../output.js";
import { runCheck, runGenerate, runGenerateWith, type SbomDeps } from "../sbom.js";

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
  const osv = (vulns: unknown[]) => (async (url: string | URL | Request) => String(url).endsWith("querybatch") ? new Response(JSON.stringify({ results: [{ vulns }] })) : new Response(JSON.stringify({ id: "GHSA-1", aliases: ["CVE-1"], summary: "Bad", database_specific: { severity: "HIGH" }, affected: [{ ranges: [{ events: [{ fixed: "4.17.21" }] }] }] }))) as typeof fetch;
  it("lists advisories per component and returns 1", async () => {
    const io = deps({ read: () => bom, fetch: osv([{ id: "GHSA-1" }]) });
    expect(await runCheck("sbom.json", {}, io.deps)).toBe(1);
    const text = io.out.join("");
    expect(text).toContain("pkg:npm/lodash@4.17.20");
    expect(text).toContain("GHSA-1 (CVE-1)  HIGH  fixed in 4.17.21");
  });
  it("returns 0 for a clean SBOM, and prints JSON on request", async () => {
    const clean = deps({ read: () => bom, fetch: osv([]) });
    expect(await runCheck("sbom.json", {}, clean.deps)).toBe(0);
    expect(clean.out.join("")).toContain("No known advisories for 1 components");
    const json = deps({ read: () => bom, fetch: osv([{ id: "GHSA-1" }]) });
    await runCheck("sbom.json", { format: "json" }, json.deps);
    expect(JSON.parse(json.out.join("")).advisories[0].id).toBe("GHSA-1");
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
});
