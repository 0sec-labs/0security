import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { GeneratorFailedError, GeneratorNotInstalledError, parseImageSource, runExternalGenerator } from "./index.js";

const dirs: string[] = [];
afterEach(() => dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true })));
const tmp = () => { const dir = mkdtempSync(join(tmpdir(), "0-fake-")); dirs.push(dir); return dir; };
const BOM = JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.5", components: [{ type: "library", name: "x", version: "1" }] });
/** A fake tool on a PATH of its own: records its arguments and working directory, then runs `script`. */
const fake = (name: string, script: string) => {
  const bin = tmp(); const log = join(bin, "args.log");
  writeFileSync(join(bin, name), `#!/bin/sh\n{ printf '%s\\n' "$@"; pwd; } > '${log}'\n${script}\n`); chmodSync(join(bin, name), 0o755);
  return { env: { PATH: bin } as NodeJS.ProcessEnv, args: () => readFileSync(log, "utf8").trim().split("\n") };
};
const posix = process.platform === "win32" ? it.skip : it;

describe("runExternalGenerator", () => {
  posix("syft: dir: source, cyclonedx-json to stdout, run outside the scanned folder", async () => {
    const tool = fake("syft", `printf '%s' '${BOM}'`); const folder = tmp();
    const { bom } = await runExternalGenerator("syft", folder, { env: tool.env });
    expect(bom.bomFormat).toBe("CycloneDX");
    const lines = tool.args();
    expect(lines.slice(0, 3)).toEqual([`dir:${folder}`, "-o", "cyclonedx-json"]);
    expect(lines.at(-1)).not.toBe(folder);
  });
  posix("trivy: fs --format cyclonedx with the folder last", async () => {
    const tool = fake("trivy", `printf '%s' '${BOM}'`); const folder = tmp();
    await runExternalGenerator("trivy", folder, { env: tool.env });
    expect(tool.args().slice(0, 5)).toEqual(["fs", "--format", "cyclonedx", "--quiet", folder]);
  });
  posix("cdxgen: no package-manager run, output file read back", async () => {
    const tool = fake("cdxgen", `while [ "$1" != "-o" ]; do shift; done; printf '%s' '${BOM}' > "$2"`); const folder = tmp();
    const { bom } = await runExternalGenerator("cdxgen", folder, { env: tool.env });
    expect(bom.bomFormat).toBe("CycloneDX");
    const lines = tool.args();
    expect(lines.slice(0, 3)).toEqual(["--lifecycle", "pre-build", "--no-install-deps"]);
    expect(lines[3]).toBe("-o");
    expect(lines[4]).toMatch(/bom\.json$/);
    expect(lines[5]).toBe(folder);
  });
  posix("refuses a folder that is not an absolute path, so it can never read as an option", async () => {
    const tool = fake("trivy", `printf '%s' '${BOM}'`);
    await expect(runExternalGenerator("trivy", "--help", { env: tool.env })).rejects.toThrow("absolute");
  });
  it("says how to install a tool that is missing", async () => {
    const error = await runExternalGenerator("syft", tmp(), { env: { PATH: tmp() } }).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(GeneratorNotInstalledError);
    expect((error as Error).message).toContain("brew install syft");
  });
  posix("reports a failing tool, non-JSON output, a non-CycloneDX document and a timeout", async () => {
    await expect(runExternalGenerator("syft", tmp(), { env: fake("syft", "echo boom >&2; exit 3").env })).rejects.toThrow(/exit 3\):\nboom/);
    await expect(runExternalGenerator("syft", tmp(), { env: fake("syft", "echo hello").env })).rejects.toThrow("did not produce JSON");
    await expect(runExternalGenerator("syft", tmp(), { env: fake("syft", "echo '{}'").env })).rejects.toThrow("CycloneDX");
    await expect(runExternalGenerator("syft", tmp(), { env: fake("syft", "exec sleep 5").env, timeoutMs: 200 })).rejects.toBeInstanceOf(GeneratorFailedError);
  });
});

describe("container images", () => {
  const archive = () => { const dir = tmp(); const file = join(dir, "img.tar"); writeFileSync(file, "x"); return file; };
  it("accepts references and existing archives and refuses anything that could be an option or another source", () => {
    for (const ok of ["nginx", "nginx:1.25", "library/nginx:1.25", "localhost:5000/app", "ghcr.io/org/app:v1.2-rc.1", `ghcr.io/org/app@sha256:${"a".repeat(64)}`]) expect(parseImageSource(ok)).toEqual({ kind: "reference", value: ok });
    const file = archive();
    expect(parseImageSource(file)).toEqual({ kind: "archive", value: file });
    for (const bad of ["", "--help", "-o", "a b", "a\nb", "dir:src", "file:x", "docker:nginx", "sbom:x.json", "nginx:", "a//b", "./missing.tar", "/missing/img.tar", "x".repeat(600)]) expect(() => parseImageSource(bad), bad).toThrow(GeneratorFailedError);
  });
  it("accepts an OCI layout folder and refuses any other folder", () => {
    const layout = tmp(); writeFileSync(join(layout, "oci-layout"), "{}");
    expect(parseImageSource(layout)).toEqual({ kind: "oci-layout", value: layout });
    expect(() => parseImageSource(tmp())).toThrow("not an OCI image layout");
  });
  posix("syft: the reference goes after -- as one argument", async () => {
    const tool = fake("syft", `printf '%s' '${BOM}'`);
    await runExternalGenerator("syft", "", { env: tool.env, image: parseImageSource("nginx:1.25") });
    expect(tool.args().slice(0, 4)).toEqual(["-o", "cyclonedx-json", "--", "nginx:1.25"]);
  });
  posix("syft: an archive is passed by absolute path and an OCI layout with the oci-dir scheme", async () => {
    const tool = fake("syft", `printf '%s' '${BOM}'`); const file = archive();
    await runExternalGenerator("syft", "", { env: tool.env, image: parseImageSource(file) });
    expect(tool.args()[3]).toBe(file);
    const layout = tmp(); writeFileSync(join(layout, "oci-layout"), "{}");
    await runExternalGenerator("syft", "", { env: tool.env, image: parseImageSource(layout) });
    expect(tool.args()[3]).toBe(`oci-dir:${layout}`);
  });
  posix("trivy: image with the reference after --, and --input for an archive", async () => {
    const tool = fake("trivy", `printf '%s' '${BOM}'`);
    await runExternalGenerator("trivy", "", { env: tool.env, image: parseImageSource("nginx:1.25") });
    expect(tool.args().slice(0, 6)).toEqual(["image", "--format", "cyclonedx", "--quiet", "--", "nginx:1.25"]);
    const file = archive();
    await runExternalGenerator("trivy", "", { env: tool.env, image: parseImageSource(file) });
    expect(tool.args().slice(0, 6)).toEqual(["image", "--format", "cyclonedx", "--quiet", "--input", file]);
  });
  it("is refused for cdxgen", async () => {
    await expect(runExternalGenerator("cdxgen", "", { image: { kind: "reference", value: "nginx" } })).rejects.toThrow("syft or trivy");
  });
});
