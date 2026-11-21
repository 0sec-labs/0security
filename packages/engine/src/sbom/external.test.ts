import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { GeneratorFailedError, GeneratorNotInstalledError, runExternalGenerator } from "./index.js";

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
