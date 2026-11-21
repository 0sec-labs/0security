/**
 * Run an installed SBOM generator (syft, cdxgen, trivy) on a folder and return its CycloneDX JSON. The tool is started
 * with an argument array (no shell), an absolute folder path (so it cannot be read as an option), a timeout, and a
 * working directory that is not the scanned folder (so project-local tool config is not picked up). Nothing from the
 * scanned folder is executed by us; what the tool itself does is the tool's behaviour, so cdxgen is told not to run
 * package managers.
 */
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";

export const EXTERNAL_GENERATORS = ["syft", "cdxgen", "trivy"] as const;
export type ExternalGenerator = (typeof EXTERNAL_GENERATORS)[number];

export class GeneratorNotInstalledError extends Error {
  constructor(readonly tool: ExternalGenerator) { super(`${tool} is not installed (or not on PATH). Install it: ${INSTALL[tool]}`); }
}
export class GeneratorFailedError extends Error {}

const INSTALL: Record<ExternalGenerator, string> = {
  syft: "brew install syft, or see https://github.com/anchore/syft#installation",
  cdxgen: "npm install -g @cyclonedx/cdxgen, or see https://github.com/CycloneDX/cdxgen",
  trivy: "brew install trivy, or see https://trivy.dev/latest/getting-started/installation/",
};

const MAX_OUTPUT_BYTES = 256 * 1024 * 1024;
export const DEFAULT_GENERATOR_TIMEOUT_MS = 10 * 60 * 1000;

/**
 * The command line for each tool. Verified against the tools' documentation: syft `dir:` sources with `-o cyclonedx-json`
 * (syft writes to stdout); cdxgen `-o <file> <path>` with `--lifecycle pre-build` and `--no-install-deps` (both documented
 * as "do not run the project's package manager"); trivy `fs --format cyclonedx <path>` with `--quiet`. NOT verified here
 * because the tools were not available to run: whether trivy needs to fetch its own vulnerability database for this
 * output on a first run, and cdxgen's behaviour on versions older than the ones documenting those two flags.
 */
function command(tool: ExternalGenerator, folder: string, outputFile: string): { args: string[]; output: "stdout" | "file" } {
  switch (tool) {
    case "syft": return { args: [`dir:${folder}`, "-o", "cyclonedx-json"], output: "stdout" };
    case "cdxgen": return { args: ["--lifecycle", "pre-build", "--no-install-deps", "-o", outputFile, folder], output: "file" };
    case "trivy": return { args: ["fs", "--format", "cyclonedx", "--quiet", folder], output: "stdout" };
  }
}

export interface ExternalOptions { timeoutMs?: number; env?: NodeJS.ProcessEnv }

export async function runExternalGenerator(tool: ExternalGenerator, folder: string, options: ExternalOptions = {}): Promise<{ bom: Record<string, unknown> }> {
  if (!isAbsolute(folder)) throw new GeneratorFailedError("The folder must be an absolute path.");
  const scratch = await mkdtemp(join(tmpdir(), "0-sbom-gen-"));
  try {
    const { args, output } = command(tool, folder, join(scratch, "bom.json"));
    const stdout = await new Promise<string>((resolve, reject) => {
      execFile(tool, args, { cwd: scratch, env: options.env ?? process.env, timeout: options.timeoutMs ?? DEFAULT_GENERATOR_TIMEOUT_MS, maxBuffer: MAX_OUTPUT_BYTES, encoding: "utf8", windowsHide: true }, (error, out, err) => {
        if (!error) return resolve(out);
        const failure = error as NodeJS.ErrnoException & { killed?: boolean; signal?: string };
        if (failure.code === "ENOENT") return reject(new GeneratorNotInstalledError(tool));
        if (failure.killed || failure.signal === "SIGTERM") return reject(new GeneratorFailedError(`${tool} did not finish within ${Math.round((options.timeoutMs ?? DEFAULT_GENERATOR_TIMEOUT_MS) / 1000)} seconds.`));
        const detail = String(err).replace(/[^\x20-\x7e\n]/g, "").trim().split("\n").slice(-5).join("\n");
        reject(new GeneratorFailedError(`${tool} failed${typeof failure.code === "number" ? ` (exit ${failure.code})` : ""}${detail ? `:\n${detail}` : "."}`));
      });
    });
    const raw = output === "file" ? await readFile(join(scratch, "bom.json"), "utf8").catch(() => "") : stdout;
    let bom: unknown;
    try { bom = JSON.parse(raw); } catch { throw new GeneratorFailedError(`${tool} did not produce JSON.`); }
    if (!bom || typeof bom !== "object" || (bom as Record<string, unknown>).bomFormat !== "CycloneDX") throw new GeneratorFailedError(`${tool} did not produce a CycloneDX document.`);
    return { bom: bom as Record<string, unknown> };
  } finally { await rm(scratch, { recursive: true, force: true }); }
}
