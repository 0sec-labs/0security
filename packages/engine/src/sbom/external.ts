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
import { statSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";

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

export const IMAGE_GENERATORS = ["syft", "trivy"] as const;

/** An image to describe: a registry or local-daemon reference, or an image archive or OCI layout on disk (absolute path). */
export type ImageSource = { kind: "reference"; value: string } | { kind: "archive"; value: string } | { kind: "oci-layout"; value: string };

const COMPONENT = "[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?";
const REFERENCE = new RegExp(`^${COMPONENT}(?::[0-9]+)?(?:/${COMPONENT})*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@[a-z0-9]+:[A-Fa-f0-9]{32,})?$`);
// syft reads "dir:x" and "file:x" as a folder or file on disk, "sbom:x" as an SBOM; none of those is an image reference.
const SCHEMES = new Set(["dir", "file", "sbom", "purl", "docker", "podman", "containerd", "registry", "docker-archive", "oci-archive", "oci-dir", "singularity"]);

/** Validate the value of `--image`. Throws a message the user can act on. Never returns a value that could be read as an option. */
export function parseImageSource(value: string): ImageSource {
  if (!value.trim()) throw new GeneratorFailedError("--image needs an image reference or the path of an image archive.");
  if (value.startsWith("-")) throw new GeneratorFailedError(`'${value}' cannot be an image: it looks like an option.`);
  // eslint-disable-next-line no-control-regex
  if (/[\s\u0000-\u001f\u007f]/.test(value) || value.length > 512) throw new GeneratorFailedError("The image reference must be one word of at most 512 characters, with no spaces or control characters.");
  let info: ReturnType<typeof statSync> | undefined;
  try { info = statSync(value); } catch { /* not on disk: a reference */ }
  if (info?.isFile()) return { kind: "archive", value: resolve(value) };
  if (info?.isDirectory()) {
    const path = resolve(value);
    let layout = false;
    try { layout = statSync(join(path, "oci-layout")).isFile(); } catch { /* not an OCI layout */ }
    if (!layout) throw new GeneratorFailedError(`'${value}' is a folder but not an OCI image layout (it has no oci-layout file). To list the packages of a folder, run 0security sbom generate ${value} without --image.`);
    return { kind: "oci-layout", value: path };
  }
  if (value.startsWith(".") || value.startsWith("/") || value.startsWith("~")) throw new GeneratorFailedError(`--image ${value}: no such file or folder.`);
  const scheme = value.split(":")[0]!.toLowerCase();
  if (SCHEMES.has(scheme)) throw new GeneratorFailedError(`--image takes a plain reference such as nginx:1.25 or the path of an archive, not '${scheme}:...'.`);
  if (!REFERENCE.test(value)) throw new GeneratorFailedError(`'${value}' is not an image reference or an existing archive. Use a reference such as nginx:1.25 or ghcr.io/org/app@sha256:..., or the path of a docker save archive.`);
  return { kind: "reference", value };
}

/** The command line for an image. The reference goes after `--`, so it cannot be read as an option. */
function imageCommand(tool: "syft" | "trivy", image: ImageSource): string[] {
  if (tool === "syft") return ["-o", "cyclonedx-json", "--", image.kind === "oci-layout" ? `oci-dir:${image.value}` : image.value];
  return image.kind === "reference" ? ["image", "--format", "cyclonedx", "--quiet", "--", image.value] : ["image", "--format", "cyclonedx", "--quiet", "--input", image.value];
}

export interface ExternalOptions { timeoutMs?: number; env?: NodeJS.ProcessEnv; image?: ImageSource }

export async function runExternalGenerator(tool: ExternalGenerator, folder: string, options: ExternalOptions = {}): Promise<{ bom: Record<string, unknown> }> {
  if (options.image && tool !== "syft" && tool !== "trivy") throw new GeneratorFailedError(`--image works with syft or trivy, not ${tool}.`);
  if (!options.image && !isAbsolute(folder)) throw new GeneratorFailedError("The folder must be an absolute path.");
  const scratch = await mkdtemp(join(tmpdir(), "0-sbom-gen-"));
  try {
    const { args, output } = options.image ? { args: imageCommand(tool as "syft" | "trivy", options.image), output: "stdout" as const } : command(tool, folder, join(scratch, "bom.json"));
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
