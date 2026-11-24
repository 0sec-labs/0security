/**
 * `0 sbom scan-models <path>` lists the code-running imports in pickle-based model files.
 * `0 sbom generate [folder]` writes a CycloneDX (or SPDX) SBOM from the lockfiles in a folder, or runs syft, cdxgen or trivy; `0 sbom check <file>` looks every
 * component up in the public OSV advisory database. Nothing is installed or run: lockfiles, pom.xml and Gradle files are read as text.
 * The one exception is --resolve, which runs the operator's own mvn or gradle after explicit consent.
 */
import { readFileSync, statSync, writeFileSync } from "node:fs";
import { relative, resolve, sep } from "node:path";
import { createInterface } from "node:readline/promises";
import type { Command } from "commander";
import { assertEgressAllowed, EXTERNAL_GENERATORS, generateSbom, ResolveFailedError, resolveJvmDependencies, GeneratorNotInstalledError, IMAGE_GENERATORS, parseImageSource, LOCKFILES, modelScanToSarif, runExternalGenerator, scanModelPath, toSpdx, type Component, type ExternalGenerator, type ImageSource, type ModelFileResult } from "@0/engine";
import { VERSION } from "@0/engine/shared";
import { finishWithError, UsageError } from "./output.js";
import { registerSbomLicenses } from "./sbom-licenses.js";
import { runCheckReport, type CheckOptions } from "./sbom-check.js";
import { resolutionLine } from "./sbom-resolution.js";

const MAX_SBOM_BYTES = 50 * 1024 * 1024;

export interface SbomDeps {
  out(text: string): void;
  err(text: string): void;
  write(path: string, text: string): void;
  read(path: string): string;
  fetch?: typeof fetch;
  /** Environment for an external generator (tests point PATH at a fake tool). */
  env?: NodeJS.ProcessEnv;
  /** Ask the operator a yes/no question. Absent when there is no terminal to ask on. */
  confirm?(question: string): Promise<boolean>;
}
const defaults: SbomDeps = {
  out: text => process.stdout.write(text),
  err: text => process.stderr.write(`${text}\n`),
  write: (path, text) => writeFileSync(path, text, { mode: 0o644 }),
  confirm: process.stdin.isTTY && process.stderr.isTTY ? async question => {
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    try { return /^y(es)?$/i.test((await rl.question(`${question} [y/N] `)).trim()); } finally { rl.close(); }
  } : undefined,
  read(path) {
    const info = statSync(path);
    if (!info.isFile() || info.size > MAX_SBOM_BYTES) throw new UsageError("The SBOM must be a regular file of at most 50 MB.");
    return readFileSync(path, "utf8");
  },
};

export interface GenerateOptions { output?: string; name?: string; ai?: boolean; generator?: string; format?: string; image?: string; resolve?: boolean; allowBuildTools?: boolean; resolveOffline?: boolean }

export const RESOLVE_WARNING = "--resolve runs the project's own build tool (mvn or gradle from your PATH) in this folder. That evaluates the project's build files, which can run arbitrary code, and it downloads from the repositories the project names. Run it only on a project you trust.";

/** Run the project's build tool after the operator agreed: the flag --allow-build-tools, or a yes at the prompt. */
async function resolveWithConsent(folder: string, options: GenerateOptions, deps: SbomDeps): Promise<{ components: Component[] }> {
  assertEgressAllowed("Maven and Gradle repositories (sbom generate --resolve)", deps.env ?? process.env);
  deps.err(`warning: ${RESOLVE_WARNING}`);
  if (!options.allowBuildTools) {
    const agreed = deps.confirm ? await deps.confirm("Run the build tool now?") : false;
    if (!agreed) throw new UsageError("Not run. Pass --allow-build-tools to confirm that 0 may run this project's build tool.");
  }
  try {
    const result = await resolveJvmDependencies(requireFolder(folder), { ...(deps.env ? { env: deps.env } : {}), ...(options.resolveOffline ? { offline: true } : {}) });
    for (const warning of result.warnings) deps.err(`warning: ${warning}`);
    deps.err(`resolved ${result.components.length} Maven/Gradle components with ${result.tools.join(", ")}`);
    return result;
  } catch (error) { if (error instanceof ResolveFailedError) throw new UsageError(error.message); throw error; }
}

function requireFolder(folder: string): string {
  const target = resolve(folder);
  let isFolder = false;
  try { isFolder = statSync(target).isDirectory(); } catch { /* reported below */ }
  if (!isFolder) throw new UsageError(`'${folder}' is not a folder.`);
  return target;
}

/** `0 sbom generate` for every generator: the built-in lockfile reader, or an installed external tool. */
export async function runGenerateWith(folder: string | undefined, options: GenerateOptions, deps: SbomDeps): Promise<void> {
  const generator = options.generator ?? "builtin";
  const format = options.format ?? "cyclonedx";
  if (generator !== "builtin" && !(EXTERNAL_GENERATORS as readonly string[]).includes(generator)) throw new UsageError(`Unknown generator '${generator}'. Use builtin, ${EXTERNAL_GENERATORS.join(", ")}.`);
  if (format !== "cyclonedx" && format !== "spdx") throw new UsageError(`Unknown format '${format}'. Use cyclonedx or spdx.`);
  if ((options.allowBuildTools || options.resolveOffline) && !options.resolve) throw new UsageError("--allow-build-tools and --resolve-offline only apply with --resolve.");
  if (options.resolve && generator !== "builtin") throw new UsageError("--resolve works with the builtin generator only.");
  if (options.resolve && options.image !== undefined) throw new UsageError("--resolve reads a project folder; it cannot be used with --image.");
  if (options.image !== undefined) {
    if (generator === "builtin") throw new UsageError(`--image needs --generator ${IMAGE_GENERATORS.join(" or ")}: the builtin generator reads lockfiles and cannot open an image.`);
    if (!(IMAGE_GENERATORS as readonly string[]).includes(generator)) throw new UsageError(`--image works with --generator ${IMAGE_GENERATORS.join(" or ")}, not ${generator}.`);
    if (folder !== undefined) throw new UsageError("Give a folder or --image, not both.");
  }
  if (generator === "builtin") {
    if (format === "spdx" && options.ai) throw new UsageError("--ai is only available with --format cyclonedx: SPDX 2.3 has no type for models, datasets or MCP servers.");
    const resolved = options.resolve ? await resolveWithConsent(folder ?? ".", options, deps) : undefined;
    return runGenerate(folder ?? ".", options, deps, resolved?.components);
  }
  if (format !== "cyclonedx") throw new UsageError(`--format ${format} is only available with the builtin generator; ${generator} is run for its CycloneDX output.`);
  if (options.ai) throw new UsageError("--ai is only available with the builtin generator.");
  let image: ImageSource | undefined;
  if (options.image !== undefined) {
    try { image = parseImageSource(options.image); } catch (error) { throw new UsageError(error instanceof Error ? error.message : String(error)); }
  }
  const target = image ? "" : requireFolder(folder ?? ".");
  let bom: Record<string, unknown>;
  try { bom = (await runExternalGenerator(generator as ExternalGenerator, target, { ...(deps.env ? { env: deps.env } : {}), ...(image ? { image } : {}) })).bom; }
  catch (error) { if (error instanceof GeneratorNotInstalledError) throw new UsageError(error.message); throw error; }
  const text = `${JSON.stringify(bom, null, 2)}\n`;
  if (options.output) { deps.write(resolve(options.output), text); deps.err(`Wrote ${options.output}`); } else deps.out(text);
  deps.err(`${Array.isArray(bom.components) ? bom.components.length : 0} components from ${generator}`);
}

export function runGenerate(folder: string, options: GenerateOptions, deps: SbomDeps, resolved?: Component[]): void {
  const target = requireFolder(folder);
  const result = generateSbom(target, { toolVersion: VERSION, ...(resolved ? { resolved } : {}), ...(options.name ? { name: options.name } : {}), ...(options.ai ? { ai: true } : {}) });
  if (!result.bom.components.length && !result.bom.services?.length && !result.unresolved.length) {
    const supported = [...new Set([...LOCKFILES.map(lock => lock.file), "pom.xml", "build.gradle", "build.gradle.kts", "gradle/libs.versions.toml"])].join(", ");
    throw new UsageError(`No supported lockfile with packages${options.ai ? " and no AI components" : ""} in ${folder}. Supported: ${supported}. For Swift or C/C++ use --generator syft, cdxgen or trivy; for a container image use --image with --generator syft or trivy.`);
  }
  const text = `${JSON.stringify(options.format === "spdx" ? toSpdx(result.bom) : result.bom, null, 2)}\n`;
  if (options.output) { deps.write(resolve(options.output), text); deps.err(`Wrote ${options.output}`); } else deps.out(text);
  const aiCount = result.bom.components.filter(component => component.type !== "library").length + (result.bom.services?.length ?? 0);
  deps.err(`${result.bom.components.filter(component => component.type === "library").length} components from ${result.lockfiles.length} lockfile${result.lockfiles.length === 1 ? "" : "s"}${result.lockfiles.length ? `: ${result.lockfiles.map(lock => `${lock.path} (${lock.label}, ${lock.components})`).join(", ")}` : ""}${options.ai ? `; ${aiCount} AI components (models, datasets, hosted model ids, MCP servers)` : ""}`);
  deps.err(resolutionLine(result.bom.components.filter(component => component.type === "library").length, result.unresolved.map(item => `${item.name} (${item.reason}) in ${item.source}`)));
}

export async function runCheck(file: string, options: CheckOptions, deps: SbomDeps): Promise<number> {
  return runCheckReport(file, options, deps);
}

const VERDICT_LABEL: Record<ModelFileResult["verdict"], string> = {
  dangerous: "DANGEROUS", unrecognised: "unrecognised imports", "none-found": "no dangerous imports found", "not-pickle": "not a pickle format", "not-scanned": "not scanned",
};

/** `0 sbom scan-models <path>`: reads model files as bytes and lists the imports their pickle streams would run. Exit 1 when any is dangerous. */
export function runScanModels(path: string, options: { format?: string }, deps: SbomDeps): number {
  const target = resolve(path);
  let exists = false;
  try { statSync(target); exists = true; } catch { /* reported below */ }
  if (!exists) throw new UsageError(`'${path}' does not exist.`);
  if (options.format && !["text", "json", "sarif"].includes(options.format)) throw new UsageError("--format must be text, json or sarif.");
  const report = scanModelPath(target);
  const dangerous = report.files.filter(file => file.verdict === "dangerous");
  const folder = statSync(target).isDirectory();
  const toCwd = (file: ModelFileResult): string => {
    const absolute = folder ? resolve(target, file.path) : target;
    const rel = relative(process.cwd(), absolute);
    return (rel && !rel.startsWith("..") ? rel : absolute).split(sep).join("/");
  };
  if (options.format === "json") deps.out(`${JSON.stringify({ root: path, files: report.files, skippedSymlinks: report.skippedSymlinks, truncated: report.truncated }, null, 2)}\n`);
  else if (options.format === "sarif") deps.out(`${JSON.stringify(modelScanToSarif(report.files, { toolVersion: VERSION, uri: toCwd }), null, 2)}\n`);
  else {
    if (!report.files.length) deps.out(`No model files found in ${path}.\n`);
    const lines: string[] = [];
    for (const file of report.files) {
      const shown = folder ? file.path : path;
      lines.push(`${shown}  [${file.format}${file.protocol !== undefined ? `, protocol ${file.protocol}` : ""}]  ${VERDICT_LABEL[file.verdict]}`);
      lines.push(`    ${file.summary}`);
      for (const item of file.findings) lines.push(`    ${item.risk === "dangerous" ? "dangerous" : "unrecognised import"}: ${item.qualified}${item.called ? " (called)" : ""}${item.member ? ` in ${item.member}` : ""} - ${item.reason}`);
      for (const warning of file.warnings) lines.push(`    warning: ${warning}`);
    }
    if (lines.length) deps.out(`${lines.join("\n")}\n`);
    if (report.files.length) deps.err(`${report.files.length} model file${report.files.length === 1 ? "" : "s"}: ${dangerous.length} dangerous, ${report.files.filter(file => file.verdict === "unrecognised").length} with unrecognised imports, ${report.files.filter(file => file.verdict === "none-found").length} with no dangerous imports found, ${report.files.filter(file => file.verdict === "not-pickle").length} not pickle, ${report.files.filter(file => file.verdict === "not-scanned").length} not scanned.${dangerous.length ? "" : " 'No dangerous imports found' is not a statement that a file is safe."}`);
  }
  if (report.truncated) deps.err("The folder was too large to walk completely; some files were not looked at.");
  if (report.skippedSymlinks) deps.err(`${report.skippedSymlinks} symbolic link${report.skippedSymlinks === 1 ? "" : "s"} not followed.`);
  return dangerous.length ? 1 : 0;
}

export function registerSbomCommand(program: Command, deps: SbomDeps = defaults): void {
  const sbom = program.command("sbom").description("Generate an SBOM from lockfiles, check one against known advisories, and scan model files");
  sbom.command("generate")
    .description("Write an SBOM (CycloneDX 1.5 or SPDX 2.3) from the lockfiles in a folder (npm, pnpm, yarn, Cargo, Go, Python, Ruby, PHP, .NET, Maven, Gradle, Dart, Elixir)")
    .argument("[folder]", "Folder to read lockfiles from (default: .)")
    .option("-o, --output <file>", "Write the SBOM to a file instead of stdout")
    .option("--name <name>", "Name of the application the SBOM describes (default: the folder's name)")
    .option("--generator <tool>", `Who writes the SBOM: builtin (reads lockfiles; default), ${EXTERNAL_GENERATORS.join(", ")} (run the installed tool; exit 2 if it is missing)`, "builtin")
    .option("--format <format>", "Output format: cyclonedx (1.5, default) or spdx (2.3 JSON; builtin generator only)", "cyclonedx")
    .option("--image <reference-or-archive>", `Describe a container image instead of a folder: a reference such as nginx:1.25, or the path of a docker save archive or OCI layout. Needs --generator ${IMAGE_GENERATORS.join(" or ")}, which pulls the image`)
    .option("--resolve", "Maven and Gradle: run the project's own mvn or gradle to resolve the full dependency tree (runs build scripts, downloads from the network; needs --allow-build-tools or a yes at the prompt)")
    .option("--allow-build-tools", "Confirm --resolve without the prompt: you trust this project to run its build")
    .option("--resolve-offline", "With --resolve, run the tool offline (mvn -o, gradle --offline): only cached artifacts resolve")
    .option("--ai", "Also list the AI in the folder: models, datasets, hosted model ids and MCP servers, found by reading files as text")
    .addHelpText("after", "\nWith the builtin generator nothing is installed or run; lockfiles are read as text. --resolve is the exception: it runs mvn or gradle from your PATH (never a wrapper script from the project) with a restricted environment and a ten minute limit, and is refused when ZERO_ENTERPRISE is set. Exit 2 when the folder has no supported lockfile, or the chosen external tool is not installed.")
    .action(async (folder: string, options: GenerateOptions) => {
      try { await runGenerateWith(folder, options, deps); } catch (error) { finishWithError(error, { err: deps.err }, false); }
    });
  sbom.command("scan-models")
    .description("Scan model files (pickle, PyTorch, joblib, numpy) for imports that can run code when loaded")
    .argument("<path>", "A model file, or a folder to search for model files")
    .option("--format <format>", "Output: text, json or sarif", "text")
    .addHelpText("after", "\nFiles are read as bytes: nothing is loaded, imported or executed, and no Python is needed. Content decides the format, not the extension. Safetensors, GGUF, ONNX and TFLite are not pickle formats. 'No dangerous imports found' is not a statement that a file is safe.\nExit codes: 0 nothing dangerous, 1 a file imports something dangerous, 2 usage error.")
    .action((path: string, options: { format?: string }) => {
      try { const code = runScanModels(path, options, deps); if (code) process.exitCode = code; }
      catch (error) { finishWithError(error, { err: deps.err }, options.format === "json"); }
    });
  sbom.command("check")
    .description("Look every component of an SBOM up in the public OSV database and list the advisories")
    .argument("<file>", "CycloneDX SBOM (JSON), for example from `0security sbom generate`")
    .option("--format <format>", "Output: text, json or sarif (SARIF imports with `0security findings import`)", "text")
    .option("-o, --output <file>", "Write the result to a file instead of stdout")
    .option("--outdated", "Also list components with a newer version (looks packages up at https://api.deps.dev; information only, not a vulnerability)")
    .addHelpText("after", "\nEach advisory shows its severity (unknown when the record has none) and the lowest version that fixes it. OSV malicious-package records (ids starting MAL-) are shown as critical.\nThe network use is the lookup at https://api.osv.dev (package URLs go out; nothing else does). --outdated also sends package names to https://api.deps.dev.\nExit codes: 0 no advisories, 1 advisories found (including any malicious package), 2 usage error. Newer versions never change the exit code.")
    .action(async (file: string, options: CheckOptions) => {
      try { const code = await runCheck(file, options, deps); if (code) process.exitCode = code; }
      catch (error) { finishWithError(error, { err: deps.err }, options.format === "json"); }
    });
  registerSbomLicenses(sbom, deps);
}
