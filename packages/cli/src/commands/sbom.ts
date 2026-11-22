/**
 * `0 sbom scan-models <path>` lists the code-running imports in pickle-based model files.
 * `0 sbom generate [folder]` writes a CycloneDX (or SPDX) SBOM from the lockfiles in a folder, or runs syft, cdxgen or trivy; `0 sbom check <file>` looks every
 * component up in the public OSV advisory database. Nothing is installed or run: lockfiles are read as text.
 */
import { readFileSync, statSync, writeFileSync } from "node:fs";
import { relative, resolve, sep } from "node:path";
import type { Command } from "commander";
import { checkBomAgainstOsv, EXTERNAL_GENERATORS, generateSbom, GeneratorNotInstalledError, IMAGE_GENERATORS, parseImageSource, LOCKFILES, modelScanToSarif, runExternalGenerator, scanModelPath, toSpdx, type Advisory, type ExternalGenerator, type ImageSource, type ModelFileResult } from "@0/engine";
import { VERSION } from "@0/engine/shared";
import { finishWithError, UsageError } from "./output.js";
import { registerSbomLicenses } from "./sbom-licenses.js";

const MAX_SBOM_BYTES = 50 * 1024 * 1024;

export interface SbomDeps {
  out(text: string): void;
  err(text: string): void;
  write(path: string, text: string): void;
  read(path: string): string;
  fetch?: typeof fetch;
  /** Environment for an external generator (tests point PATH at a fake tool). */
  env?: NodeJS.ProcessEnv;
}
const defaults: SbomDeps = {
  out: text => process.stdout.write(text),
  err: text => process.stderr.write(`${text}\n`),
  write: (path, text) => writeFileSync(path, text, { mode: 0o644 }),
  read(path) {
    const info = statSync(path);
    if (!info.isFile() || info.size > MAX_SBOM_BYTES) throw new UsageError("The SBOM must be a regular file of at most 50 MB.");
    return readFileSync(path, "utf8");
  },
};

export interface GenerateOptions { output?: string; name?: string; ai?: boolean; generator?: string; format?: string; image?: string }

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
  if (options.image !== undefined) {
    if (generator === "builtin") throw new UsageError(`--image needs --generator ${IMAGE_GENERATORS.join(" or ")}: the builtin generator reads lockfiles and cannot open an image.`);
    if (!(IMAGE_GENERATORS as readonly string[]).includes(generator)) throw new UsageError(`--image works with --generator ${IMAGE_GENERATORS.join(" or ")}, not ${generator}.`);
    if (folder !== undefined) throw new UsageError("Give a folder or --image, not both.");
  }
  if (generator === "builtin") {
    if (format === "spdx" && options.ai) throw new UsageError("--ai is only available with --format cyclonedx: SPDX 2.3 has no type for models, datasets or MCP servers.");
    return runGenerate(folder ?? ".", options, deps);
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

export function runGenerate(folder: string, options: GenerateOptions, deps: SbomDeps): void {
  const target = requireFolder(folder);
  const result = generateSbom(target, { toolVersion: VERSION, ...(options.name ? { name: options.name } : {}), ...(options.ai ? { ai: true } : {}) });
  if (!result.bom.components.length && !result.bom.services?.length) {
    const supported = [...new Set(LOCKFILES.map(lock => lock.file))].join(", ");
    throw new UsageError(`No supported lockfile with packages${options.ai ? " and no AI components" : ""} in ${folder}. Supported: ${supported}. For Maven, Gradle or NuGet use --generator syft, cdxgen or trivy; for a container image use --image with --generator syft or trivy.`);
  }
  const text = `${JSON.stringify(options.format === "spdx" ? toSpdx(result.bom) : result.bom, null, 2)}\n`;
  if (options.output) { deps.write(resolve(options.output), text); deps.err(`Wrote ${options.output}`); } else deps.out(text);
  const aiCount = result.bom.components.filter(component => component.type !== "library").length + (result.bom.services?.length ?? 0);
  deps.err(`${result.bom.components.filter(component => component.type === "library").length} components from ${result.lockfiles.length} lockfile${result.lockfiles.length === 1 ? "" : "s"}${result.lockfiles.length ? `: ${result.lockfiles.map(lock => `${lock.path} (${lock.label}, ${lock.components})`).join(", ")}` : ""}${options.ai ? `; ${aiCount} AI components (models, datasets, hosted model ids, MCP servers)` : ""}`);
}

export async function runCheck(file: string, options: { format?: string }, deps: SbomDeps): Promise<number> {
  let bom: unknown;
  try { bom = JSON.parse(deps.read(resolve(file))); } catch (error) { if (error instanceof UsageError) throw error; throw new UsageError(`'${file}' is not a JSON SBOM.`); }
  const result = await checkBomAgainstOsv(bom, deps.fetch ? { fetch: deps.fetch } : {}).catch(error => { throw new Error(`Could not check against OSV: ${error instanceof Error ? error.message : String(error)}`); });
  if (options.format === "json") deps.out(`${JSON.stringify(result, null, 2)}\n`);
  else if (!result.advisories.length) deps.out(`No known advisories for ${result.checked} components (OSV).\n`);
  else {
    const byComponent = new Map<string, Advisory[]>();
    for (const advisory of result.advisories) byComponent.set(advisory.purl, [...(byComponent.get(advisory.purl) ?? []), advisory]);
    const lines = [`${result.advisories.length} advisories affect ${byComponent.size} of ${result.checked} components (OSV):`, ""];
    for (const [purl, list] of byComponent) {
      lines.push(purl);
      for (const item of list) lines.push(`  ${item.id}${item.aliases.length ? ` (${item.aliases.join(", ")})` : ""}${item.severity ? `  ${item.severity}` : ""}${item.fixed.length ? `  fixed in ${item.fixed.join(", ")}` : ""}${item.summary ? `\n    ${item.summary}` : ""}`);
    }
    deps.out(`${lines.join("\n")}\n`);
    if (result.withoutDetails) deps.err(`${result.withoutDetails} advisories are listed by id only (details unavailable or over the limit).`);
  }
  return result.advisories.length ? 1 : 0;
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
    .description("Write an SBOM (CycloneDX 1.5 or SPDX 2.3) from the lockfiles in a folder (npm, pnpm, yarn, Cargo, Go, Python, Ruby, PHP, .NET, Gradle, Dart, Elixir)")
    .argument("[folder]", "Folder to read lockfiles from (default: .)")
    .option("-o, --output <file>", "Write the SBOM to a file instead of stdout")
    .option("--name <name>", "Name of the application the SBOM describes (default: the folder's name)")
    .option("--generator <tool>", `Who writes the SBOM: builtin (reads lockfiles; default), ${EXTERNAL_GENERATORS.join(", ")} (run the installed tool; exit 2 if it is missing)`, "builtin")
    .option("--format <format>", "Output format: cyclonedx (1.5, default) or spdx (2.3 JSON; builtin generator only)", "cyclonedx")
    .option("--image <reference-or-archive>", `Describe a container image instead of a folder: a reference such as nginx:1.25, or the path of a docker save archive or OCI layout. Needs --generator ${IMAGE_GENERATORS.join(" or ")}, which pulls the image`)
    .option("--ai", "Also list the AI in the folder: models, datasets, hosted model ids and MCP servers, found by reading files as text")
    .addHelpText("after", "\nWith the builtin generator nothing is installed or run; lockfiles are read as text. Exit 2 when the folder has no supported lockfile, or the chosen external tool is not installed.")
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
    .argument("<file>", "CycloneDX SBOM (JSON), for example from `0 sbom generate`")
    .option("--format <format>", "Output: text or json", "text")
    .addHelpText("after", "\nThe only network use is the lookup at https://api.osv.dev (package URLs go out; nothing else does).\nExit codes: 0 no advisories, 1 advisories found, 2 usage error.")
    .action(async (file: string, options: { format?: string }) => {
      try { const code = await runCheck(file, options, deps); if (code) process.exitCode = code; }
      catch (error) { finishWithError(error, { err: deps.err }, options.format === "json"); }
    });
  registerSbomLicenses(sbom, deps);
}
