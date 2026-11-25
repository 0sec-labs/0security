/**
 * `0 sbom agent-config [path]` checks the files AI coding tools read (rules, MCP and settings) for hidden text, unpinned launchers, secrets and broad permissions.
 * `0 sbom scan-models <path>` lists the code-running imports in pickle-based model files.
 * `0 sbom generate [folder]` writes a CycloneDX (or SPDX) SBOM from the lockfiles in a folder, or runs syft, cdxgen or trivy; `0 sbom check <file>` looks every
 * component up in the public OSV advisory database. Nothing is installed or run: lockfiles, pom.xml and Gradle files are read as text.
 * The one exception is --resolve, which runs the operator's own mvn or gradle after explicit consent.
 */
import { readFileSync, statSync, writeFileSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { createInterface } from "node:readline/promises";
import type { Command } from "commander";
import { agentConfigToSarif, agentConfigToText, AGENT_CONFIG_SEVERITIES, assertEgressAllowed, EXTERNAL_GENERATORS, scanAgentConfig, generateSbom, ResolveFailedError, resolveJvmDependencies, parseDependencyReport, mergeComponents, scanJavaUsage, javaUsageToText, GeneratorNotInstalledError, IMAGE_GENERATORS, parseImageSource, LOCKFILES, modelScanToSarif, runExternalGenerator, scanModelPath, toSpdx, type Component, type ExternalGenerator, type ImageSource, type ModelFileResult } from "@0/engine";
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

export interface GenerateOptions { output?: string; name?: string; ai?: boolean; generator?: string; format?: string; image?: string; resolve?: boolean; allowBuildTools?: boolean; resolveOffline?: boolean; resolveFrom?: string[]; mavenSettings?: string; gradleInitScript?: string }

/** `--resolve-from`: read dependency reports somebody else produced with the build tool. Nothing runs and nothing is downloaded. */
function resolveFromReports(files: string[], deps: SbomDeps): Component[] {
  const lists: Component[][] = [];
  for (const file of files) {
    let text: string;
    try { text = deps.read(resolve(file)); } catch (error) { if (error instanceof UsageError) throw error; throw new UsageError(`Cannot read '${file}'.`); }
    const report = parseDependencyReport(text);
    if (report.tool === "unknown" || !report.components.length) throw new UsageError(`'${file}' is not a Maven dependency:tree text file or a Gradle dependencies report.`);
    deps.err(`read ${report.components.length} components from ${file} (${report.tool === "mvn" ? "Maven" : "Gradle"} report)`);
    lists.push(report.components);
  }
  return mergeComponents(lists);
}

/** An operator-named file that must exist: a settings or init script is never found in the project. */
function requireFile(path: string, flag: string): string {
  const target = resolve(path);
  let ok = false;
  try { ok = statSync(target).isFile(); } catch { /* reported below */ }
  if (!ok) throw new UsageError(`${flag}: '${path}' is not a file.`);
  return target;
}

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
    const result = await resolveJvmDependencies(requireFolder(folder), { ...(deps.env ? { env: deps.env } : {}), ...(options.resolveOffline ? { offline: true } : {}), ...(options.mavenSettings ? { mavenSettings: requireFile(options.mavenSettings, "--maven-settings") } : {}), ...(options.gradleInitScript ? { gradleInitScript: requireFile(options.gradleInitScript, "--gradle-init-script") } : {}) });
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
  if ((options.allowBuildTools || options.resolveOffline || options.mavenSettings || options.gradleInitScript) && !options.resolve) throw new UsageError("--allow-build-tools, --resolve-offline, --maven-settings and --gradle-init-script only apply with --resolve.");
  if (options.resolveFrom?.length && (options.resolve || generator !== "builtin" || options.image !== undefined)) throw new UsageError("--resolve-from reads report files with the builtin generator; it cannot be combined with --resolve, --generator or --image.");
  if (options.resolve && generator !== "builtin") throw new UsageError("--resolve works with the builtin generator only.");
  if (options.resolve && options.image !== undefined) throw new UsageError("--resolve reads a project folder; it cannot be used with --image.");
  if (options.image !== undefined) {
    if (generator === "builtin") throw new UsageError(`--image needs --generator ${IMAGE_GENERATORS.join(" or ")}: the builtin generator reads lockfiles and cannot open an image.`);
    if (!(IMAGE_GENERATORS as readonly string[]).includes(generator)) throw new UsageError(`--image works with --generator ${IMAGE_GENERATORS.join(" or ")}, not ${generator}.`);
    if (folder !== undefined) throw new UsageError("Give a folder or --image, not both.");
  }
  if (generator === "builtin") {
    if (format === "spdx" && options.ai) throw new UsageError("--ai is only available with --format cyclonedx: SPDX 2.3 has no type for models, datasets or MCP servers.");
    const resolved = options.resolve ? (await resolveWithConsent(folder ?? ".", options, deps)).components : options.resolveFrom?.length ? resolveFromReports(options.resolveFrom, deps) : undefined;
    return runGenerate(folder ?? ".", options, deps, resolved);
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

export interface AgentConfigOptions { format?: string; output?: string; failOn?: string; allowHost?: string[] }

/** `0 sbom agent-config [path]`: reads the files AI coding tools take instructions and settings from, as text, and lists what could steer or endanger an agent. No model, no network. */
export function runAgentConfig(path: string, options: AgentConfigOptions, deps: SbomDeps): number {
  const format = options.format ?? "text";
  if (!["text", "json", "sarif"].includes(format)) throw new UsageError("--format must be text, json or sarif.");
  if (options.failOn !== undefined && !(AGENT_CONFIG_SEVERITIES as readonly string[]).includes(options.failOn)) throw new UsageError(`--fail-on must be one of: ${AGENT_CONFIG_SEVERITIES.join(", ")}.`);
  const target = resolve(path);
  let info; try { info = statSync(target); } catch { throw new UsageError(`'${path}' does not exist.`); }
  let report; try { report = scanAgentConfig(target, options.allowHost?.length ? { allowHosts: options.allowHost } : {}); } catch { throw new UsageError(`Could not read '${path}'.`); }
  const base = info.isDirectory() ? report.root : target.split(sep).slice(0, -1).join(sep) || sep;
  const toCwd = (file: string): string => { const rel = relative(process.cwd(), resolve(base, file)); return (rel && !rel.startsWith("..") && !isAbsolute(rel) ? rel : file).split(sep).join("/"); }; // never an absolute local path
  const body = format === "json" ? `${JSON.stringify({ root: path, filesScanned: report.filesScanned, findings: report.findings, skipped: report.skipped, truncated: report.truncated }, null, 2)}\n`
    : format === "sarif" ? `${JSON.stringify(agentConfigToSarif(report.findings, { toolVersion: VERSION, uri: toCwd }), null, 2)}\n` : agentConfigToText(report);
  if (options.output) { deps.write(resolve(options.output), body); deps.err(`Wrote ${options.output}`); } else deps.out(body);
  const names: Record<string, string> = { "too-large": "larger than 1 MB", symlink: "a symbolic link, which is never followed", hardlinked: "a hard link, which is not read", budget: "the scan reached its read limit", "not-a-regular-file": "not a regular file", unreadable: "could not be read", "not-valid-json": "not valid JSON" };
  for (const item of report.skipped.slice(0, 20)) deps.err(`not scanned: ${item.file.replace(/[^\x20-\x7e]/g, "?")} (${names[item.reason]})`);
  if (report.skipped.length > 20) deps.err(`and ${report.skipped.length - 20} more files not scanned.`);
  if (report.truncated) deps.err("The folder was too large to walk completely; some files were not looked at.");
  if (format !== "text" || options.output) deps.err(`${report.findings.length} finding${report.findings.length === 1 ? "" : "s"} in ${report.filesScanned.length} agent configuration file${report.filesScanned.length === 1 ? "" : "s"}.`);
  const limit = options.failOn === undefined ? -1 : AGENT_CONFIG_SEVERITIES.indexOf(options.failOn as typeof AGENT_CONFIG_SEVERITIES[number]);
  return limit >= 0 && report.findings.some(item => AGENT_CONFIG_SEVERITIES.indexOf(item.severity) <= limit) ? 1 : 0;
}

/** `0 sbom java-usage <sbom> [folder]`: where the application's own source imports each Maven component. */
export function runJavaUsage(file: string, folder: string, options: { format?: string }, deps: SbomDeps): void {
  const format = options.format ?? "text";
  if (format !== "text" && format !== "json") throw new UsageError("--format must be text or json.");
  let bom: { components?: unknown };
  try { bom = JSON.parse(deps.read(resolve(file))) as { components?: unknown }; } catch (error) { if (error instanceof UsageError) throw error; throw new UsageError(`'${file}' is not a JSON SBOM.`); }
  const components: Array<{ name: string; version: string; purl: string }> = [];
  for (const entry of Array.isArray(bom.components) ? bom.components : []) {
    const purl = (entry as { purl?: unknown } | null)?.purl;
    const match = typeof purl === "string" ? /^pkg:maven\/([^/@]+)\/([^/@?#]+)@([^?#]+)/.exec(purl) : null;
    if (match) components.push({ name: `${decodeURIComponent(match[1]!)}/${decodeURIComponent(match[2]!)}`, version: decodeURIComponent(match[3]!), purl: purl as string });
  }
  if (!components.length) throw new UsageError(`'${file}' lists no Maven components (pkg:maven/...).`);
  const report = scanJavaUsage(requireFolder(folder), components);
  if (format === "json") deps.out(`${JSON.stringify(report, null, 2)}\n`); else deps.out(javaUsageToText(report));
}

export function registerSbomCommand(program: Command, deps: SbomDeps = defaults): void {
  const sbom = program.command("sbom").description("Generate an SBOM from lockfiles, check one against known advisories, and scan model files and agent configuration");
  sbom.command("generate")
    .description("Write an SBOM (CycloneDX 1.6 or SPDX 2.3) from the lockfiles in a folder (npm, pnpm, yarn, Cargo, Go, Python, Ruby, PHP, .NET, Maven, Gradle, Dart, Elixir)")
    .argument("[folder]", "Folder to read lockfiles from (default: .)")
    .option("-o, --output <file>", "Write the SBOM to a file instead of stdout")
    .option("--name <name>", "Name of the application the SBOM describes (default: the folder's name)")
    .option("--generator <tool>", `Who writes the SBOM: builtin (reads lockfiles; default), ${EXTERNAL_GENERATORS.join(", ")} (run the installed tool; exit 2 if it is missing)`, "builtin")
    .option("--format <format>", "Output format: cyclonedx (1.6, default) or spdx (2.3 JSON; builtin generator only)", "cyclonedx")
    .option("--image <reference-or-archive>", `Describe a container image instead of a folder: a reference such as nginx:1.25, or the path of a docker save archive or OCI layout. Needs --generator ${IMAGE_GENERATORS.join(" or ")}, which pulls the image`)
    .option("--resolve", "Maven and Gradle: run the project's own mvn or gradle to resolve the full dependency tree (runs build scripts, downloads from the network; needs --allow-build-tools or a yes at the prompt)")
    .option("--allow-build-tools", "Confirm --resolve without the prompt: you trust this project to run its build")
    .option("--resolve-offline", "With --resolve, run the tool offline (mvn -o, gradle --offline): only cached artifacts resolve")
    .option("--resolve-from <file>", "Maven and Gradle: read the output of mvn dependency:tree (text) or gradle dependencies that you already ran; repeat for more files. Nothing runs or downloads, so it works offline and under ZERO_ENTERPRISE", (value: string, previous: string[]) => [...previous, value], [] as string[])
    .option("--maven-settings <file>", "With --resolve, pass this settings.xml to mvn (-s): your mirror, proxy and credentials")
    .option("--gradle-init-script <file>", "With --resolve, pass this init script to gradle (-I): your mirror and proxy")
    .option("--ai", "Also list the AI in the folder as an ML-BOM: model files, datasets, Hub references, hosted model ids and MCP servers, found by reading files")
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
  sbom.command("agent-config")
    .description("Check the rules, MCP and settings files AI coding tools read in a repository for hidden text, unpinned launchers, secrets and broad permissions")
    .argument("[path]", "Folder to search, or one file (default: .)")
    .option("--format <format>", "Output: text, json or sarif (SARIF imports with `0security findings import`)", "text")
    .option("-o, --output <file>", "Write the result to a file instead of stdout")
    .option("--fail-on <severity>", "Exit 1 when a finding is at or above this severity: critical, high, medium, low or info")
    .option("--allow-host <host>", "Host a remote MCP server may use; repeat the option or separate hosts with commas. `*.example.com` allows subdomains", (value: string, previous: string[] = []) => [...previous, ...value.split(",").map(host => host.trim()).filter(Boolean)])
    .addHelpText("after", "\nFiles are read as text and size-limited: nothing is executed, there is no model call and nothing goes over the network. Symbolic links and hard links are never followed, and each linked agent file is reported. The wording rule is a heuristic and can miss or misjudge text.\nExit codes: 0 done (and nothing at or above --fail-on), 1 a finding at or above --fail-on, 2 usage error.")
    .action((path: string | undefined, options: AgentConfigOptions) => {
      try { const code = runAgentConfig(path ?? ".", options, deps); if (code) process.exitCode = code; }
      catch (error) { finishWithError(error, { err: deps.err }, options.format === "json"); }
    });
  sbom.command("check")
    .description("Look every component of an SBOM up in the public OSV database and list the advisories")
    .argument("<file>", "CycloneDX SBOM (JSON), for example from `0security sbom generate`")
    .option("--format <format>", "Output: text, json or sarif (SARIF imports with `0security findings import`)", "text")
    .option("-o, --output <file>", "Write the result to a file instead of stdout")
    .option("--outdated", "Also list components with a newer version (looks packages up at https://api.deps.dev; information only, not a vulnerability)")
    .option("--registry", "Also look each npm and PyPI package up on its public registry for invented or planted names (sends package names to registry.npmjs.org, api.npmjs.org and pypi.org)")
    .option("--new-days <days>", "With --registry: a package first published fewer days ago than this is new (default 30)")
    .option("--private <name>", "With --registry: a package name, or @scope/*, to treat as private and skip; repeat the option or separate names with commas", (value: string, previous: string[] = []) => [...previous, ...value.split(",").map(item => item.trim()).filter(Boolean)])
    .option("--fail-on <severity>", "With --registry: exit 1 when a registry finding is at or above this severity: critical, high, medium, low or info")
    .addHelpText("after", "\nEach advisory shows its severity (unknown when the record has none) and the lowest version that fixes it. OSV malicious-package records (ids starting MAL-) are shown as critical.\nThe network use is the lookup at https://api.osv.dev (package URLs go out; nothing else does). --outdated also sends package names to https://api.deps.dev. --registry sends package names to https://registry.npmjs.org, https://api.npmjs.org and https://pypi.org, and is refused under ZERO_ENTERPRISE and ZERO_OFFLINE (the report then says not checked, never ok). Private scopes, workspace members and local or private-registry packages are skipped.\nExit codes: 0 no advisories, 1 advisories found (including any malicious package) or a registry finding at or above --fail-on, 2 usage error. Newer versions never change the exit code.")
    .action(async (file: string, options: CheckOptions) => {
      try { const code = await runCheck(file, options, deps); if (code) process.exitCode = code; }
      catch (error) { finishWithError(error, { err: deps.err }, options.format === "json"); }
    });
  sbom.command("java-usage")
    .description("List which Maven components of an SBOM your Java, Kotlin, Scala or Groovy source imports")
    .argument("<file>", "CycloneDX SBOM (JSON), for example from `0security sbom generate`")
    .argument("[folder]", "Source folder to read (default: .)")
    .option("--format <format>", "Output: text or json", "text")
    .addHelpText("after", "\nSource files are read as text; nothing runs and nothing is sent anywhere. An import shows where a package is named, not that a vulnerable method is called, so this is evidence and not a reachability verdict. A transitive dependency has no import of its own. Imports are matched to a component by its Maven group and artifact (and a small table of well-known libraries), so a library that uses an unrelated package name shows no import.")
    .action((file: string, folder: string | undefined, options: { format?: string }) => {
      try { runJavaUsage(file, folder ?? ".", options, deps); } catch (error) { finishWithError(error, { err: deps.err }, options.format === "json"); }
    });
  registerSbomLicenses(sbom, deps);
}
