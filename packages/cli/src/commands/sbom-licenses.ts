/**
 * `0 sbom licenses [sbom-file-or-folder]` checks the licenses a CycloneDX SBOM states against an allow/deny policy.
 * A folder is turned into an SBOM with the builtin lockfile reader first. Information from lockfiles, not legal advice.
 */
import { readFileSync, statSync } from "node:fs";
import { basename, join, relative, resolve, sep } from "node:path";
import type { Command } from "commander";
import { parseDocument } from "yaml";
import { assertEgressAllowed, checkBomLicenses, classifyLicense, generateSbom, licensesToSarif, LOCKFILES, mergePolicies, packageUrl, policyFromDocument, PRESET_NAMES, validatePolicy, type ComponentVerdict, type LicensePolicy, type LicenseReport, type PresetName, type UnknownMode } from "@0/engine";
import { VERSION } from "@0/engine/shared";
import type { SbomDeps } from "./sbom.js";
import { finishWithError, UsageError } from "./output.js";

export interface LicensesOptions { policy?: string; allow?: string; deny?: string; preset?: string; unknown?: string; format?: string; excludeDev?: boolean; resolve?: boolean; resolveLimit?: string }

const MAX_POLICY_BYTES = 256 * 1024;
const SHOWN_PER_GROUP = 100;
const csv = (value: string | undefined): string[] => (value ?? "").split(",").map(item => item.trim()).filter(Boolean);

/** Read a policy file as JSON, falling back to YAML. */
export function readPolicyFile(path: string): ReturnType<typeof policyFromDocument> {
  const target = resolve(path);
  let text: string;
  try {
    const info = statSync(target);
    if (!info.isFile() || info.size > MAX_POLICY_BYTES) throw new UsageError("");
    text = readFileSync(target, "utf8");
  } catch { throw new UsageError(`Cannot read the policy file '${path}' (it must be a regular file of at most 256 KB).`); }
  let raw: unknown;
  try { raw = JSON.parse(text); }
  catch {
    const document = parseDocument(text, { schema: "core", merge: false });
    if (document.errors.length) throw new UsageError(`'${path}' is neither JSON nor YAML: ${document.errors[0]!.message.split("\n")[0]}`);
    raw = document.toJS();
  }
  try { return policyFromDocument(raw); } catch (error) { throw new UsageError(`${path}: ${error instanceof Error ? error.message : String(error)}`); }
}

/** Combine --preset, --policy, --allow, --deny and --unknown into one policy. A preset in the file applies before the file's own lists. */
export function buildPolicy(options: LicensesOptions): LicensePolicy {
  if (options.preset !== undefined && !(PRESET_NAMES as readonly string[]).includes(options.preset)) throw new UsageError(`Unknown preset '${options.preset}'. Use ${PRESET_NAMES.join(" or ")}.`);
  if (options.unknown !== undefined && !["warn", "fail", "allow"].includes(options.unknown)) throw new UsageError("--unknown must be warn, fail or allow.");
  const file = options.policy ? readPolicyFile(options.policy) : undefined;
  const flags = { allow: csv(options.allow), deny: csv(options.deny) };
  if (!options.preset && !file && !flags.allow.length && !flags.deny.length) throw new UsageError("Give a policy: --preset permissive|no-copyleft, --policy <file>, --allow <ids> or --deny <ids>.");
  const policy = mergePolicies([
    ...(options.preset ? [{ preset: options.preset as PresetName }] : []),
    ...(file ? [file] : []),
    { ...flags, ...(options.unknown ? { unknown: options.unknown as UnknownMode } : {}) },
  ]);
  if (!policy.allow.length && !policy.deny.length && !policy.allowByPackage.length) throw new UsageError("The policy has no allow or deny list, so it would accept every license.");
  const problems = validatePolicy(policy);
  if (problems.length) throw new UsageError(`Invalid policy:\n  ${problems.join("\n  ")}`);
  return policy;
}

const ECOSYSTEM_OF_PURL: Record<string, string[]> = {
  npm: ["npm", "pnpm", "yarn"], cargo: ["Cargo"], golang: ["Go"], pypi: ["Poetry", "Pipenv", "pip (pinned)"], gem: ["Bundler"],
  composer: ["Composer"], nuget: ["NuGet"], maven: ["Gradle"], pub: ["Dart/Flutter"], hex: ["Mix"],
};

interface Source { bom: unknown; /** The file a violation points at, per component. */ locate: (component: ComponentVerdict) => string; label: string; lockfiles?: number }

function displayPath(path: string): string {
  const rel = relative(process.cwd(), path);
  return (rel && !rel.startsWith("..") ? rel : path).split(sep).join("/");
}

function loadSource(input: string, deps: SbomDeps): Source {
  const target = resolve(input);
  let info: ReturnType<typeof statSync>;
  try { info = statSync(target); } catch { throw new UsageError(`'${input}' does not exist.`); }
  if (!info.isDirectory()) {
    let bom: { bomFormat?: unknown; components?: unknown };
    try { bom = JSON.parse(deps.read(target)); } catch (error) { if (error instanceof UsageError) throw error; throw new UsageError(`'${input}' is not a JSON SBOM.`); }
    if (!bom || typeof bom !== "object" || bom.bomFormat !== "CycloneDX") throw new UsageError(`'${input}' is not a CycloneDX SBOM (JSON with "bomFormat": "CycloneDX"). Generate one with '0security sbom generate'.`);
    return { bom, locate: () => displayPath(target), label: displayPath(target) };
  }
  const result = generateSbom(target, { toolVersion: VERSION });
  if (!result.bom.components.length) {
    const supported = [...new Set(LOCKFILES.map(lock => lock.file))].join(", ");
    throw new UsageError(`No supported lockfile with packages in ${input}. Supported: ${supported}.`);
  }
  // Point each component at the lockfile that lists it: the first, in path order, whose own parse contains its package URL.
  const purls = new Map<string, Set<string>>();
  for (const lock of result.lockfiles) {
    const reader = LOCKFILES.find(candidate => candidate.file === basename(lock.path));
    if (!reader) continue;
    try { purls.set(lock.path, new Set(reader.parse(readFileSync(join(target, lock.path), "utf8")).map(packageUrl))); } catch { /* the SBOM already has what it could read */ }
  }
  const locate = (component: ComponentVerdict): string => {
    const owner = result.lockfiles.find(lock => purls.get(lock.path)?.has(component.purl));
    const fallback = result.lockfiles.find(lock => (ECOSYSTEM_OF_PURL[/^pkg:([^/]+)\//.exec(component.purl)?.[1] ?? ""] ?? []).includes(lock.label));
    return displayPath(join(target, (owner ?? fallback ?? result.lockfiles[0]!).path));
  };
  return { bom: result.bom, locate, label: `${input} (${result.lockfiles.length} lockfile${result.lockfiles.length === 1 ? "" : "s"})`, lockfiles: result.lockfiles.length };
}


// --- --resolve: look licenses up on deps.dev ----------------------------------------------------------------------

const DEPS_DEV_URL = "https://api.deps.dev/v3/systems";
const DEPS_DEV_SYSTEM: Record<string, string> = { npm: "npm", cargo: "cargo", golang: "go", pypi: "pypi", gem: "rubygems", nuget: "nuget", maven: "maven" };
const DEFAULT_RESOLVE_LIMIT = 2000;
const RESOLVE_CONCURRENCY = 8;
const RESOLVE_TIMEOUT_MS = 10_000;

/** The deps.dev system, package name and version for a package URL, or undefined for an ecosystem deps.dev does not cover. */
export function depsDevKey(purl: string): { system: string; name: string; version: string } | undefined {
  const match = /^pkg:([a-z]+)\/([^?#]+)/.exec(purl);
  if (!match) return undefined;
  const system = DEPS_DEV_SYSTEM[match[1]!];
  const at = match[2]!.lastIndexOf("@");
  if (!system || at < 0) return undefined;
  try {
    const parts = match[2]!.slice(0, at).split("/").map(decodeURIComponent);
    const version = decodeURIComponent(match[2]!.slice(at + 1));
    return { system, name: system === "maven" ? parts.join(":") : parts.join("/"), version };
  } catch { return undefined; }
}

interface ResolveStats { asked: number; found: number; notFound: number; failed: number; unsupported: number; overLimit: number }

/** Fill in the license of components that state none, from deps.dev. Mutates the components it resolves; returns their package URLs. */
async function resolveLicenses(bom: { components?: unknown }, limit: number, fetchFn: typeof fetch): Promise<{ resolved: Set<string>; stats: ResolveStats }> {
  const stats: ResolveStats = { asked: 0, found: 0, notFound: 0, failed: 0, unsupported: 0, overLimit: 0 };
  const todo: Array<{ component: { licenses?: unknown; purl?: unknown }; key: NonNullable<ReturnType<typeof depsDevKey>> }> = [];
  const walk = (list: unknown): void => {
    if (!Array.isArray(list)) return;
    for (const item of list as Array<{ licenses?: unknown; purl?: unknown; components?: unknown }>) {
      if (item && typeof item === "object") {
        if (!(Array.isArray(item.licenses) && item.licenses.length) && typeof item.purl === "string") {
          const key = depsDevKey(item.purl);
          if (!key) stats.unsupported += 1; else todo.push({ component: item, key });
        }
        walk(item.components);
      }
    }
  };
  walk(bom.components);
  const batch = todo.slice(0, limit);
  stats.overLimit = todo.length - batch.length;
  const resolved = new Set<string>();
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < batch.length) {
      const { component, key } = batch[next++]!;
      stats.asked += 1;
      try {
        const response = await fetchFn(`${DEPS_DEV_URL}/${key.system}/packages/${encodeURIComponent(key.name)}/versions/${encodeURIComponent(key.version)}`, { signal: AbortSignal.timeout(RESOLVE_TIMEOUT_MS) });
        if (response.status === 404) { stats.notFound += 1; continue; }
        if (!response.ok) { stats.failed += 1; continue; }
        const body = await response.json() as { licenses?: unknown };
        const licenses = Array.isArray(body.licenses) ? body.licenses.filter((value): value is string => typeof value === "string" && !!value.trim()) : [];
        if (!licenses.length) { stats.notFound += 1; continue; }
        component.licenses = licenses.map(value => classifyLicense(value.trim()));
        resolved.add(String(component.purl));
        stats.found += 1;
      } catch { stats.failed += 1; }
    }
  };
  await Promise.all(Array.from({ length: Math.min(RESOLVE_CONCURRENCY, batch.length) }, worker));
  return { resolved, stats };
}

function describePolicy(policy: LicensePolicy): string[] {
  return [
    policy.allow.length ? `allow: ${policy.allow.join(", ")}` : "allow: (any license not denied)",
    ...(policy.deny.length ? [`deny: ${policy.deny.join(", ")}`] : []),
    `unknown: ${policy.unknown}`,
    ...(policy.allowByPackage.length ? [`exceptions: ${policy.allowByPackage.length}`] : []),
  ];
}

function group(lines: string[], title: string, items: ComponentVerdict[], detail: (item: ComponentVerdict) => string): void {
  if (!items.length) return;
  lines.push("", `${title} (${items.length})`);
  for (const item of items.slice(0, SHOWN_PER_GROUP)) lines.push(`  ${item.name}@${item.version}  ${detail(item)}${item.dev ? "  [dev]" : ""}${item.resolved ? "  [deps.dev]" : ""}`);
  if (items.length > SHOWN_PER_GROUP) lines.push(`  ... and ${items.length - SHOWN_PER_GROUP} more (use --format json for the full list)`);
}

export function renderText(report: LicenseReport, label: string): string {
  const { summary, components, policy } = report;
  const lines = [`License check of ${label}`, ...describePolicy(policy).map(line => `  ${line}`)];
  const of = (verdict: ComponentVerdict["verdict"]) => components.filter(component => component.verdict === verdict);
  group(lines, "Denied", of("denied"), item => `${item.licenses.join(", ")}  (denied: ${item.causes.join(", ")})`);
  group(lines, "Not allowed", of("not-allowed"), item => `${item.licenses.join(", ")}  (not allowed: ${item.causes.join(", ")})`);
  if (policy.unknown !== "allow") group(lines, `Unknown${policy.unknown === "fail" ? " (fails the check)" : ""}`, of("unknown"), item => item.reason ?? "no license stated");
  group(lines, "Allowed by exception", components.filter(component => component.exception?.waived), item => `${item.licenses.join(", ") || "no license stated"}  (${item.exception!.reason})`);
  lines.push("", `${summary.total} components: ${summary.denied} denied, ${summary.notAllowed} not allowed, ${summary.unknown} unknown, ${summary.allowed} allowed${summary.excepted ? ` (${summary.excepted} by exception)` : ""}.`);
  if (summary.total && summary.unknown * 2 > summary.total) lines.push(`Most components (${summary.unknown} of ${summary.total}) have no license data: lockfiles other than npm and Composer do not state licenses. Treat the result as incomplete, or add --resolve to look them up.`);
  lines.push(summary.violations ? `${summary.violations} violation${summary.violations === 1 ? "" : "s"}.` : "No violations.", "Information from lockfiles and registries, not legal advice.");
  return `${lines.join("\n")}\n`;
}

/** Returns the exit code: 1 when any component violates the policy. */
export async function runLicenses(input: string | undefined, options: LicensesOptions, deps: SbomDeps): Promise<number> {
  if (options.format && !["text", "json", "sarif"].includes(options.format)) throw new UsageError("--format must be text, json or sarif.");
  const policy = buildPolicy(options);
  const source = loadSource(input ?? ".", deps);
  let limit = DEFAULT_RESOLVE_LIMIT;
  if (options.resolveLimit !== undefined) {
    limit = Number(options.resolveLimit);
    if (!Number.isInteger(limit) || limit < 1 || limit > 20_000) throw new UsageError("--resolve-limit must be a whole number from 1 to 20000.");
  }
  if (options.resolve && !deps.fetch) assertEgressAllowed("api.deps.dev (license lookup)");
  const lookup = options.resolve ? await resolveLicenses(source.bom as { components?: unknown }, limit, deps.fetch ?? fetch) : undefined;
  const report = checkBomLicenses(source.bom, policy, options.excludeDev ? { excludeDev: true } : {});
  if (lookup) for (const component of report.components) if (lookup.resolved.has(component.purl)) component.resolved = true;
  if (options.format === "json") {
    deps.out(`${JSON.stringify({ source: source.label, policy: { allow: policy.allow, deny: policy.deny, unknown: policy.unknown, allowByPackage: policy.allowByPackage }, summary: report.summary, components: report.components }, null, 2)}\n`);
  } else if (options.format === "sarif") {
    deps.out(`${JSON.stringify(licensesToSarif(report, { toolVersion: VERSION, uri: source.locate }), null, 2)}\n`);
  } else deps.out(renderText(report, source.label));
  if (lookup) {
    const { stats } = lookup;
    deps.err(`Looked up ${stats.asked} components on deps.dev: ${stats.found} with license data, ${stats.notFound} not found or without one, ${stats.failed} failed.${stats.unsupported ? ` ${stats.unsupported} are in ecosystems deps.dev does not cover.` : ""}${stats.overLimit ? ` ${stats.overLimit} were not looked up because of --resolve-limit ${limit}.` : ""}`);
  }
  if (options.format && options.format !== "text") {
    if (report.summary.unknown) deps.err(`${report.summary.unknown} of ${report.summary.total} components have no usable license data${options.resolve ? "" : " (lockfiles other than npm and Composer state none; --resolve looks them up)"}.`);
    deps.err("Information from lockfiles and registries, not legal advice.");
  }
  return report.summary.violations ? 1 : 0;
}

export function registerSbomLicenses(sbom: Command, deps: SbomDeps): void {
  sbom.command("licenses")
    .description("Check the licenses in an SBOM, or in a folder's lockfiles, against an allow or deny policy")
    .argument("[sbom-file-or-folder]", "CycloneDX SBOM (JSON), or a folder to read lockfiles from", ".")
    .option("--preset <name>", `Start from a preset: ${PRESET_NAMES.join(" or ")}`)
    .option("--policy <file>", "Policy file (JSON or YAML): allow, deny, allowByPackage (with a reason), unknown")
    .option("--allow <ids>", "Comma list of SPDX ids to allow; any license not listed is not allowed")
    .option("--deny <ids>", "Comma list of SPDX ids to deny; a trailing * matches a family, for example GPL-*")
    .option("--unknown <mode>", "What a component with no usable license data does: warn (default), fail or allow")
    .option("--resolve", "Look up the license of components that state none on deps.dev (network; sends package names and versions)")
    .option("--resolve-limit <n>", `With --resolve, look up at most this many components (default ${DEFAULT_RESOLVE_LIMIT})`)
    .option("--exclude-dev", "Skip components that are development-only")
    .option("--format <format>", "Output: text, json or sarif", "text")
    .addHelpText("after", "\nIn an SPDX expression OR is your choice and AND needs every part. A license name in free text, an id that is not on the SPDX list and a component with no license are unknown; nothing is guessed. Information from lockfiles and registries, not legal advice.\nExit codes: 0 no violation, 1 a denied or not-allowed license (or an unknown one with --unknown fail), 2 usage error.")
    .action(async (input: string | undefined, options: LicensesOptions) => {
      try { const code = await runLicenses(input, options, deps); if (code) process.exitCode = code; }
      catch (error) { finishWithError(error, { err: deps.err }, options.format === "json"); }
    });
}
