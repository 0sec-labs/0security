/** `0 sbom check`: look the components of an SBOM up in OSV, and optionally in deps.dev for newer versions. */
import { statSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { assessJavaDependencyReachability, advisoriesToSarif, advisoriesToText, attachJavaUsage, scanIsComplete, scanLimitText, checkBomAgainstOsv, checkOutdated, checkSlopsquat, outdatedToText, slopsquatFails, slopsquatSarifParts, slopsquatToText, usageSummary } from "@0/engine";
import { VERSION } from "@0/engine/shared";
import { UsageError } from "./output.js";
import { resolutionLine } from "./sbom-resolution.js";
import type { SbomDeps } from "./sbom.js";

export interface CheckOptions { format?: string; output?: string; outdated?: boolean; registry?: boolean; newDays?: string; private?: string[]; failOn?: string; source?: string; usage?: string; ignoreNotImported?: boolean }

/** The file each component came from: its lockfile when the SBOM records one (`0:source`, cdxgen's `SrcFile`, or evidence), otherwise the SBOM itself. */
function componentLocator(bom: unknown, sbomPath: string): (purl: string) => string {
  const root = process.cwd();
  const sbomDir = dirname(sbomPath);
  const shown = (absolute: string): string => { const rel = relative(root, absolute); return (rel && !rel.startsWith("..") && !isAbsolute(rel) ? rel : absolute).split(sep).join("/"); };
  const isFile = (path: string): boolean => { try { return statSync(path).isFile(); } catch { return false; } };
  const sources = new Map<string, string>();
  const components = bom && typeof bom === "object" && Array.isArray((bom as { components?: unknown }).components) ? (bom as { components: unknown[] }).components : [];
  for (const entry of components) {
    if (!entry || typeof entry !== "object") continue;
    const component = entry as { purl?: unknown; properties?: unknown; evidence?: { occurrences?: unknown } };
    if (typeof component.purl !== "string") continue;
    const candidates: string[] = [];
    for (const property of Array.isArray(component.properties) ? component.properties : []) {
      const item = property as { name?: unknown; value?: unknown } | null;
      if (item && (item.name === "0:source" || item.name === "SrcFile") && typeof item.value === "string") candidates.push(item.value);
    }
    for (const occurrence of Array.isArray(component.evidence?.occurrences) ? component.evidence.occurrences : []) {
      const location = (occurrence as { location?: unknown } | null)?.location;
      if (typeof location === "string") candidates.push(location);
    }
    for (const candidate of candidates) {
      const found = [resolve(sbomDir, candidate), resolve(root, candidate)].find(isFile);
      if (found) { sources.set(component.purl, found); break; }
    }
  }
  return purl => shown(sources.get(purl) ?? sbomPath);
}

export async function runCheckReport(file: string, options: CheckOptions, deps: SbomDeps): Promise<number> {
  const format = options.format ?? "text";
  if (!["text", "json", "sarif"].includes(format)) throw new UsageError("--format must be text, json or sarif.");
  let bom: unknown;
  try { bom = JSON.parse(deps.read(resolve(file))); } catch (error) { if (error instanceof UsageError) throw error; throw new UsageError(`'${file}' is not a JSON SBOM.`); }
  if (options.ignoreNotImported && options.usage === undefined) throw new UsageError("--ignore-not-imported needs --usage <folder>.");
  let usageFolder: string | undefined;
  if (options.usage !== undefined) {
    usageFolder = resolve(options.usage);
    let isFolder = false;
    try { isFolder = statSync(usageFolder).isDirectory(); } catch { /* reported below */ }
    if (!isFolder) throw new UsageError(`--usage: '${options.usage}' is not a folder.`);
  }
  let reachability;
  if (options.source !== undefined) {
    const folder = resolve(options.source);
    let valid = false;
    try { valid = statSync(folder).isDirectory(); } catch { /* report usage error below */ }
    if (!valid) throw new UsageError(`--source: '${options.source}' is not a folder.`);
    reachability = assessJavaDependencyReachability(folder, bom);
  }
  const fetchOption = deps.fetch ? { fetch: deps.fetch } : {};
  const checked = await checkBomAgainstOsv(bom, fetchOption).catch(error => { throw new Error(`Could not check against OSV: ${error instanceof Error ? error.message : String(error)}`); });
  if (reachability) {
    const byPurl = new Map(reachability.components.map(item => [item.purl, item]));
    for (const advisory of checked.advisories) {
      const evidence = byPurl.get(advisory.purl);
      if (evidence) advisory.reachability = evidence;
    }
  }
  const usage = usageFolder ? attachJavaUsage(checked.advisories, usageFolder) : undefined;
  const result = usage ? { ...checked, advisories: usage.advisories } : checked;
  const failOn = options.failOn?.toLowerCase();
  if (failOn !== undefined && !["critical", "high", "medium", "low", "info"].includes(failOn)) throw new UsageError("--fail-on must be one of critical, high, medium, low or info.");
  const newDays = options.newDays === undefined ? undefined : Number(options.newDays);
  if (newDays !== undefined && (!Number.isInteger(newDays) || newDays < 1 || newDays > 3650)) throw new UsageError("--new-days must be a whole number of days from 1 to 3650.");
  if ((options.newDays !== undefined || options.private?.length || failOn) && !options.registry) throw new UsageError("--new-days, --private and --fail-on apply to --registry. Add --registry.");
  const registry = options.registry ? await checkSlopsquat(bom, { ...fetchOption, ...(newDays !== undefined ? { newDays } : {}), privatePatterns: options.private ?? [] }) : undefined;
  const outdated = options.outdated ? await checkOutdated(bom, fetchOption) : undefined;
  let text: string;
  if (format === "json") text = `${JSON.stringify({ ...result, ...(reachability ? { reachability } : {}), ...(outdated ? { outdated } : {}), ...(registry ? { registry } : {}), ...(usage ? { usageScan: { ...usage.scan, ignoreNotImported: !!options.ignoreNotImported } } : {}) }, null, 2)}\n`;
  else if (format === "sarif") {
    const locate = componentLocator(bom, resolve(file));
    const sarif = advisoriesToSarif(result.advisories, { toolVersion: VERSION, locate }) as { runs: Array<{ tool: { driver: { rules: object[] } }; results: object[] }> };
    if (registry) { const parts = slopsquatSarifParts(registry.findings, locate); sarif.runs[0]!.tool.driver.rules.push(...parts.rules); sarif.runs[0]!.results.push(...parts.results); }
    text = `${JSON.stringify(sarif, null, 2)}\n`;
  }
  else text = advisoriesToText(result.advisories, result.checked) + (outdated ? `\n${outdatedToText(outdated)}` : "") + (registry ? `\n${slopsquatToText(registry)}` : "") + (usage ? `\n${usageSummary(result.advisories, usage.scan, !!options.ignoreNotImported)}\n` : "") + `\n${resolutionLine(result.checked, result.unresolved)}\n`;
  if (options.output) {
    deps.write(resolve(options.output), text);
    deps.err(`Wrote ${options.output}`);
    if (format !== "text") deps.err(`${result.advisories.length} advisories affect ${new Set(result.advisories.map(item => item.purl)).size} of ${result.checked} components`);
    if (format !== "text" && outdated) deps.err(outdatedToText(outdated).trimEnd());
    if (format !== "text" && registry) deps.err(slopsquatToText(registry).trimEnd());
  } else deps.out(text);
  if (reachability && (reachability.graphTruncated || reachability.usage.truncated)) deps.err("Source or dependency evidence is incomplete; vulnerable-code reachability remains unknown.");
  if (registry?.notChecked) deps.err(`Registry check not checked: ${registry.notChecked}.`);
  if (usage && options.ignoreNotImported && !scanIsComplete(usage.scan)) deps.err(`${scanLimitText(usage.scan)} Advisories with no import found are marked unknown, and --ignore-not-imported never ignores unknown.`);
  if (usage && format !== "text") deps.err(usageSummary(result.advisories, usage.scan, !!options.ignoreNotImported));
  if (format !== "text") deps.err(resolutionLine(result.checked, result.unresolved));
  if (format === "text" && result.withoutDetails) deps.err(`${result.withoutDetails} advisories are listed by id only (details unavailable or over the limit).`);
  if (result.advisories.some(item => item.malicious)) deps.err("A malicious package is in this SBOM. Remove it and treat machines that installed it as compromised.");
  // A malicious package never counts as not imported: it does not need an import to harm a build.
  const counted = result.advisories.filter(item => !(options.ignoreNotImported && !item.malicious && item.usage?.status === "not-imported")).length;
  return counted || (registry && slopsquatFails(registry.findings, failOn)) ? 1 : 0;
}
