/**
 * Add import evidence to the Maven advisories of `0 sbom check --usage <folder>`. Reads source files as text with the
 * `java-usage` scanner (bounded walk, no symbolic links, size caps); nothing runs and nothing goes over the network.
 *
 * The result is evidence and never a verdict. Nothing here lowers a severity, and no status says "not reachable":
 * a dependency can be used through a transitive library, reflection or a service loader without any import.
 */
import { scanJavaUsage, type JavaSymbolHit, type JavaUsageOptions } from "./java-usage.js";
import type { Advisory } from "./osv.js";

export type AdvisoryUsageStatus = "imported" | "symbol-imported" | "test-only" | "not-imported" | "unknown";
export interface UsageLocation { path: string; line: number; /** The import, or the vulnerable symbol that was found. */ name: string; test: boolean }
export interface AdvisoryUsage {
  status: AdvisoryUsageStatus;
  /** `group` when only the Maven group id matched a package, so the artifact is a guess. Absent for symbol matches. */
  match?: "package" | "group";
  locations: UsageLocation[];
  /** The vulnerable symbols the advisory lists, when it lists any. */
  symbols?: string[];
  note: string;
}
export interface UsageScan { filesScanned: number; truncated: boolean; skipped: number; mavenAdvisories: number }

const MAX_LOCATIONS = 10;
const CONTROL = new RegExp("[\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029\\u202a-\\u202e\\u2066-\\u2069]", "g");
const shownPath = (path: string): string => path.replace(CONTROL, "?").slice(0, 300);

/** A scan that stopped at a limit or could not read some source cannot show that an import is absent. */
/** The sentence that says how much was not read. */
export function scanLimitText(scan: UsageScan): string {
  const what = scan.skipped ? `${scan.skipped} files not scanned` : "the scan stopped early";
  return `${scan.truncated ? "Scan limit reached" : "Scan incomplete"}: ${what}.`;
}
export const scanIsComplete = (scan: UsageScan): boolean => !scan.truncated && scan.skipped === 0;

export const USAGE_NOTES: Record<AdvisoryUsageStatus, string> = {
  imported: "Source code imports a package of this component. This does not show that the vulnerable code runs.",
  "symbol-imported": "Source code names a class or symbol that this advisory lists as vulnerable. This does not show that the vulnerable code runs.",
  "test-only": "Only test source imports this component. This does not show that the vulnerable code is unused.",
  unknown: "The scan did not cover all source, so no statement is made.",
  "not-imported": "No import found in the scanned source: a transitive or reflection use is not ruled out.",
};

/** `group/artifact` and version of a Maven package URL, or undefined for any other ecosystem. */
function mavenName(purl: string): { name: string; version: string } | undefined {
  const match = /^pkg:maven\/([^/@?#]+)\/([^/@?#]+)(?:@([^?#]*))?/.exec(purl);
  if (!match) return undefined;
  try { return { name: `${decodeURIComponent(match[1]!)}/${decodeURIComponent(match[2]!)}`, version: decodeURIComponent(match[3] ?? "") }; } catch { return undefined; }
}

export function attachJavaUsage(advisories: Advisory[], folder: string, limits?: JavaUsageOptions["limits"]): { advisories: Advisory[]; scan: UsageScan } {
  const components = new Map<string, { name: string; version: string; purl: string }>();
  const symbols = new Set<string>();
  for (const advisory of advisories) {
    const parsed = mavenName(advisory.purl);
    if (!parsed || advisory.malicious) continue;
    components.set(advisory.purl, { ...parsed, purl: advisory.purl });
    for (const symbol of advisory.vulnerableSymbols ?? []) symbols.add(symbol);
  }
  if (!components.size) return { advisories, scan: { filesScanned: 0, truncated: false, skipped: 0, mavenAdvisories: 0 } };
  const report = scanJavaUsage(folder, [...components.values()], { symbols: [...symbols], ...(limits ? { limits } : {}) });
  const byPurl = new Map(report.usage.map(item => [item.purl, item]));
  const hitsOf = (symbol: string): JavaSymbolHit[] => (report.symbolHits ?? []).filter(hit => hit.symbol === symbol);
  const scan: UsageScan = { filesScanned: report.filesScanned, truncated: report.truncated, skipped: report.skipped, mavenAdvisories: advisories.filter(advisory => byPurl.has(advisory.purl) && !advisory.malicious).length };
  const unknownNote = (advisory: Advisory): string => `${advisory.vulnerableSymbolsTruncated ? "This advisory lists more vulnerable symbols than were searched. " : ""}${scanIsComplete(scan) ? "" : `${scanLimitText(scan)} `}No import was found in the part that was scanned, so a missing import proves nothing.`;
  const enriched = advisories.map((advisory): Advisory => {
    const item = byPurl.get(advisory.purl);
    if (!item || advisory.malicious) return advisory;
    const wanted = advisory.vulnerableSymbols ?? [];
    const symbolHits = wanted.flatMap(hitsOf).filter(hit => !hit.test);
    const testSymbolHits = wanted.flatMap(hitsOf).filter(hit => hit.test);
    const nonTest = item.imports.filter(entry => !entry.test);
    const incomplete = !scanIsComplete(scan) || advisory.vulnerableSymbolsTruncated === true;
    const base = (status: AdvisoryUsageStatus, locations: UsageLocation[], match?: "package" | "group"): AdvisoryUsage => ({
      status, ...(match ? { match } : {}), locations: locations.slice(0, MAX_LOCATIONS), ...(wanted.length ? { symbols: wanted } : {}), note: status === "unknown" ? unknownNote(advisory) : status === "test-only" && incomplete ? `${USAGE_NOTES[status]} ${scanLimitText(scan)}` : USAGE_NOTES[status],
    });
    const place = (entry: { path: string; line: number; test: boolean }, name: string): UsageLocation => ({ path: shownPath(entry.path), line: entry.line, name, test: entry.test });
    let usage: AdvisoryUsage;
    if (symbolHits.length) usage = base("symbol-imported", symbolHits.map(hit => place(hit, hit.symbol)));
    else if (nonTest.length) usage = base("imported", nonTest.map(entry => place(entry, entry.import)), item.verdict === "imported-by-group" ? "group" : "package");
    else if (item.imports.length || testSymbolHits.length) usage = base("test-only", [...item.imports.map(entry => place(entry, entry.import)), ...testSymbolHits.map(hit => place(hit, hit.symbol))], item.imports.length ? (item.verdict === "imported-by-group" ? "group" : "package") : undefined);
    else usage = base(incomplete ? "unknown" : "not-imported", []);
    return { ...advisory, usage };
  });
  return { advisories: enriched, scan };
}
