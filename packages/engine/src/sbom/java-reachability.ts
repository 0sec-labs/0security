/** Source imports and the SBOM graph are package-level evidence, never proof that vulnerable code executes. */
import { scanJavaUsage, type JavaImport, type JavaUsageReport } from "./java-usage.js";

export interface DependencyReachability {
  purl: string;
  /** Deliberately unknown: imports and dependency edges cannot establish vulnerable-method reachability. */
  vulnerableCode: "unknown";
  evidence: "source-import" | "dependency-path" | "none";
  source: "main" | "test" | "unknown";
  /** Source or graph limits were encountered; retained with advisory exports. */
  incomplete: boolean;
  /** A possible package path, in dependency direction, starting at a source-import candidate. */
  dependencyPath: string[];
  imports: JavaImport[];
  rationale: string;
}
export interface JavaReachabilityReport {
  components: DependencyReachability[];
  usage: JavaUsageReport;
  graphTruncated: boolean;
}
const LIMIT = 20_000;
const EDGE_LIMIT = 100_000;
const MAX_PATH = 100;
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);

/** Decode Maven identities from package URLs; component display names and bom-ref values are not coordinates. */
export function mavenComponents(bom: unknown): Array<{ name: string; version: string; purl: string }> {
  const result = new Map<string, { name: string; version: string; purl: string }>();
  for (const item of object(bom) && Array.isArray(bom.components) ? bom.components : []) {
    if (!object(item) || typeof item.purl !== "string") continue;
    const match = /^pkg:maven\/([^/@]+)\/([^/@?#]+)@([^?#]+)(?:[?#].*)?$/.exec(item.purl);
    if (!match) continue;
    try {
      const group = decodeURIComponent(match[1]!); const artifact = decodeURIComponent(match[2]!); const version = decodeURIComponent(match[3]!);
      if (!group || !artifact || !version || /[\s\x00-\x1f/]/.test(group + artifact + version)) continue;
      result.set(item.purl, { name: `${group}/${artifact}`, version, purl: item.purl });
    } catch { /* Invalid encoded identity: cannot match it safely. */ }
    if (result.size >= LIMIT) break;
  }
  return [...result.values()];
}

/** Never lowers advisory severity, removes a finding, or concludes that an unimported package is safe. */
export function assessJavaDependencyReachability(folder: string, bom: unknown): JavaReachabilityReport {
  const components = mavenComponents(bom);
  const usage = scanJavaUsage(folder, components);
  const entries = object(bom) && Array.isArray(bom.components) ? bom.components : [];
  const known = new Set(components.map(item => item.purl));
  const refs = new Map<string, string>();
  const ambiguous = new Set<string>();
  for (const item of entries) {
    if (!object(item) || typeof item.purl !== "string" || !known.has(item.purl)) continue;
    for (const ref of [item.purl, item["bom-ref"]]) {
      if (typeof ref !== "string") continue;
      if (refs.has(ref) && refs.get(ref) !== item.purl) ambiguous.add(ref);
      else refs.set(ref, item.purl);
    }
  }
  for (const ref of ambiguous) refs.delete(ref);
  const edges = new Map<string, string[]>();
  let count = 0; let graphTruncated = entries.length > LIMIT;
  for (const item of object(bom) && Array.isArray(bom.dependencies) ? bom.dependencies : []) {
    if (!object(item) || typeof item.ref !== "string" || !Array.isArray(item.dependsOn)) continue;
    const from = refs.get(item.ref); if (!from) continue;
    const targets = edges.get(from) ?? [];
    for (const ref of item.dependsOn) {
      if (++count > EDGE_LIMIT) { graphTruncated = true; break; }
      const to = typeof ref === "string" ? refs.get(ref) : undefined;
      if (to) targets.push(to);
    }
    edges.set(from, targets);
    if (count > EDGE_LIMIT) break;
  }
  type Path = { path: string[]; imports: JavaImport[]; source: "main" | "test"; byGroup: boolean };
  // Two breadth-first searches: prefer any main-source path over one seen only in tests.
  const main = new Map<string, Path>(); const test = new Map<string, Path>();
  for (const [target, testOnly] of [[main, false], [test, true]] as const) {
    const queue: string[] = [];
    for (const item of usage.usage) {
      const imports = item.imports.filter(entry => entry.test === testOnly);
      if (!imports.length) continue;
      target.set(item.purl, { path: [item.purl], imports, source: testOnly ? "test" : "main", byGroup: item.verdict === "imported-by-group" });
      queue.push(item.purl);
    }
    for (let index = 0; index < queue.length; index += 1) {
      const from = queue[index]!; const previous = target.get(from)!;
      for (const to of edges.get(from) ?? []) {
        if (target.has(to)) continue;
        if (previous.path.length >= MAX_PATH) { graphTruncated = true; continue; }
        target.set(to, { ...previous, path: [...previous.path, to] }); queue.push(to);
      }
    }
  }
  return {
    usage, graphTruncated,
    components: components.map(item => {
      const found = main.get(item.purl) ?? test.get(item.purl);
      return {
        purl: item.purl, vulnerableCode: "unknown", evidence: found ? found.path.length === 1 ? "source-import" : "dependency-path" : "none",
        source: found?.source ?? "unknown", incomplete: usage.truncated || graphTruncated, dependencyPath: found?.path ?? [], imports: found?.imports ?? [],
        rationale: found
          ? `${found.path.length === 1 ? "Source names a candidate package" : "The SBOM records a dependency path from a source-import candidate"}${found.byGroup ? " (group-only match)" : ""}${found.source === "test" ? "; observed only from test imports" : ""}. Package matching is heuristic; this does not establish a call to vulnerable code or exploitability.`
          : "No source-import or dependency-path evidence found. Reflection, runtime loading, framework wiring and incomplete source or dependency graphs can hide use. Vulnerable-code reachability remains unknown.",
      };
    }),
  };
}

export function dependencyReachabilityToText(items: DependencyReachability[], truncated = false): string {
  const lines = items.map(item => `${item.purl}: ${item.evidence} (${item.source}); vulnerable-code reachability: unknown\n  ${item.rationale}${item.dependencyPath.length > 1 ? `\n  ${item.dependencyPath.join(" -> ")}` : ""}${item.imports.slice(0, 3).map(entry => `\n  ${entry.path}:${entry.line}  ${entry.import}`).join("")}`);
  lines.push("Imports and package dependency paths are evidence for investigation, not vulnerable-method reachability. No advisories are suppressed or downgraded.");
  if (truncated || items.some(item => item.incomplete)) lines.push("Source or dependency evidence is incomplete; scan limits or unreadable files were encountered.");
  return `${lines.join("\n")}\n`;
}
