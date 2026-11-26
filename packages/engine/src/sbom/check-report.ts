/** How `0 sbom check` writes its answer: plain text, and SARIF that `0 findings import` accepts. */
import { dependencyReachabilityToText } from "./java-reachability.js";
import { createHash } from "node:crypto";
import { bandOfScore } from "./advisory-facts.js";
import type { Advisory, AdvisorySeverity } from "./osv.js";

const ORDER: Record<AdvisorySeverity, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
const SCORE: Record<AdvisorySeverity, number | undefined> = { critical: 9.5, high: 8, medium: 5, low: 2, unknown: undefined };
const LEVEL: Record<AdvisorySeverity, "error" | "warning" | "note"> = { critical: "error", high: "error", medium: "warning", low: "note", unknown: "warning" };

/** `lodash 4.17.20` from `pkg:npm/lodash@4.17.20`. */
export function componentLabel(purl: string): string {
  const match = /^pkg:[^/]+\/(.+?)(?:@([^@?#]+))?(?:[?#].*)?$/.exec(purl);
  if (!match) return purl;
  let name = match[1]!; let version = match[2];
  try { name = decodeURIComponent(name); if (version) version = decodeURIComponent(version); } catch { /* keep the raw text */ }
  return version ? `${name} ${version}` : name;
}

/** The one-sentence fix advice for an advisory. */
export function fixAdvice(advisory: Advisory): string {
  if (advisory.malicious) return "Remove this package and treat any machine or pipeline that installed it as compromised.";
  return advisory.fixedVersion ? `Fixed in ${advisory.fixedVersion}.` : "No fixed version known.";
}

export function sortAdvisories(advisories: Advisory[]): Advisory[] {
  return [...advisories].sort((a, b) => ORDER[a.severity] - ORDER[b.severity] || (a.purl < b.purl ? -1 : a.purl > b.purl ? 1 : 0) || (a.id < b.id ? -1 : 1));
}

const severityText = (advisory: Advisory): string => `${advisory.severity}${advisory.cvss !== undefined ? ` (CVSS ${advisory.cvss.toFixed(1)})` : ""}`;

export function advisoriesToText(advisories: Advisory[], checked: number): string {
  if (!advisories.length) return `No known advisories for ${checked} components (OSV).\n`;
  const byComponent = new Map<string, Advisory[]>();
  for (const advisory of sortAdvisories(advisories)) byComponent.set(advisory.purl, [...(byComponent.get(advisory.purl) ?? []), advisory]);
  const lines: string[] = [];
  const malicious = advisories.filter(advisory => advisory.malicious);
  if (malicious.length) {
    lines.push(`!!! ${new Set(malicious.map(advisory => advisory.purl)).size} MALICIOUS PACKAGE${new Set(malicious.map(advisory => advisory.purl)).size === 1 ? "" : "S"} FOUND. Remove ${new Set(malicious.map(advisory => advisory.purl)).size === 1 ? "it" : "them"} now. !!!`, "");
  }
  lines.push(`${advisories.length} advisories affect ${byComponent.size} of ${checked} components (OSV):`, "");
  for (const [purl, list] of byComponent) {
    lines.push(componentLabel(purl) === purl ? purl : `${componentLabel(purl)}  ${purl}`);
    for (const item of list) {
      const alias = item.aliases.length ? ` (${item.aliases.join(", ")})` : "";
      if (item.malicious) lines.push(`  MALICIOUS PACKAGE  ${item.id}${alias}  critical`);
      else lines.push(`  ${item.id}${alias}  ${severityText(item)}  ${fixAdvice(item)}`);
      if (item.reachability) lines.push(`    ${dependencyReachabilityToText([item.reachability]).trimEnd().replace(/\n/g, "\n    ")}`);
      if (item.summary) lines.push(`    ${item.summary}`);
      if (item.malicious) lines.push(`    ${fixAdvice(item)}`);
    }
  }
  return `${lines.join("\n")}\n`;
}

const sha = (value: string): string => createHash("sha256").update(value).digest("hex").slice(0, 32);

/**
 * SARIF 2.1.0 with one result per vulnerable component and advisory. `locate` gives the file a component came from (its
 * lockfile, or the SBOM). The fingerprint depends only on the package URL and the advisory id, so an import is stable.
 */
export function advisoriesToSarif(advisories: Advisory[], options: { toolVersion: string; locate: (purl: string) => string }): object {
  const sorted = sortAdvisories(advisories);
  const rules = new Map<string, Advisory>();
  for (const advisory of sorted) if (!rules.has(advisory.id)) rules.set(advisory.id, advisory);
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "0 sbom check",
          version: options.toolVersion,
          informationUri: "https://github.com/0sec-labs/0security",
          rules: [...rules.values()].map(advisory => ({
            id: advisory.id,
            name: advisory.malicious ? "MaliciousPackage" : "VulnerableDependency",
            shortDescription: { text: advisory.malicious ? `Malicious package (${advisory.id})` : (advisory.summary || advisory.id).slice(0, 300) },
            fullDescription: { text: advisory.malicious ? "OSV lists this package as malicious: it was published to attack the people who install it." : `Known vulnerability ${advisory.id} in a dependency. Details: https://osv.dev/vulnerability/${encodeURIComponent(advisory.id)}` },
            helpUri: `https://osv.dev/vulnerability/${encodeURIComponent(advisory.id)}`,
            defaultConfiguration: { level: LEVEL[advisory.severity] },
            properties: { tags: ["dependency", ...(advisory.malicious ? ["malicious-package"] : [])] },
          })),
        },
      },
      results: sorted.map(advisory => {
        const fromCvss = advisory.cvss !== undefined && bandOfScore(advisory.cvss) === advisory.severity ? advisory.cvss : undefined;
        const score = advisory.malicious ? 10 : fromCvss ?? SCORE[advisory.severity];
        const what = advisory.malicious ? `MALICIOUS PACKAGE: ${componentLabel(advisory.purl)} is listed as malicious (${advisory.id}).` : `${componentLabel(advisory.purl)} has ${advisory.id}${advisory.summary ? `: ${advisory.summary}` : ""}.`;
        return {
          ruleId: advisory.id,
          level: LEVEL[advisory.severity],
          message: { text: `${what} ${fixAdvice(advisory)}` },
          locations: [{ physicalLocation: { artifactLocation: { uri: options.locate(advisory.purl).split("\\").join("/") }, region: { startLine: 1 } } }],
          partialFingerprints: { "0sbomAdvisory/v1": sha(`${advisory.purl}\n${advisory.id}`) },
          properties: { purl: advisory.purl, severity: advisory.severity, ...(score !== undefined ? { "security-severity": String(score) } : {}), ...(advisory.fixedVersion ? { fixedVersion: advisory.fixedVersion } : {}), ...(advisory.aliases.length ? { aliases: advisory.aliases } : {}), malicious: advisory.malicious, ...(advisory.reachability ? { reachability: advisory.reachability } : {}) },
        };
      }),
    }],
  };
}
