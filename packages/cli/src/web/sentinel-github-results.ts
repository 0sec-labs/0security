/**
 * The SARIF a Sentinel run uploads to GitHub code scanning. It is built from share-safe finding fields only (severity, title,
 * category, repository-relative location): no description, evidence, proof-of-concept steps or local paths. Text is neutralised for
 * GitHub, and the document has a fixed size cap, so a long run cannot produce an upload GitHub would refuse.
 */
import { createHash } from "node:crypto";
import { VERSION, type ShareSafeReport } from "@0/engine/shared";

/** GitHub accepts up to 5,000 results in a run. Fewer keeps the document small. */
export const MAX_SARIF_RESULTS = 1_000;
const TOOL_NAME = "0security Sentinel";

/** One line for GitHub: no links, markup, @mentions or #123 references. */
export const neutralise = (text: string, max: number): string => text
  .replace(/[a-z][a-z0-9+.-]*:\/\/\S+/gi, "(link removed)")
  .replace(/[\r\n\t]+/g, " ")
  .replace(/[<>`\[\]]/g, "")
  .replace(/@/g, "@​")
  .replace(/#(?=\w)/g, "#​")
  .slice(0, max)
  .trim();

const safePath = (path: string | undefined): string | undefined =>
  path && /^[\w./@+-]{1,200}$/.test(path) && !path.startsWith("/") && !path.split("/").includes("..") ? path : undefined;

const levelOf = (severity: string): "error" | "warning" | "note" => {
  const value = severity.toLowerCase();
  return value === "critical" || value === "high" ? "error" : value === "medium" ? "warning" : "note";
};
const securitySeverity = (severity: string): string => ({ critical: "9.5", high: "8.0", medium: "5.5", low: "3.0" } as Record<string, string>)[severity.toLowerCase()] ?? "1.0";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const slug = (text: string, max: number): string => text.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, max) || "sentinel";

export interface BuiltSarif {
  /** The SARIF 2.1.0 document. */
  text: string;
  /** Results in the document. */
  included: number;
  /** Findings left out: no repository-relative location, or over the cap. */
  skipped: number;
}

export function buildSentinelSarif(sentinelName: string, findings: ShareSafeReport["findings"]): BuiltSarif {
  const rules = new Map<string, { id: string; name: string; shortDescription: { text: string }; properties: Record<string, unknown> }>();
  const results: Array<Record<string, unknown>> = [];
  let skipped = 0;
  // The most severe findings come first, so the cap drops the least important ones.
  const ordered = [...findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity.toLowerCase()) - SEVERITY_ORDER.indexOf(b.severity.toLowerCase()));
  for (const finding of ordered) {
    const path = safePath(finding.location?.path);
    if (!path || results.length >= MAX_SARIF_RESULTS) { skipped += 1; continue; }
    const line = Math.max(1, Math.floor(finding.location?.startLine ?? 1));
    const ruleId = slug(finding.templateId || finding.category || "finding", 80);
    if (!rules.has(ruleId)) rules.set(ruleId, { id: ruleId, name: ruleId, shortDescription: { text: neutralise(finding.category || ruleId, 100) || ruleId }, properties: { "security-severity": securitySeverity(finding.severity) } });
    const fingerprint = createHash("sha256").update(`${ruleId}\n${path}\n${finding.fingerprint ?? finding.title}`).digest("hex").slice(0, 32);
    results.push({
      ruleId,
      level: levelOf(finding.severity),
      message: { text: `${neutralise(finding.severity, 16)}: ${neutralise(finding.title, 200)}` },
      locations: [{ physicalLocation: { artifactLocation: { uri: path }, region: { startLine: line } } }],
      partialFingerprints: { "0securitySentinel/v1": fingerprint },
    });
  }
  const document = {
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: TOOL_NAME, version: VERSION, rules: [...rules.values()] } },
      // One category per Sentinel, so two Sentinels never close each other's alerts.
      automationDetails: { id: `0-sentinel/${slug(sentinelName, 60)}/` },
      results,
    }],
  };
  return { text: JSON.stringify(document), included: results.length, skipped };
}
