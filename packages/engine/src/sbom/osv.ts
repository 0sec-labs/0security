import type { DependencyReachability } from "./java-reachability.js";
import { assertEgressAllowed } from "../policy/enterprise.js";

/**
 * Check an SBOM's components against the public OSV database (https://osv.dev). The SBOM and the responses are untrusted
 * text: package URLs are validated and bounded, and every string that comes back is cleaned and truncated before use.
 */
import { fixesFor, severityOf, vulnerableSymbolsFor, type AdvisorySeverity } from "./advisory-facts.js";
export type { AdvisorySeverity } from "./advisory-facts.js";
import type { AdvisoryUsage } from "./advisory-usage.js";

export interface Advisory {
  /** Optional package-level source evidence. Vulnerable-code reachability remains unknown. */
  reachability?: DependencyReachability;
  /** The component's package URL. */
  purl: string;
  id: string;
  aliases: string[];
  summary: string;
  /** From the database's own label or a CVSS 3 vector; `unknown` when the record has neither. A malicious package is always critical. */
  severity: AdvisorySeverity;
  /** CVSS 3 base score, when the record has a vector. */
  cvss?: number;
  /** True for an OSV malicious-package record (id starts with `MAL-`): the package itself is hostile, not merely buggy. */
  malicious: boolean;
  /** Every version that fixes it for this package, lowest first. */
  fixed: string[];
  /** The lowest fixing version above the installed one. Absent when the record names none. */
  fixedVersion?: string;
  /** Fully qualified classes or symbols the record names as vulnerable (Maven only), when it lists any. */
  vulnerableSymbols?: string[];
  /** True when the record lists more symbols than `vulnerableSymbols` keeps. */
  vulnerableSymbolsTruncated?: boolean;
  /** Where the application's own source imports this component. Only set by `0 sbom check --usage`: evidence, not reachability. */
  usage?: AdvisoryUsage;
}
export interface OsvOptions {
  fetch?: typeof fetch;
  baseUrl?: string;
  /** Most advisories whose details are fetched; the rest are still counted. */
  maxDetails?: number;
}

const MAX_SYMBOLS_PER_ADVISORY = 20;
const BATCH = 1000;
const MAX_COMPONENTS = 20_000;
const MAX_DETAILS = 500;
const CONCURRENCY = 8;
const TIMEOUT_MS = 20_000;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;
const clean = (value: unknown, max: number): string => typeof value === "string" ? value.replace(CONTROL, "").trim().slice(0, max) : "";
const isObject = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);

async function post(fetcher: typeof fetch, url: string, body: unknown): Promise<unknown> {
  const response = await fetcher(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!response.ok) throw new Error(`OSV answered ${response.status}`);
  return response.json();
}
async function get(fetcher: typeof fetch, url: string): Promise<unknown> {
  const response = await fetcher(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
  if (!response.ok) throw new Error(`OSV answered ${response.status}`);
  return response.json();
}

/** What the SBOM says it could not resolve (the `0:unresolved` metadata properties from `0 sbom generate`), cleaned for display. */
function unresolvedOf(bom: unknown): string[] {
  const metadata = isObject(bom) && isObject(bom.metadata) ? bom.metadata : {};
  const properties = Array.isArray(metadata.properties) ? metadata.properties : [];
  return properties.flatMap(property => isObject(property) && property.name === "0:unresolved" ? [clean(property.value, 400)] : []).filter(Boolean);
}

function symbolsField(affected: unknown[], purl: string): { vulnerableSymbols?: string[]; vulnerableSymbolsTruncated?: boolean } {
  if (!purl.startsWith("pkg:maven/")) return {};
  const symbols = vulnerableSymbolsFor(affected, purl);
  return symbols.length ? { vulnerableSymbols: symbols.slice(0, MAX_SYMBOLS_PER_ADVISORY), ...(symbols.length > MAX_SYMBOLS_PER_ADVISORY ? { vulnerableSymbolsTruncated: true } : {}) } : {};
}

export async function checkBomAgainstOsv(bom: unknown, options: OsvOptions = {}): Promise<{ checked: number; advisories: Advisory[]; withoutDetails: number; unresolved: string[] }> {
  if (!options.fetch && !options.baseUrl) assertEgressAllowed("api.osv.dev (advisory lookup)");
  const fetcher = options.fetch ?? fetch;
  const base = (options.baseUrl ?? "https://api.osv.dev").replace(/\/$/, "");
  const components = isObject(bom) && Array.isArray(bom.components) ? bom.components : [];
  const purls = [...new Set(components.map(component => isObject(component) ? component.purl : undefined)
    .filter((purl): purl is string => typeof purl === "string" && /^pkg:[a-z]+\/\S{1,380}$/.test(purl)))].slice(0, MAX_COMPONENTS);
  if (!purls.length) throw new Error("The SBOM has no components with a package URL to check.");

  const hits = new Map<string, Set<string>>(); // advisory id -> purls it affects
  for (let start = 0; start < purls.length; start += BATCH) {
    const slice = purls.slice(start, start + BATCH);
    const answer = await post(fetcher, `${base}/v1/querybatch`, { queries: slice.map(purl => ({ package: { purl } })) });
    const results = isObject(answer) && Array.isArray(answer.results) ? answer.results : [];
    results.forEach((result, index) => {
      const vulns = isObject(result) && Array.isArray(result.vulns) ? result.vulns : [];
      for (const vuln of vulns) {
        const id = isObject(vuln) ? clean(vuln.id, 80) : "";
        if (id) hits.set(id, (hits.get(id) ?? new Set()).add(slice[index]!));
      }
    });
  }

  const ids = [...hits.keys()].sort();
  const detailIds = ids.slice(0, options.maxDetails ?? MAX_DETAILS);
  const details = new Map<string, { aliases: string[]; summary: string; severity: AdvisorySeverity; cvss?: number; affected: unknown[] }>();
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, detailIds.length) }, async () => {
    while (next < detailIds.length) {
      const id = detailIds[next++]!;
      try {
        const record = await get(fetcher, `${base}/v1/vulns/${encodeURIComponent(id)}`);
        if (!isObject(record)) continue;
        details.set(id, {
          aliases: (Array.isArray(record.aliases) ? record.aliases : []).map(alias => clean(alias, 80)).filter(Boolean).slice(0, 8),
          summary: clean(record.summary, 300) || clean(record.details, 300),
          ...severityOf(record),
          affected: Array.isArray(record.affected) ? record.affected.slice(0, 500) : [],
        });
      } catch { /* an advisory whose details cannot be read is still reported by id */ }
    }
  }));

  const advisories: Advisory[] = [];
  for (const id of ids) {
    const detail = details.get(id) ?? { aliases: [], summary: "", severity: "unknown" as AdvisorySeverity, affected: [] };
    const malicious = id.startsWith("MAL-");
    for (const purl of [...hits.get(id)!].sort()) {
      advisories.push({ purl, id, aliases: detail.aliases, summary: detail.summary, severity: malicious ? "critical" : detail.severity, ...(detail.cvss !== undefined ? { cvss: detail.cvss } : {}), malicious, ...fixesFor(detail.affected, purl), ...symbolsField(detail.affected, purl) });
    }
  }
  return { checked: purls.length, advisories, withoutDetails: ids.length - detailIds.length + detailIds.filter(id => !details.has(id)).length, unresolved: unresolvedOf(bom) };
}
