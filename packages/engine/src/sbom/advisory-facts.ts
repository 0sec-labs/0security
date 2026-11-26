/**
 * Facts read from an OSV record for one package: the severity, the version that fixes it and whether the package is
 * malicious. Records are untrusted text; nothing here is executed and every string is bounded by the caller.
 */
export type AdvisorySeverity = "critical" | "high" | "medium" | "low" | "unknown";

const isObject = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);

/** CVSS 3.x base score from a vector string such as `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. Undefined for anything else. */
export function cvss3BaseScore(vector: string): number | undefined {
  if (!/^CVSS:3\.[01]\//.test(vector) || vector.length > 200) return undefined;
  const metrics = new Map(vector.split("/").slice(1).map(part => part.split(":") as [string, string]));
  const pick = (key: string, table: Record<string, number>): number | undefined => table[metrics.get(key) ?? ""];
  const scopeChanged = metrics.get("S") === "C";
  if (metrics.get("S") !== "C" && metrics.get("S") !== "U") return undefined;
  const av = pick("AV", { N: 0.85, A: 0.62, L: 0.55, P: 0.2 });
  const ac = pick("AC", { L: 0.77, H: 0.44 });
  const pr = pick("PR", scopeChanged ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 });
  const ui = pick("UI", { N: 0.85, R: 0.62 });
  const c = pick("C", { H: 0.56, L: 0.22, N: 0 });
  const i = pick("I", { H: 0.56, L: 0.22, N: 0 });
  const a = pick("A", { H: 0.56, L: 0.22, N: 0 });
  if ([av, ac, pr, ui, c, i, a].some(value => value === undefined)) return undefined;
  const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  const exploitability = 8.22 * av! * ac! * pr! * ui!;
  if (impact <= 0) return 0;
  const raw = scopeChanged ? Math.min(1.08 * (impact + exploitability), 10) : Math.min(impact + exploitability, 10);
  return Math.ceil(Math.round(raw * 100000) / 10000) / 10;
}

export function bandOfScore(score: number): AdvisorySeverity {
  return score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : score > 0 ? "low" : "unknown";
}

/**
 * The severity of an OSV record. The database's own label (GitHub writes LOW, MODERATE, HIGH or CRITICAL) wins; otherwise
 * a CVSS 3 vector is scored. A CVSS 4 vector, an unknown label or no data stays unknown.
 */
export function severityOf(record: Record<string, unknown>): { severity: AdvisorySeverity; cvss?: number } {
  const database = isObject(record.database_specific) ? record.database_specific : {};
  let cvss: number | undefined;
  for (const entry of Array.isArray(record.severity) ? record.severity : []) {
    if (isObject(entry) && typeof entry.score === "string") { cvss = cvss3BaseScore(entry.score) ?? cvss; if (cvss !== undefined) break; }
  }
  const label = typeof database.severity === "string" ? database.severity.trim().toLowerCase() : "";
  const named: AdvisorySeverity | undefined = label === "critical" ? "critical" : label === "high" ? "high" : label === "moderate" || label === "medium" ? "medium" : label === "low" ? "low" : undefined;
  if (named) return { severity: named, ...(cvss !== undefined ? { cvss } : {}) };
  if (cvss !== undefined) return { severity: bandOfScore(cvss), cvss };
  return { severity: "unknown" };
}

/** A tolerant version order for npm, Cargo, PyPI, Go, Ruby, NuGet, Composer and Maven versions. Pre-release suffixes sort before the release. */
export function compareVersions(a: string, b: string): number {
  const parse = (value: string) => {
    const match = /^v?(?:\d+:)?(\d+(?:[._]\d+)*)(.*)$/i.exec(value.trim());
    if (!match) return { nums: [] as number[], rest: value.trim().toLowerCase(), pre: false };
    const rest = match[2]!.replace(/^\+.*$/, "").toLowerCase();
    return { nums: match[1]!.split(/[._]/).map(Number), rest, pre: /^[-._]?(a|b|c|rc|alpha|beta|pre|preview|dev|snapshot|m\d)/.test(rest) };
  };
  const left = parse(a); const right = parse(b);
  for (let index = 0; index < Math.max(left.nums.length, right.nums.length); index += 1) {
    const diff = (left.nums[index] ?? 0) - (right.nums[index] ?? 0);
    if (diff) return diff < 0 ? -1 : 1;
  }
  if (left.pre !== right.pre) return left.pre ? -1 : 1;
  return left.rest < right.rest ? -1 : left.rest > right.rest ? 1 : 0;
}

const norm = (value: string): string => { try { return decodeURIComponent(value).toLowerCase().replace(/[._]+/g, "-"); } catch { return value.toLowerCase(); } };
const baseOf = (purl: string): string => norm(purl.replace(/[?#].*$/, "").replace(/@[^@/]*$/, ""));

/** The installed version in a package URL, or undefined. */
export function purlVersion(purl: string): string | undefined {
  const match = /@([^@/?#]+)(?:[?#].*)?$/.exec(purl);
  if (!match) return undefined;
  try { return decodeURIComponent(match[1]!); } catch { return match[1]; }
}

/** The `affected` entries of a record that are about this package. An entry with no package field applies to every package. */
function matching(affected: unknown[], purl: string): Record<string, unknown>[] {
  const wanted = baseOf(purl);
  return affected.filter(isObject).filter(entry => {
    const pkg = isObject(entry.package) ? entry.package : undefined;
    if (!pkg) return true;
    return typeof pkg.purl === "string" && baseOf(pkg.purl) === wanted;
  });
}

/**
 * Versions that fix the advisory for this package, and the lowest of them above the installed version. Only the
 * `fixed` events of SEMVER and ECOSYSTEM ranges count (a GIT range names commits). No guess when the record gives none.
 */
export function fixesFor(affected: unknown[], purl: string): { fixed: string[]; fixedVersion?: string } {
  const fixed = new Set<string>();
  for (const entry of matching(affected, purl)) {
    for (const range of Array.isArray(entry.ranges) ? entry.ranges : []) {
      if (!isObject(range) || (range.type !== "SEMVER" && range.type !== "ECOSYSTEM")) continue;
      for (const event of Array.isArray(range.events) ? range.events : []) {
        if (isObject(event) && typeof event.fixed === "string" && event.fixed.trim() && event.fixed.length <= 60) fixed.add(event.fixed.trim());
      }
    }
  }
  const installed = purlVersion(purl);
  const sorted = [...fixed].sort(compareVersions);
  const above = installed ? sorted.find(version => compareVersions(version, installed) > 0) : sorted[0];
  return { fixed: sorted.slice(0, 5), ...(above ? { fixedVersion: above } : {}) };
}

const SYMBOL = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/;

/**
 * The classes or symbols a Maven advisory names as vulnerable, as fully qualified names. OSV puts them in
 * `ecosystem_specific.imports` or `database_specific.imports` as `{ path, symbols }` (the shape the Go ecosystem uses).
 * A symbol that starts with a capital letter is qualified with the entry's `path`; a name that cannot be qualified is dropped, never guessed.
 */
export function vulnerableSymbolsFor(affected: unknown[], purl: string): string[] {
  const found = new Set<string>();
  // Stops at 100 names and 10000 looks: the caller keeps 20 and reports that there were more.
  let looks = 0;
  for (const entry of matching(affected, purl)) {
    for (const holder of [entry.ecosystem_specific, entry.database_specific]) {
      if (!isObject(holder) || !Array.isArray(holder.imports)) continue;
      for (const item of holder.imports.slice(0, 200)) {
        if (!isObject(item)) continue;
        const path = typeof item.path === "string" && item.path.length <= 200 ? item.path.trim() : "";
        for (const symbol of (Array.isArray(item.symbols) ? item.symbols : []).slice(0, 200)) {
          looks += 1;
          if (looks > 10_000 || found.size >= 100) return [...found].sort();
          if (typeof symbol !== "string" || symbol.length > 200) continue;
          const bare = symbol.trim();
          // `Server.Serve` is a class and method under the path; `a.b.C` is already qualified.
          const name = !path || /^[a-z]/.test(bare) ? bare : `${path}.${bare}`;
          if (SYMBOL.test(name)) found.add(name);
        }
      }
    }
  }
  return [...found].sort();
}
