/**
 * Find components with a newer release, using the public deps.dev API (https://docs.deps.dev/api/v3/). Opt-in: package
 * names go to api.deps.dev. A newer version is information, not a vulnerability; nothing here says an old version is unsafe.
 */
import { assertEgressAllowed } from "../policy/enterprise.js";
import { compareVersions, purlVersion } from "./advisory-facts.js";

export interface OutdatedNote {
  purl: string;
  installed: string;
  latest: string;
  /** How far behind, as the largest differing part: major versions, else minor versions, else patch versions. */
  behind: { major: number; minor: number; patch: number };
  /** Releases (not pre-releases) published after the installed one. */
  releasesBehind: number;
}
export interface OutdatedResult {
  /** Components looked up. */
  checked: number;
  /** Components with a package URL in an ecosystem deps.dev does not cover. */
  unsupported: number;
  /** Components not looked up because there were more than the cap. */
  overCap: number;
  /** Lookups that failed (network error, unknown package). */
  failed: number;
  cap: number;
  notes: OutdatedNote[];
}
export interface OutdatedOptions { fetch?: typeof fetch; baseUrl?: string; cap?: number }

export const OUTDATED_CAP = 200;
const CONCURRENCY = 6;
const TIMEOUT_MS = 15_000;
const SYSTEMS: Record<string, string> = { npm: "npm", pypi: "pypi", cargo: "cargo", golang: "go", nuget: "nuget", maven: "maven", gem: "rubygems" };
const isObject = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);

function parts(version: string): number[] {
  const match = /^v?(\d+(?:\.\d+)*)/.exec(version.trim());
  return match ? match[1]!.split(".").map(Number) : [];
}
const isPre = (version: string): boolean => /^v?\d+(?:[._]\d+)*[-._]?(a|b|c|rc|alpha|beta|pre|preview|dev|snapshot|m\d)/i.test(version.trim());

export function gap(installed: string, latest: string): { major: number; minor: number; patch: number } {
  const a = parts(installed); const b = parts(latest);
  const dM = (b[0] ?? 0) - (a[0] ?? 0);
  if (dM > 0) return { major: dM, minor: 0, patch: 0 };
  const dm = (b[1] ?? 0) - (a[1] ?? 0);
  if (dM === 0 && dm > 0) return { major: 0, minor: dm, patch: 0 };
  const dp = (b[2] ?? 0) - (a[2] ?? 0);
  return { major: 0, minor: 0, patch: dM === 0 && dm === 0 && dp > 0 ? dp : 0 };
}

/** The deps.dev system and package name for a package URL, or undefined when deps.dev does not cover the ecosystem. */
export function depsDevName(purl: string): { system: string; name: string } | undefined {
  const match = /^pkg:([a-z]+)\/([^@?#]+)@[^?#]+/.exec(purl);
  const system = match ? SYSTEMS[match[1]!] : undefined;
  if (!match || !system) return undefined;
  let name: string;
  try { name = decodeURIComponent(match[2]!); } catch { return undefined; }
  if (match[1] === "maven") name = name.replace("/", ":");
  return name.length <= 300 ? { system, name } : undefined;
}

export async function checkOutdated(bom: unknown, options: OutdatedOptions = {}): Promise<OutdatedResult> {
  if (!options.fetch && !options.baseUrl) assertEgressAllowed("api.deps.dev (newer versions)");
  const fetcher = options.fetch ?? fetch;
  const base = (options.baseUrl ?? "https://api.deps.dev").replace(/\/$/, "");
  const cap = options.cap ?? OUTDATED_CAP;
  const components = isObject(bom) && Array.isArray(bom.components) ? bom.components.filter(isObject) : [];
  // Runtime dependencies first, so the cap drops development-only packages before anything else.
  const ordered = [...components].sort((a, b) => Number(a.scope === "excluded") - Number(b.scope === "excluded"));
  const seen = new Set<string>();
  const wanted: Array<{ purl: string; installed: string; system: string; name: string }> = [];
  let unsupported = 0;
  for (const component of ordered) {
    const purl = typeof component.purl === "string" && /^pkg:[a-z]+\/\S{1,380}$/.test(component.purl) ? component.purl : undefined;
    if (!purl || seen.has(purl)) continue;
    seen.add(purl);
    const target = depsDevName(purl); const installed = purlVersion(purl);
    if (!target || !installed) { unsupported += 1; continue; }
    wanted.push({ purl, installed, ...target });
  }
  const chosen = wanted.slice(0, cap);
  const notes: OutdatedNote[] = [];
  let failed = 0; let next = 0;
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, chosen.length) }, async () => {
    while (next < chosen.length) {
      const item = chosen[next++]!;
      try {
        const response = await fetcher(`${base}/v3/systems/${item.system}/packages/${encodeURIComponent(item.name)}`, { signal: AbortSignal.timeout(TIMEOUT_MS) });
        if (!response.ok) { failed += 1; continue; }
        const body = await response.json() as unknown;
        const versions = isObject(body) && Array.isArray(body.versions) ? body.versions.filter(isObject) : [];
        const name = (entry: Record<string, unknown>): string => isObject(entry.versionKey) && typeof entry.versionKey.version === "string" ? entry.versionKey.version.slice(0, 80) : "";
        const latest = versions.filter(entry => entry.isDefault === true).map(name).find(Boolean);
        if (!latest || compareVersions(latest, item.installed) <= 0) continue;
        const releasesBehind = versions.map(name).filter(version => version && !isPre(version) && compareVersions(version, item.installed) > 0).length;
        notes.push({ purl: item.purl, installed: item.installed, latest, behind: gap(item.installed, latest), releasesBehind });
      } catch { failed += 1; }
    }
  }));
  notes.sort((a, b) => b.behind.major - a.behind.major || b.behind.minor - a.behind.minor || b.behind.patch - a.behind.patch || (a.purl < b.purl ? -1 : 1));
  return { checked: chosen.length, unsupported, overCap: wanted.length - chosen.length, failed, cap, notes };
}

const describe = (note: OutdatedNote): string => {
  const { major, minor, patch } = note.behind;
  return major ? `${major} major version${major === 1 ? "" : "s"} behind` : minor ? `${minor} minor version${minor === 1 ? "" : "s"} behind` : patch ? `${patch} patch version${patch === 1 ? "" : "s"} behind` : "behind";
};

/** Informational notes. They never say a version is unsafe. */
export function outdatedToText(result: OutdatedResult): string {
  const lines = ["Newer versions (information only; an older version is not necessarily unsafe):"];
  if (!result.notes.length) lines.push("  No newer versions found.");
  for (const note of result.notes) {
    const name = /^pkg:[^/]+\/([^@?#]+)/.exec(note.purl)?.[1] ?? note.purl;
    let shown = name; try { shown = decodeURIComponent(name); } catch { /* keep raw */ }
    lines.push(`  ${shown} ${note.installed}  latest ${note.latest}  ${describe(note)}  (${note.releasesBehind} release${note.releasesBehind === 1 ? "" : "s"} since)`);
  }
  if (result.overCap) lines.push(`  Looked up the first ${result.cap} of ${result.checked + result.overCap} supported components; ${result.overCap} were not checked.`);
  if (result.unsupported) lines.push(`  ${result.unsupported} components are in ecosystems deps.dev does not cover.`);
  if (result.failed) lines.push(`  ${result.failed} lookups failed.`);
  return `${lines.join("\n")}\n`;
}
