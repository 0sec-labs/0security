/**
 * Choosing generators for one agent. A generator applies when the agent's manifest has what it needs: every required tool name is
 * listed, every required privilege class is held by some tool, and every required source kind is read (a manifest that lists no
 * sources at all is treated as unknown and does not exclude anything, as in the starter pack). An agent with no tools is never
 * selected for: nothing could be steered. The pick mixes difficulties and spreads over areas so a small count still covers a lot.
 */
import type { BrainManifest } from "../brain/schema.js";
import { CATALOG } from "./entries/index.js";
import type { Difficulty, GeneratorSpec, Tier } from "./types.js";

export interface SelectOptions {
  count?: number;
  difficulties?: Difficulty[];
  /** Case-insensitive prefix of the area name, so "Exfiltration" matches "Exfiltration (render)". */
  areas?: string[];
  tiers?: Tier[];
  /** Rotates the starting point so repeated runs sample different generators; without it the order is the catalog order. */
  seed?: string;
}

const ORDER: readonly Difficulty[] = ["basic", "intermediate", "advanced"];

export function applies(spec: GeneratorSpec, manifest: BrainManifest): boolean {
  if (!manifest.tools.length) return false;
  const names = new Set(manifest.tools.map(tool => tool.name));
  const privileges = new Set<string>(manifest.tools.map(tool => tool.privilege));
  const kinds = new Set<string>(manifest.sources.map(source => source.kind));
  return (spec.requires.tools ?? []).every(name => names.has(name))
    && (spec.requires.privileges ?? []).every(privilege => privileges.has(privilege))
    && (!kinds.size || (spec.requires.sources ?? []).every(kind => kinds.has(kind)));
}

/** Takes one from each group in turn until all are empty. */
function interleave<T>(groups: T[][]): T[] {
  const out: T[] = [];
  for (let round = 0; groups.some(group => round < group.length); round++) for (const group of groups) if (round < group.length) out.push(group[round]!);
  return out;
}

const hash = (text: string): number => { let h = 0; for (const ch of text) h = (h * 31 + ch.charCodeAt(0)) >>> 0; return h; };
const rotate = <T>(items: T[], by: number): T[] => (items.length ? [...items.slice(by % items.length), ...items.slice(0, by % items.length)] : items);

export function selectGenerators(manifest: BrainManifest, options: SelectOptions = {}): GeneratorSpec[] {
  const areas = options.areas?.map(area => area.toLowerCase());
  const fits = CATALOG.filter(spec => applies(spec, manifest)
    && (!options.difficulties || options.difficulties.includes(spec.difficulty))
    && (!areas || areas.some(area => spec.area.toLowerCase().startsWith(area)))
    && (!options.tiers || options.tiers.includes(spec.tier)));
  const shift = options.seed ? hash(options.seed) : 0;
  const buckets = ORDER.map(difficulty => {
    const inBucket = fits.filter(spec => spec.difficulty === difficulty);
    const byArea = new Map<string, GeneratorSpec[]>();
    for (const spec of inBucket) byArea.set(spec.area, [...(byArea.get(spec.area) ?? []), spec]);
    return rotate(interleave([...byArea.values()]), shift);
  });
  const mixed = interleave(buckets);
  return mixed.slice(0, options.count ?? mixed.length);
}

export interface CatalogStats { total: number; byArea: Record<string, number>; byTier: Record<Tier, number>; byDifficulty: Record<Difficulty, number> }

export function catalogStats(specs: readonly GeneratorSpec[] = CATALOG): CatalogStats {
  const stats: CatalogStats = { total: specs.length, byArea: {}, byTier: { open: 0, closed: 0, both: 0 }, byDifficulty: { basic: 0, intermediate: 0, advanced: 0 } };
  for (const spec of specs) {
    stats.byArea[spec.area] = (stats.byArea[spec.area] ?? 0) + 1;
    stats.byTier[spec.tier]++;
    stats.byDifficulty[spec.difficulty]++;
  }
  return stats;
}
