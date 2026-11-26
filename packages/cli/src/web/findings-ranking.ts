/**
 * Business-context labels for the web Findings list when no label was stored by a scan: the engine reads the file named
 * by the findingsContext setting (the same one the commands use) and labels each finding family the same way
 * `scan --business-context` does. The browser orders and explains; severity is never changed. Nothing is read from a
 * scanned repository.
 */
import { statSync } from "node:fs";
import { basename } from "node:path";
import type { FindingBusinessContext } from "@0/engine/shared";
import { loadBusinessContext, findingPath, type BusinessContext } from "../business-context.js";
import { contextPath, detectRepository, labelFor, type LoadedContext } from "../business-context-load.js";
import { repoIdentifier } from "../scan-tiers.js";

interface Cached { path: string; mtimeMs: number; size: number; context?: BusinessContext }
let cached: Cached | undefined;
const repositories = new Map<string, string | undefined>();
const MAX_REMEMBERED_TARGETS = 500;

function readContext(path: string): Cached {
  let stat;
  try { stat = statSync(path); } catch { return { path, mtimeMs: 0, size: 0 }; }
  if (cached && cached.path === path && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) return cached;
  try { cached = { path, mtimeMs: stat.mtimeMs, size: stat.size, context: loadBusinessContext(path) }; }
  catch { cached = { path, mtimeMs: stat.mtimeMs, size: stat.size }; }
  return cached;
}

/** The repository a scan target stands for: owner/name from a git URL, the folder's git remote or its name. */
async function repositoryOf(target: string): Promise<string | undefined> {
  if (repositories.has(target)) return repositories.get(target);
  let name: string | undefined;
  if (/^(?:[a-z][a-z0-9+.-]*:\/\/|git@)/i.test(target)) name = repoIdentifier(target);
  else if (/^(\/|~|[A-Za-z]:[\\/])/.test(target)) name = (await detectRepository(target)) ?? (basename(target.replace(/[\\/]+$/, "")) || undefined);
  if (repositories.size >= MAX_REMEMBERED_TARGETS) repositories.clear();
  repositories.set(target, name);
  return name;
}

export interface RankableFamily { key: string; latest: { scanId: string; severity: string; reviewAnnotation?: unknown } }

/**
 * A label per family key. A missing or invalid file labels nothing: the list keeps what a scan stored or its severity
 * order, and `0 findings context check` says why.
 */
export async function labelFamilies(families: readonly RankableFamily[], scanTargets: ReadonlyMap<string, string>, settings?: { findingsContext?: string }): Promise<Map<string, FindingBusinessContext>> {
  const labels = new Map<string, FindingBusinessContext>();
  let named;
  try { named = contextPath({}, settings); } catch { return labels; }
  if (!named) return labels;
  const loaded = readContext(named.path);
  if (!loaded.context) return labels;
  const wrapper: LoadedContext = { context: loaded.context, source: named.path, fromConfig: true };
  const needsRepository = loaded.context.repositories.length > 0;
  for (const family of families) {
    const target = scanTargets.get(family.latest.scanId);
    const repository = needsRepository && target ? await repositoryOf(target) : undefined;
    const path = findingPath(family.latest.reviewAnnotation);
    labels.set(family.key, labelFor(wrapper, { severity: family.latest.severity, ...(path ? { path } : {}) }, repository ?? (target ? basename(target.replace(/[\\/]+$/, "")) : undefined)));
  }
  return labels;
}
