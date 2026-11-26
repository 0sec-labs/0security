import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import { extname, join } from "node:path";
import { SKIP_DIRS, SKIP_FILE, isIgnored, parseGitignore } from "../inventory/index.js";
import { SOURCE_EXTENSIONS } from "../inventory/matchers.js";
import type { IgnoreRule } from "../inventory/gitignore.js";
import { IndexBudgetExceeded, appendAll, withDeadline } from "./budget.js";
import { extractJs } from "./extract-js.js";
import { extractPy } from "./extract-py.js";
import { foxguardGraph } from "./foxguard.js";
import type { CodeIndex, FileExtract } from "./types.js";

const JS_EXT = new Set(["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts"]);
const PY_EXT = new Set(["py"]);
/** Parsed only by the Foxguard graph. They are `unsupported` for the built-in extractor but still key the cache. */
const GRAPH_ONLY_EXT = new Set(["java", "kt", "kts"]);

export interface BuildLimits { maxFiles: number; maxFileBytes: number; maxTotalBytes: number; /** Wall-clock limit for one file, ms. */ fileBudgetMs: number; /** Wall-clock limit for all files, ms. */ totalBudgetMs: number }
/** Most Java files stat-ed for the cache key. */
const GRAPH_ONLY_MAX = 300_000;

export const DEFAULT_LIMITS: BuildLimits = { maxFiles: 5000, maxFileBytes: 400 * 1024, maxTotalBytes: 48 * 1024 * 1024, fileBudgetMs: 2_000, totalBudgetMs: 20_000 };

function git(root: string, args: string[]): string | undefined {
  try {
    return execFileSync("git", args, { cwd: root, encoding: "utf8", timeout: 10_000, stdio: ["ignore", "pipe", "ignore"], maxBuffer: 8 * 1024 * 1024 });
  } catch { return undefined; }
}

interface SourceFile { path: string; size: number; mtimeMs: number }

function walk(root: string, limits: BuildLimits): { files: SourceFile[]; graphOnly: SourceFile[]; unsupported: Record<string, number>; truncated: boolean } {
  const files: SourceFile[] = [];
  const graphOnly: SourceFile[] = [];
  const unsupported: Record<string, number> = {};
  let truncated = false;
  const visit = (rel: string, inherited: readonly IgnoreRule[]): void => {
    let entries;
    try { entries = readdirSync(join(root, rel), { withFileTypes: true }); } catch { return; }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    let rules = inherited;
    if (entries.some((e) => e.name === ".gitignore" && e.isFile())) {
      try { rules = [...inherited, ...parseGitignore(readFileSync(join(root, rel, ".gitignore"), "utf8").slice(0, 64 * 1024), rel)]; } catch { /* unreadable ignore file */ }
    }
    for (const entry of entries) {
      const path = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name) || isIgnored(rules, path, true)) continue;
        visit(path, rules);
        continue;
      }
      if (!entry.isFile()) continue;
      // The servlet deployment descriptor holds security constraints the Foxguard graph maps onto routes.
      if (entry.name === "web.xml" && graphOnly.length < GRAPH_ONLY_MAX && !isIgnored(rules, path, false)) {
        try { const st = lstatSync(join(root, path)); graphOnly.push({ path, size: st.size, mtimeMs: st.mtimeMs }); } catch { /* vanished */ }
        continue;
      }
      const ext = extname(entry.name).slice(1).toLowerCase();
      if (!SOURCE_EXTENSIONS.has(ext) || SKIP_FILE.test(entry.name) || isIgnored(rules, path, false)) continue;
      if (!JS_EXT.has(ext) && !PY_EXT.has(ext)) {
        unsupported[ext] = (unsupported[ext] ?? 0) + 1;
        if (GRAPH_ONLY_EXT.has(ext) && graphOnly.length < GRAPH_ONLY_MAX) {
          try { const st = lstatSync(join(root, path)); graphOnly.push({ path, size: st.size, mtimeMs: st.mtimeMs }); } catch { /* vanished */ }
        }
        continue;
      }
      if (files.length >= limits.maxFiles) { truncated = true; return; }
      try {
        const st = lstatSync(join(root, path));
        if (st.size > limits.maxFileBytes) { truncated = true; continue; }
        files.push({ path, size: st.size, mtimeMs: st.mtimeMs });
      } catch { /* vanished */ }
    }
  };
  visit("", []);
  return { files, graphOnly, unsupported, truncated };
}

function fingerprintOf(commit: string, files: readonly SourceFile[], graphOnly: readonly SourceFile[] = []): string {
  // Commit plus the stat of every indexed file: a new commit or any edit, committed or not, gives a new key.
  const h = createHash("sha256").update(commit);
  for (const f of files) h.update(`\0${f.path}\0${f.size}\0${f.mtimeMs}`);
  for (const f of graphOnly) h.update(`\0${f.path}\0${f.size}\0${f.mtimeMs}`);
  return h.digest("hex").slice(0, 16);
}

function resolveRefs(index: CodeIndex): void {
  const byName = new Map<string, string[]>();
  for (const s of index.symbols) {
    if (s.kind === "module" || s.kind === "route-handler") continue;
    const list = byName.get(s.name);
    if (list) list.push(s.id); else byName.set(s.name, [s.id]);
  }
  for (const r of index.routes) {
    if (!r.handler.startsWith("ref:")) continue;
    const name = r.handler.slice(4);
    const candidates = byName.get(name) ?? [];
    const sameFile = candidates.find((id) => id.startsWith(`${r.file}#`));
    r.handler = sameFile ?? candidates[0] ?? `unresolved:${name}`;
  }
}

async function buildFrom(root: string, walked: ReturnType<typeof walk>, commit: string, fingerprint: string, limits: BuildLimits): Promise<CodeIndex> {
  const index: CodeIndex = {
    version: 1, root, commit, fingerprint,
    files: 0, symbols: [], calls: [], routes: [], unsupported: walked.unsupported, truncated: walked.truncated, engine: "builtin",
  };
  let total = 0;
  const startedAt = Date.now();
  let yielded = startedAt;
  for (const f of walked.files) {
    // Extraction is synchronous: give the event loop a turn every 50 ms, and stop when the total budget is spent.
    if (Date.now() - yielded > 50) { await new Promise<void>((resolve) => setImmediate(resolve)); yielded = Date.now(); }
    const left = limits.totalBudgetMs - (Date.now() - startedAt);
    if (left <= 0) { index.truncated = true; index.skippedSlow = (index.skippedSlow ?? 0) + 1; continue; }
    total += f.size;
    if (total > limits.maxTotalBytes) { index.truncated = true; break; }
    let src: string;
    try { src = readFileSync(join(root, f.path), "utf8"); } catch { continue; }
    const ext = extname(f.path).slice(1).toLowerCase();
    let extract: FileExtract;
    try {
      extract = withDeadline(Math.min(limits.fileBudgetMs, left), () => (JS_EXT.has(ext) ? extractJs(f.path, src) : extractPy(f.path, src)));
    } catch (error) {
      if (error instanceof IndexBudgetExceeded) { index.truncated = true; index.skippedSlow = (index.skippedSlow ?? 0) + 1; }
      continue;
    }
    index.files++;
    appendAll(index.symbols, extract.symbols);
    appendAll(index.calls, extract.calls);
    appendAll(index.routes, extract.routes);
  }
  resolveRefs(index);
  return index;
}

const cache = new Map<string, CodeIndex>();
const CACHE_MAX = 4;

/** The index for a folder, built once per commit and working-tree state. Everything runs locally. */
export async function getIndex(rootInput: string, limits: BuildLimits = DEFAULT_LIMITS, options: { foxguard?: boolean } = {}): Promise<{ index: CodeIndex; cached: boolean }> {
  const root = realpathSync(rootInput);
  const walked = walk(root, limits);
  const commit = git(root, ["rev-parse", "HEAD"])?.trim() ?? "none";
  const fingerprint = fingerprintOf(commit, walked.files, walked.graphOnly);
  const id = `${root}@${fingerprint}`;
  const hit = cache.get(id);
  if (hit) { cache.delete(id); cache.set(id, hit); return { index: hit, cached: true }; }
  // A Foxguard graph, when its binary supports it, replaces the built-in extractor; the key still follows the commit and tree.
  const index = (options.foxguard === false ? undefined : await foxguardGraph(root, commit, fingerprint)) ?? await buildFrom(root, walked, commit, fingerprint, limits);
  cache.set(id, index);
  while (cache.size > CACHE_MAX) cache.delete(cache.keys().next().value as string);
  return { index, cached: false };
}

export function clearIndexCache(): void { cache.clear(); }
