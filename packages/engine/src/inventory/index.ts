/**
 * The entry points of a folder, listed without a model and without running anything.
 *
 * `buildInventory` walks the folder (skipping what .gitignore ignores and vendored or build directories), reads each source
 * file as text and matches it against broad patterns for routes, handlers, webhooks, consumers, program mains and the places
 * hostile data becomes code or a file. Files no pattern matches are grouped into one `other` unit per directory chunk, so
 * every source file belongs to some unit. The result is deterministic: the same folder gives the same units and ids.
 */
import { createHash } from "node:crypto";
import { lstatSync, openSync, closeSync, readdirSync, readFileSync, readSync } from "node:fs";
import { extname, join } from "node:path";
import { isIgnored, parseGitignore, type IgnoreRule } from "./gitignore.js";
import { isEntryPointKind, LINE_MATCHERS, PATH_MATCHERS, SOURCE_EXTENSIONS, UNIT_KINDS, WEBHOOK_NAME, type UnitKind } from "./matchers.js";

export { isEntryPointKind, UNIT_KINDS, type UnitKind } from "./matchers.js";
export { parseGitignore, isIgnored } from "./gitignore.js";
export { javaModuleResolver, javaPackageOf, type BuildModule, type ModuleKind } from "./modules.js";

export interface InventoryUnit {
  /** A hash of the kind, path, line and name: the same code gives the same id. */
  id: string;
  kind: UnitKind;
  /** Relative to the folder, forward slashes. For an `other` unit, the directory. */
  path: string;
  startLine?: number;
  name?: string;
  /** The files an `other` unit covers. */
  files?: string[];
}

export interface InventoryOptions {
  /** Files larger than this are listed as skipped and not read (default 512 KiB). */
  maxFileBytes?: number;
  /** Stop walking after this many files (default 20000). */
  maxFiles?: number;
  /** Entry-point units kept; the files of later ones fall into `other` units (default 3000). */
  maxEntryUnits?: number;
  /** Most files in one `other` unit (default 25). */
  otherChunk?: number;
  /** Only these files (relative paths), for a review of a change. */
  only?: ReadonlySet<string>;
  /** Total bytes read for matching; the rest of the files are not read (default 96 MiB). */
  maxTotalBytes?: number;
}

export interface InventorySummary {
  sourceFiles: number;
  entryPoints: number;
  otherUnits: number;
  byKind: Partial<Record<UnitKind, number>>;
  /** The largest top-level directories: path, source files, entry points. */
  directories: Array<{ path: string; files: number; entryPoints: number }>;
  /** What was left out of the inventory, and why. */
  skipped: { tooLarge: string[]; unreadable: number; walkLimit: boolean; unitLimit: boolean };
}

export interface Inventory { units: InventoryUnit[]; summary: InventorySummary }

export const SKIP_DIRS: ReadonlySet<string> = new Set([
  "node_modules", "vendor", "third_party", "third-party", "bower_components", "dist", "build", "out", "target", ".git", ".hg", ".svn", ".next", ".nuxt", ".svelte-kit", ".turbo", ".cache",
  "__pycache__", ".venv", "venv", "site-packages", ".tox", ".gradle", ".idea", ".vscode", "Pods", "coverage", ".terraform", "obj", ".mypy_cache", ".pytest_cache", ".yarn", ".pnpm-store",
]);
export const SKIP_FILE = /\.(?:min|bundle|generated)\.[a-z]+$|\.d\.ts$|\.pb\.go$|_pb2(?:_grpc)?\.py$|\.map$/i;
const MAX_LINE = 2000;

export const unitId = (kind: UnitKind, path: string, startLine: number | undefined, name: string | undefined): string =>
  createHash("sha256").update(`${kind}\u0000${path}\u0000${startLine ?? ""}\u0000${name ?? ""}`).digest("hex").slice(0, 16);

function readText(path: string, maxBytes: number): string | undefined {
  try {
    const buffer = Buffer.alloc(Math.min(maxBytes, 4096));
    const fd = openSync(path, "r");
    try {
      const read = readSync(fd, buffer, 0, buffer.length, 0);
      if (buffer.subarray(0, read).includes(0)) return undefined; // binary
    } finally { closeSync(fd); }
    return readFileSync(path, "utf8");
  } catch { return undefined; }
}

interface Candidate { path: string; size: number }

function walk(root: string, options: Required<Pick<InventoryOptions, "maxFiles" | "maxFileBytes">> & Pick<InventoryOptions, "only">, summary: InventorySummary): Candidate[] {
  const found: Candidate[] = [];
  const visit = (dir: string, rel: string, inherited: readonly IgnoreRule[]): void => {
    if (summary.skipped.walkLimit) return;
    let entries;
    try { entries = readdirSync(join(root, rel), { withFileTypes: true }); } catch { summary.skipped.unreadable++; return; }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    let rules = inherited;
    if (entries.some(entry => entry.name === ".gitignore" && entry.isFile())) {
      const text = readText(join(root, rel, ".gitignore"), 64 * 1024);
      if (text !== undefined) rules = [...inherited, ...parseGitignore(text.slice(0, 64 * 1024), rel)];
    }
    for (const entry of entries) {
      const path = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink()) continue; // never follow a link out of the folder
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name) || isIgnored(rules, path, true)) continue;
        visit(dir, path, rules);
        continue;
      }
      if (!entry.isFile()) continue;
      if (!SOURCE_EXTENSIONS.has(extname(entry.name).slice(1).toLowerCase()) || SKIP_FILE.test(entry.name) || isIgnored(rules, path, false)) continue;
      if (options.only && !options.only.has(path)) continue;
      if (found.length >= options.maxFiles) { summary.skipped.walkLimit = true; return; }
      let size = 0;
      try { size = lstatSync(join(root, path)).size; } catch { summary.skipped.unreadable++; continue; }
      found.push({ path, size });
    }
  };
  visit(root, "", []);
  return found;
}

/** The units of a folder: entry points first (by path and line), then the `other` units by directory. */
export function buildInventory(root: string, options: InventoryOptions = {}): Inventory {
  const maxFileBytes = options.maxFileBytes ?? 512 * 1024;
  const maxFiles = options.maxFiles ?? 20_000;
  const maxEntryUnits = options.maxEntryUnits ?? 3000;
  const otherChunk = Math.max(1, options.otherChunk ?? 25);
  let bytesLeft = options.maxTotalBytes ?? 96 * 1024 * 1024;
  const summary: InventorySummary = { sourceFiles: 0, entryPoints: 0, otherUnits: 0, byKind: {}, directories: [], skipped: { tooLarge: [], unreadable: 0, walkLimit: false, unitLimit: false } };
  const files = walk(root, { maxFiles, maxFileBytes, ...(options.only ? { only: options.only } : {}) }, summary);
  summary.sourceFiles = files.length;

  const entries: InventoryUnit[] = [];
  const unmatched: string[] = [];
  const dirStats = new Map<string, { files: number; entryPoints: number }>();
  const bump = (path: string, entry: boolean) => {
    const top = path.includes("/") ? path.split("/")[0]! : ".";
    const stat = dirStats.get(top) ?? { files: 0, entryPoints: 0 };
    if (entry) stat.entryPoints++; else stat.files++;
    dirStats.set(top, stat);
  };

  for (const file of files) {
    bump(file.path, false);
    const ext = extname(file.path).slice(1).toLowerCase();
    const found: InventoryUnit[] = [];
    if (file.size > maxFileBytes) { summary.skipped.tooLarge.push(file.path); unmatched.push(file.path); continue; }
    if (file.size > bytesLeft || entries.length >= maxEntryUnits) {
      if (entries.length >= maxEntryUnits) summary.skipped.unitLimit = true;
      unmatched.push(file.path);
      continue;
    }
    for (const matcher of PATH_MATCHERS) {
      if (matcher.pathRe.test(file.path)) found.push({ id: unitId(matcher.kind, file.path, undefined, matcher.name), kind: matcher.kind, path: file.path, name: matcher.name });
    }
    const text = readText(join(root, file.path), maxFileBytes);
    bytesLeft -= file.size;
    if (text === undefined) { summary.skipped.unreadable++; unmatched.push(file.path); continue; }
    const lines = text.split(/\r?\n/);
    const applicable = LINE_MATCHERS.filter(matcher => (!matcher.exts || matcher.exts.includes(ext)) && (!matcher.pathRe || matcher.pathRe.test(file.path)));
    const counts = new Map<(typeof applicable)[number], number>();
    const stopped = new Set<(typeof applicable)[number]>();
    const seen = new Set<string>();
    for (let index = 0; index < lines.length; index++) {
      const line = lines[index]!;
      if (line.length > MAX_LINE) continue;
      for (const matcher of applicable) {
        if (stopped.has(matcher)) continue;
        if (matcher.stopRe?.test(line)) { stopped.add(matcher); continue; }
        if ((counts.get(matcher) ?? 0) >= (matcher.perFile ?? 25)) continue;
        const match = matcher.lineRe.exec(line);
        if (!match) continue;
        let kind = matcher.kind;
        const name = matcher.name ? matcher.name(match) : match.slice(1).filter(Boolean).join(" ") || undefined;
        if (kind === "http-route" && name && WEBHOOK_NAME.test(name)) kind = "webhook";
        const key = `${kind}:${index + 1}`;
        if (seen.has(key)) continue;
        seen.add(key);
        counts.set(matcher, (counts.get(matcher) ?? 0) + 1);
        found.push({ id: unitId(kind, file.path, index + 1, name), kind, path: file.path, startLine: index + 1, ...(name ? { name: name.slice(0, 120) } : {}) });
      }
    }
    if (!found.length) { unmatched.push(file.path); continue; }
    for (const unit of found) { entries.push(unit); bump(file.path, true); }
  }

  const byPathLine = (a: InventoryUnit, b: InventoryUnit) => (a.path < b.path ? -1 : a.path > b.path ? 1 : (a.startLine ?? 0) - (b.startLine ?? 0) || (a.id < b.id ? -1 : 1));
  entries.sort(byPathLine);

  const byDir = new Map<string, string[]>();
  for (const path of unmatched) {
    const dir = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : ".";
    byDir.set(dir, [...(byDir.get(dir) ?? []), path]);
  }
  const others: InventoryUnit[] = [];
  for (const dir of [...byDir.keys()].sort()) {
    const group = byDir.get(dir)!.sort();
    for (let at = 0; at < group.length; at += otherChunk) {
      const chunk = group.slice(at, at + otherChunk);
      const part = Math.floor(at / otherChunk);
      const name = `${chunk.length} file${chunk.length === 1 ? "" : "s"}${group.length > otherChunk ? ` (part ${part + 1})` : ""}`;
      others.push({ id: unitId("other", dir, undefined, `${part}:${chunk[0]}`), kind: "other", path: dir, name, files: chunk });
    }
  }

  for (const unit of entries) summary.byKind[unit.kind] = (summary.byKind[unit.kind] ?? 0) + 1;
  summary.entryPoints = entries.length;
  summary.otherUnits = others.length;
  if (others.length) summary.byKind.other = others.length;
  summary.directories = [...dirStats.entries()].map(([path, stat]) => ({ path, files: stat.files, entryPoints: stat.entryPoints })).sort((a, b) => b.files - a.files || (a.path < b.path ? -1 : 1)).slice(0, 20);
  summary.skipped.tooLarge = summary.skipped.tooLarge.slice(0, 50);
  return { units: [...entries, ...others], summary };
}

export interface Batch {
  index: number;
  units: InventoryUnit[];
  /** The build module (a directory relative to the folder) every unit of this batch sits in, when the plan was made by module. */
  module?: string;
  /** CODEOWNERS labels used only to group work, never to omit a unit. */
  owners?: string[];
}

export interface PlanBatchOptions {
  /** Says which shard (for Java, a build module) a unit belongs to. A batch never mixes shards. */
  shardOf?: (unit: InventoryUnit) => string | undefined;
  ownersOf?: (unit: InventoryUnit) => readonly string[];
}

type RawBatch = { units: InventoryUnit[]; module?: string; owners?: string[] };
const numbered = (batches: RawBatch[]): Batch[] => batches.map((batch, index) => ({ index, ...batch }));

/**
 * Split units into batches: entry points first, files kept together, at most `size` entry-point units in a batch. `other`
 * units follow, grouped so a batch covers at most `size` of them and about 40 files. With `shardOf`, each shard is planned on
 * its own, in shard order, so a batch stays inside one shard; with one shard or none the result is the plain plan.
 */
export function planBatches(units: readonly InventoryUnit[], size = 8, options: PlanBatchOptions = {}): Batch[] {
  if (!options.shardOf && !options.ownersOf) return numbered(planGroup(units, size).map(group => ({ units: group })));
  const shards = new Map<string, { module: string; owners: string[]; units: InventoryUnit[] }>();
  for (const unit of units) {
    const module = options.shardOf?.(unit) ?? "";
    const owners = [...new Set(options.ownersOf?.(unit) ?? [])].sort();
    const key = JSON.stringify([module, owners]);
    const shard = shards.get(key);
    if (shard) shard.units.push(unit); else shards.set(key, { module, owners, units: [unit] });
  }
  const out: RawBatch[] = [];
  for (const key of [...shards.keys()].sort()) {
    const shard = shards.get(key)!;
    for (const group of planGroup(shard.units, size)) out.push({ units: group,
      ...(shard.module && (shards.size > 1 || shard.module !== ".") ? { module: shard.module } : {}),
      ...(shard.owners.length ? { owners: shard.owners } : {}),
    });
  }
  return numbered(out);
}

function planGroup(units: readonly InventoryUnit[], size: number): InventoryUnit[][] {
  const limit = Math.max(1, Math.floor(size));
  const batches: InventoryUnit[][] = [];
  let current: InventoryUnit[] = [];
  let currentFile: string | undefined;
  const entry = units.filter(unit => isEntryPointKind(unit.kind));
  for (const unit of entry) {
    // Start a new batch when this one is full, except that a file's units stay together while they fit.
    if (current.length >= limit && (unit.path !== currentFile || current.length >= limit * 2)) { batches.push(current); current = []; }
    current.push(unit);
    currentFile = unit.path;
  }
  if (current.length) batches.push(current);
  current = [];
  let files = 0;
  for (const unit of units.filter(item => !isEntryPointKind(item.kind))) {
    const count = unit.files?.length ?? 1;
    if (current.length && (current.length >= limit || files + count > 40)) { batches.push(current); current = []; files = 0; }
    current.push(unit);
    files += count;
  }
  if (current.length) batches.push(current);
  return batches;
}

/** A short text for a batch prompt: counts by kind and the biggest directories. */
export function inventorySummaryText(summary: InventorySummary): string {
  const kinds = UNIT_KINDS.filter(kind => summary.byKind[kind]).map(kind => `${summary.byKind[kind]} ${kind}`).join(", ");
  const dirs = summary.directories.slice(0, 12).map(dir => `${dir.path} (${dir.files} files, ${dir.entryPoints} entry points)`).join("; ");
  return `${summary.sourceFiles} source files; ${summary.entryPoints} entry points${kinds ? ` and groups of other files (${kinds})` : ""}. Directories: ${dirs || "none"}.`;
}
