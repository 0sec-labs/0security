/**
 * Tree-wide candidate sites for a variant hunt, computed in code before any model runs.
 *
 * A model asked to "find the same bug elsewhere" searches near the fix and stops early (docs/design/hard-benchmark.md).
 * So the list of sites is built here, deterministically, from the recorded root cause and the code index, and the model
 * only judges each one. Three steps:
 *
 *  1. Sink shape. The names the root cause gives for the unsafe call, checked against the calls that exist in the tree,
 *     plus the sibling APIs (same receiver kind, same verb family) and sibling operations (read, list, update, delete).
 *  2. Guard evidence. Words taken from the missing guard are looked for in the body of every function on the way from an
 *     entry point to the sink. A site with no such word ranks first; a site with one stays in the list, ranked lower, so
 *     the model has to cite the guard.
 *  3. Grouping. Sites are one per enclosing function, so a helper shared by many callers is one item that lists them.
 *
 * Authorization-like classes also add the routes the Foxguard graph marks `missingGuard` (it reaches a data sink with no
 * auth signal). Repository text is untrusted: a candidate carries a path, a line, a symbol name and a route, each cleaned
 * and restricted to a plain character set, plus a reason written here. It never carries file content.
 */
import { readFileSync, readdirSync, lstatSync } from "node:fs";
import { extname, join } from "node:path";
import { SKIP_DIRS, SKIP_FILE } from "../inventory/index.js";
import { SOURCE_EXTENSIONS } from "../inventory/matchers.js";
import { getIndex } from "./build.js";
import { cleanText } from "./sanitize.js";
import { AUTH_NAME } from "./sinks.js";
import type { CodeIndex, IndexCall, IndexSymbol, SinkCategory } from "./types.js";

export interface RootCauseLike {
  bugClass: string;
  unsafePattern: { sink: string; source: string };
  missingGuard: string;
  designOrigin: string;
}

export interface CandidateSeed { path?: string; startLine?: number; endLine?: number }

export interface VariantCandidate {
  /** `C1`, `C2`, ... in rank order. */
  id: string;
  file: string;
  line: number;
  /** The function the site is in; empty for a text-search hit outside any indexed function. */
  symbol: string;
  /** Routes and entry points that reach the site, at most six. */
  entries: string[];
  entriesOmitted: number;
  /** Why this is a candidate, in words written by this module. */
  why: string;
  /** Present when a guard-like word was found in a function on the path: the model must check it and cite it. */
  guardHint?: string;
  rank: number;
}

export interface CandidateList {
  candidates: VariantCandidate[];
  /** Sites found before the cap. */
  total: number;
  omitted: number;
  /** `foxguard` or `builtin` or `text`. */
  engine: string;
  strategy: "authorization" | "sink-shape";
  sinkNames: string[];
  guardWords: string[];
  notes: string[];
}

export const DEFAULT_CANDIDATE_LIMIT = 60;
const MAX_ENTRIES = 6;
const MAX_HOPS = 4;
const TEXT_SCAN_MAX_FILES = 4000;
const TEXT_SCAN_MAX_BYTES = 400 * 1024;

const IDENT = /[A-Za-z_$][\w$]*/g;
const SAFE_NAME = /^[\w$.<>#:/\-@ {}[\]*]+$/;
const AUTHZ_CLASS = /author|access.control|ownership|tenant|idor|permission|privilege|isolation|scop|missing (auth|guard|check)|cross.org|bola|object.level/i;
const STOP_WORDS = new Set(["the", "and", "for", "from", "with", "that", "this", "not", "req", "res", "request", "response", "user", "users", "id", "ids", "by", "get", "set", "find", "check", "call", "caller", "callers", "any", "data", "value", "input", "param", "params", "body", "query", "record", "records", "missing", "must", "does", "only", "same", "all", "own", "when", "before", "after", "should", "never", "instead", "using", "used", "load", "loaded", "lookup", "route", "handler", "function", "method", "assert", "ensure", "scoped", "scope", "access", "authorization", "ownership", "comparison", "compare"]);
const READ_VERBS = ["find", "get", "load", "fetch", "read", "lookup", "list", "all", "search", "export", "select", "query", "by"];
const WRITE_VERBS = ["save", "update", "delete", "remove", "patch", "put", "set", "upsert", "insert", "create", "cancel", "approve"];
const RECEIVER_SUFFIX = /(Repo|Repository|Store|Dao|DAO|Model|Collection|Service|Manager|Client|Loader)$/;

/** Plain identifiers in a model-written string. Used only as search keys, never shown as instructions. */
export function identifiersIn(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(IDENT)) if (m[0].length >= 3 && m[0].length <= 60 && !out.includes(m[0])) out.push(m[0]);
  return out;
}

function camelWords(identifier: string): string[] {
  return identifier.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/[_$]+/g, " ").toLowerCase().split(" ").filter(Boolean);
}

/** The distinctive words of the guard: `orgId` and `findForOrg` give `org`. Plain English words and generic verbs are dropped. */
export function guardWordsOf(rootCause: RootCauseLike): string[] {
  const words: string[] = [];
  const add = (w: string) => { if (w.length >= 3 && !STOP_WORDS.has(w) && !READ_VERBS.includes(w) && !WRITE_VERBS.includes(w) && !words.includes(w)) words.push(w); };
  // Words of a receiver (`invoiceRepo` in `invoiceRepo.findForOrg(...)`) name the entity, not the guard.
  const entity = new Set<string>(["repo", "repository", "store", "dao", "model", "collection", "service", "manager", "client", "loader", "req", "res", "ctx", "this", "self"]);
  for (const m of `${rootCause.missingGuard} ${rootCause.unsafePattern.sink} ${rootCause.unsafePattern.source}`.matchAll(/([A-Za-z_$][\w$]*)\s*\./g)) for (const w of camelWords(m[1]!)) entity.add(w);
  const add2 = add;
  for (const id of identifiersIn(`${rootCause.missingGuard} ${rootCause.unsafePattern.source}`)) {
    // Only code-like names: a camelCase or snake_case token, or one that ends in Id. Prose words are not guards.
    if (/[a-z][A-Z]|_|\d/.test(id) || /[a-z]Id$/.test(id)) for (const w of camelWords(id)) if (!entity.has(w)) add2(w);
  }
  return words.slice(0, 8);
}

/** The called names the root cause gives for its sink: `invoiceRepo.findById(id)` gives `findById`. */
export function sinkNamesOf(rootCause: RootCauseLike): { names: string[]; receivers: string[] } {
  const names: string[] = [];
  const receivers: string[] = [];
  const text = rootCause.unsafePattern.sink;
  for (const m of text.matchAll(/([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(/g)) {
    const parts = m[1]!.split(".");
    const name = parts[parts.length - 1]!;
    if (name.length >= 3 && !names.includes(name)) names.push(name);
    if (parts.length >= 2) { const r = parts[parts.length - 2]!; if (!receivers.includes(r)) receivers.push(r); }
  }
  if (!names.length) {
    // `unsafe_pattern.sink` may be prose around a bare name: take dotted pairs, then code-like words.
    for (const m of text.matchAll(/([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)/g)) {
      if (!names.includes(m[2]!)) names.push(m[2]!);
      if (!receivers.includes(m[1]!)) receivers.push(m[1]!);
    }
    for (const id of identifiersIn(text)) if (/[a-z][A-Z]/.test(id) && !names.includes(id)) names.push(id);
  }
  return { names: names.slice(0, 8), receivers: receivers.slice(0, 4) };
}

/** A call whose own name carries a guard word (`findForOrg`) is scoped by construction: it is not a candidate. */
const nameCarriesGuard = (name: string, words: readonly string[]): boolean => { const w = camelWords(name); return words.some((x) => w.includes(x)); };
const verbOf = (name: string): string => /^[a-z]+/.exec(name)?.[0] ?? name;
const receiverOf = (call: IndexCall): string => { const parts = call.text.replace(/\s+/g, "").split("."); return parts.length >= 2 ? parts[parts.length - 2]!.replace(/\(.*$/, "") : ""; };
const suffixOf = (receiver: string): string => RECEIVER_SUFFIX.exec(receiver)?.[1] ?? "";
const isTest = (file: string): boolean => /(^|\/)(tests?|__tests__|spec|e2e|fixtures?|mocks?)(\/|$)|\.(test|spec)\.\w+$/i.test(file);

/** A name that is safe to put in a prompt: plain characters only, cleaned and short. */
const safe = (text: string, max = 80): string => { const t = cleanText(text, max); return SAFE_NAME.test(t) ? t : t.replace(/[^\w$.<>#:/\-@ {}[\]*]/g, "?"); };

class Graph {
  readonly byId = new Map<string, IndexSymbol>();
  readonly callersByName = new Map<string, IndexSymbol[]>();
  readonly routesByHandler = new Map<string, Array<{ label: string }>>();
  private readonly byName = new Map<string, IndexSymbol[]>();
  constructor(readonly index: CodeIndex) {
    for (const s of index.symbols) {
      this.byId.set(s.id, s);
      if (s.kind !== "module" && s.kind !== "route-handler") { const l = this.byName.get(s.name); if (l) l.push(s); else this.byName.set(s.name, [s]); }
    }
    for (const c of index.calls) {
      const from = this.byId.get(c.from);
      if (!from) continue;
      const l = this.callersByName.get(c.name);
      if (l) { if (!l.includes(from)) l.push(from); } else this.callersByName.set(c.name, [from]);
    }
    for (const r of index.routes) {
      const label = `${safe(r.method, 10)} ${safe(r.path, 80)}`;
      const l = this.routesByHandler.get(r.handler);
      if (l) l.push({ label }); else this.routesByHandler.set(r.handler, [{ label }]);
    }
  }
  /** Symbols that call `sym` (by name join: an over-approximation when names repeat), excluding module bodies. */
  callersOf(sym: IndexSymbol): IndexSymbol[] {
    if (sym.kind === "route-handler" || sym.kind === "module") return [];
    const list = this.callersByName.get(sym.name) ?? [];
    return list.length > 12 ? [] : list.filter((s) => s.id !== sym.id);
  }
}

interface PathInfo { entries: string[]; entriesOmitted: number; bodies: IndexSymbol[] }

/** Reverse walk from the sink function to routes and to functions that nothing else calls (jobs, resolvers, message handlers). */
function pathInfo(graph: Graph, start: IndexSymbol): PathInfo {
  const bodies: IndexSymbol[] = [start];
  const entries: string[] = [];
  const seen = new Set<string>([start.id]);
  let frontier = [start];
  const addEntry = (label: string) => { if (!entries.includes(label)) entries.push(label); };
  for (let hop = 0; hop <= MAX_HOPS && frontier.length; hop++) {
    const next: IndexSymbol[] = [];
    for (const sym of frontier) {
      for (const r of graph.routesByHandler.get(sym.id) ?? []) addEntry(r.label);
      const callers = graph.callersOf(sym);
      if (!callers.length && !(graph.routesByHandler.get(sym.id)?.length) && sym.kind !== "module") addEntry(`entry ${safe(sym.qualified, 60)} (${safe(sym.file, 60)})`);
      for (const c of callers) {
        if (seen.has(c.id)) continue;
        seen.add(c.id);
        if (c.kind !== "module") bodies.push(c);
        next.push(c);
      }
    }
    frontier = next;
  }
  return { entries: entries.slice(0, 200), entriesOmitted: 0, bodies };
}

const fileCache = new Map<string, string[]>();
function linesOf(root: string, file: string): string[] {
  const key = `${root}\0${file}`;
  let l = fileCache.get(key);
  if (!l) { try { l = readFileSync(join(root, file), "utf8").split("\n"); } catch { l = []; } fileCache.set(key, l); if (fileCache.size > 400) fileCache.delete(fileCache.keys().next().value as string); }
  return l;
}

/** First guard-like word found in the body of one of the functions on the path, as `word in symbol`. Reads the code, returns names only. */
function guardEvidence(root: string, bodies: readonly IndexSymbol[], words: readonly string[], middleware: readonly string[]): string | undefined {
  if (!words.length) return undefined;
  for (const m of middleware) if (words.some((w) => camelWords(m).includes(w)) || AUTH_NAME.test(m)) return `middleware ${safe(m, 40)}`;
  for (const sym of bodies) {
    const lines = linesOf(root, sym.file).slice(sym.line - 1, Math.min(sym.endLine, sym.line + 400));
    const body = lines.join("\n");
    for (const id of body.match(IDENT) ?? []) {
      const w = camelWords(id);
      const hit = words.find((x) => w.includes(x));
      if (hit) return `word "${hit}" appears in ${safe(sym.qualified, 60)}`;
    }
  }
  return undefined;
}

/** Walk the source files for `name(` when the index has nothing: any language, no symbols, no routes. */
function textSites(root: string, names: readonly string[]): Array<{ file: string; line: number; name: string }> {
  const out: Array<{ file: string; line: number; name: string }> = [];
  if (!names.length) return out;
  const re = new RegExp(`\\b(${names.map((n) => n.replace(/[$]/g, "\\$")).join("|")})\\s*\\(`);
  let files = 0;
  const visit = (rel: string): void => {
    let entries; try { entries = readdirSync(join(root, rel), { withFileTypes: true }); } catch { return; }
    entries.sort((a, b) => (a.name < b.name ? -1 : 1));
    for (const e of entries) {
      const path = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) visit(path); continue; }
      if (!e.isFile() || files >= TEXT_SCAN_MAX_FILES || isTest(path) || SKIP_FILE.test(e.name) || !SOURCE_EXTENSIONS.has(extname(e.name).slice(1).toLowerCase())) continue;
      try { if (lstatSync(join(root, path)).size > TEXT_SCAN_MAX_BYTES) continue; } catch { continue; }
      files++;
      const lines = linesOf(root, path);
      for (let i = 0; i < lines.length; i++) { const m = re.exec(lines[i]!); if (m) out.push({ file: path, line: i + 1, name: m[1]! }); }
    }
  };
  visit("");
  return out;
}

interface Hit { sym?: IndexSymbol; file: string; line: number; names: string[]; tier: number; why: string[]; routeFlag?: boolean }

export interface CandidateOptions { limit?: number; index?: CodeIndex; foxguard?: boolean }

/** The candidate list for one seed and root cause. Never throws on a bad tree: an empty list comes back with a note. */
export async function variantCandidates(root: string, seed: CandidateSeed, rootCause: RootCauseLike, options: CandidateOptions = {}): Promise<CandidateList> {
  const limit = options.limit ?? DEFAULT_CANDIDATE_LIMIT;
  const notes: string[] = [];
  const strategy = AUTHZ_CLASS.test(`${rootCause.bugClass} ${rootCause.missingGuard}`) ? "authorization" as const : "sink-shape" as const;
  const { names: sinkNames, receivers } = sinkNamesOf(rootCause);
  const guardWords = guardWordsOf(rootCause);
  let index: CodeIndex | undefined = options.index;
  try { index ??= (await getIndex(root, undefined, { ...(options.foxguard === false ? { foxguard: false } : {}), missingGuard: true })).index; } catch { notes.push("the code index could not be built"); }
  const empty = (engine: string): CandidateList => ({ candidates: [], total: 0, omitted: 0, engine, strategy, sinkNames, guardWords, notes });
  if (!index) return empty("none");
  const graph = new Graph(index);
  fileCache.clear();

  // Names that exist as calls somewhere in the tree. A name the root cause gives that is never called is dropped.
  const calledNames = new Set(index.calls.map((c) => c.name));
  let names = sinkNames.filter((n) => calledNames.has(n));
  if (!names.length && seed.path) {
    // Fall back to the calls that sit in the seed's own lines and are sinks.
    const inSeed = index.calls.filter((c) => c.file === seed.path && c.line >= (seed.startLine ?? 1) - 1 && c.line <= (seed.endLine ?? seed.startLine ?? 1) + 1 && c.sink);
    names = [...new Set(inSeed.map((c) => c.name))];
    if (names.length) notes.push("the sink names were taken from the sink calls on the seed's own lines");
  }
  if (!names.length) notes.push("none of the sink names in the root cause is called anywhere in the tree");

  const seedSuffixes = new Set([...receivers.map(suffixOf), ...index.calls.filter((c) => names.includes(c.name)).map((c) => suffixOf(receiverOf(c)))].filter(Boolean));
  const seedVerbs = new Set(names.map(verbOf));
  const seedCategories = new Set<SinkCategory>(index.calls.filter((c) => names.includes(c.name) && c.sink).map((c) => c.sink!.category));
  const tierOf = (c: IndexCall): { tier: number; why: string } | undefined => {
    if (strategy === "authorization" && !names.includes(c.name) && nameCarriesGuard(c.name, guardWords)) return undefined;
    if (names.includes(c.name)) return { tier: 3, why: `calls ${safe(c.name, 40)}, the unsafe call in the root cause` };
    if (strategy === "sink-shape" && c.sink && seedCategories.has(c.sink.category)) return { tier: 2, why: `calls a ${c.sink.category} sink (${safe(c.name, 40)}) like the unsafe call` };
    if (strategy === "authorization") {
      const suffix = suffixOf(receiverOf(c));
      if (suffix && seedSuffixes.has(suffix) && c.name.length >= 3) {
        const v = verbOf(c.name);
        if (seedVerbs.has(v)) return { tier: 2, why: `calls ${safe(c.name, 40)} on a ${suffix}, a sibling of the unsafe lookup` };
        if (READ_VERBS.includes(v) || WRITE_VERBS.includes(v)) return { tier: 1, why: `${WRITE_VERBS.includes(v) ? "writes" : "reads"} through ${safe(c.name, 40)} on a ${suffix}, a sibling operation` };
      }
    }
    return undefined;
  };

  const hits = new Map<string, Hit>();
  const addHit = (key: string, file: string, line: number, sym: IndexSymbol | undefined, name: string, tier: number, why: string, routeFlag = false): void => {
    const h = hits.get(key);
    if (h) { if (!h.names.includes(name)) h.names.push(name); h.tier = Math.max(h.tier, tier); if (!h.why.includes(why) && h.why.length < 3) h.why.push(why); h.routeFlag ||= routeFlag; if (line < h.line) h.line = line; return; }
    hits.set(key, { ...(sym ? { sym } : {}), file, line, names: [name], tier, why: [why], routeFlag });
  };

  for (const c of index.calls) {
    if (isTest(c.file)) continue;
    if (seed.path && c.file === seed.path && seed.startLine && c.line >= seed.startLine && c.line <= (seed.endLine ?? seed.startLine)) continue;
    const t = tierOf(c);
    if (!t) continue;
    const sym = graph.byId.get(c.from);
    addHit(sym && sym.kind !== "module" ? sym.id : `${c.file}:${c.line}`, c.file, c.line, sym && sym.kind !== "module" ? sym : undefined, c.name, t.tier, t.why);
  }

  // Authorization classes: the routes the Foxguard graph marks as reaching a data sink with no auth signal.
  if (strategy === "authorization") {
    for (const r of index.routes) {
      if (r.missingGuard !== true || isTest(r.file)) continue;
      const sym = graph.byId.get(r.handler);
      addHit(sym?.id ?? `${r.file}:${r.line}`, sym?.file ?? r.file, sym?.line ?? r.line, sym, "route", 4, `the Foxguard graph marks route ${safe(r.method, 10)} ${safe(r.path, 80)} as reaching a data sink with no auth signal`, true);
    }
  }

  let engine: string = index.engine ?? "builtin";
  const searchNames = names.length ? names : sinkNames;
  if (!hits.size && searchNames.length) {
    // The index saw no such call: search the text of every source file (this reaches languages the index cannot parse).
    for (const s of textSites(root, searchNames)) {
      if (seed.path && s.file === seed.path && seed.startLine && s.line >= seed.startLine && s.line <= (seed.endLine ?? seed.startLine)) continue;
      addHit(`${s.file}:${s.line}`, s.file, s.line, undefined, s.name, 3, `text search: ${safe(s.name, 40)}( is called here`);
    }
    if (hits.size) { engine = "text"; notes.push("the code index had no matching call; the sites come from a text search"); }
  }

  const scored: Array<VariantCandidate & { sort: number }> = [];
  for (const h of hits.values()) {
    const info = h.sym ? pathInfo(graph, h.sym) : { entries: [], entriesOmitted: 0, bodies: [] as IndexSymbol[] };
    const routeMiddleware = h.sym ? (index.routes.filter((r) => r.handler === h.sym!.id).flatMap((r) => r.middleware)) : [];
    const guardHint = strategy === "authorization" && !h.routeFlag ? guardEvidence(root, info.bodies, guardWords, routeMiddleware) : strategy === "sink-shape" ? guardEvidence(root, info.bodies, guardWords, []) : undefined;
    const reachable = info.entries.length > 0;
    const sort = h.tier * 100 + (guardHint ? 0 : 50) + (reachable ? 10 : 0) + (h.routeFlag ? 20 : 0);
    const entries = info.entries.slice(0, MAX_ENTRIES);
    const why = `${h.why.join("; ")}${h.names.length > 1 ? ` (${h.names.slice(0, 4).map((n) => safe(n, 30)).join(", ")})` : ""}${guardHint ? "" : strategy === "authorization" ? "; no word of the missing guard appears on the path" : ""}`;
    scored.push({ id: "", file: safe(h.file, 200), line: h.line, symbol: h.sym ? safe(h.sym.qualified, 80) : "", entries, entriesOmitted: Math.max(0, info.entries.length - entries.length), why, ...(guardHint ? { guardHint } : {}), rank: sort, sort });
  }
  scored.sort((a, b) => b.sort - a.sort || (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line));
  const kept = scored.slice(0, limit).map(({ sort: _sort, ...c }, i) => ({ ...c, id: `C${i + 1}`, rank: i + 1 }));
  fileCache.clear();
  return { candidates: kept, total: scored.length, omitted: Math.max(0, scored.length - kept.length), engine, strategy, sinkNames: names, guardWords, notes };
}
