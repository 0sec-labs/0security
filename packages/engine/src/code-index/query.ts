import { AUTH_NAME } from "./sinks.js";
import type { CodeIndex, IndexCall, IndexRoute, IndexSymbol, SinkCategory } from "./types.js";

const NODE_BUDGET = 20_000;

const NAME_ONLY = /^[\w$.<>#:/\- ]+$/;

export interface Site { symbol: string; file: string; line: number }

function siteOf(s: IndexSymbol, line = s.line): Site { return { symbol: s.qualified, file: s.file, line } }

/** Append without copying: a large Java tree has thousands of symbols and calls under one name. */
function push<T>(map: Map<string, T[]>, key: string, value: T): void {
  const list = map.get(key);
  if (list) list.push(value); else map.set(key, [value]);
}

class Lookup {
  readonly byId = new Map<string, IndexSymbol>();
  readonly byName = new Map<string, IndexSymbol[]>();
  readonly callsFrom = new Map<string, IndexCall[]>();
  readonly callsTo = new Map<string, IndexCall[]>();
  readonly routesByHandler = new Map<string, IndexRoute[]>();
  constructor(readonly index: CodeIndex) {
    for (const s of index.symbols) {
      this.byId.set(s.id, s);
      if (s.kind !== "module" && s.kind !== "route-handler") push(this.byName, s.name, s);
    }
    for (const c of index.calls) {
      push(this.callsFrom, c.from, c);
      push(this.callsTo, c.name, c);
    }
    for (const r of index.routes) push(this.routesByHandler, r.handler, r);
  }
  /** A Java call with a known receiver type reaches that class (exact), else a class named like it (`UserService`, `UserServiceImpl`), else every symbol of the name. */
  private narrowByReceiver(all: IndexSymbol[], call: IndexCall): IndexSymbol[] {
    const t = call.receiverType;
    if (!t || all.length <= 1) return all;
    const key = `${call.name}\0${t}`;
    let hit = this.narrowed.get(key);
    if (!hit) { hit = this.narrow(all, t); this.narrowed.set(key, hit); }
    return hit;
  }
  private readonly narrowed = new Map<string, IndexSymbol[]>();
  private narrow(all: IndexSymbol[], t: string): IndexSymbol[] {
    const exact = all.filter((s) => classOf(s) === t);
    if (exact.length > 0) return exact;
    if (t.length >= 4) {
      const fuzzy = all.filter((s) => { const c = classOf(s); return c.startsWith(t) || c.endsWith(t); });
      if (fuzzy.length > 0) return fuzzy;
    }
    return all;
  }
  /** Symbols a call can reach: every symbol of that name (an over-approximation when names repeat). */
  targets(call: IndexCall): IndexSymbol[] {
    const all = this.narrowByReceiver(this.byName.get(call.name) ?? [], call);
    if (all.length <= 1) return all;
    const sameFile = all.filter((s) => s.file === call.file);
    if (sameFile.length > 0 && !call.text.includes(".")) return sameFile;
    // `this.x()` or `obj.x()`: prefer methods for a dotted call, functions for a bare call.
    const wantMethod = call.text.includes(".");
    const narrowed = all.filter((s) => (s.kind === "method") === wantMethod);
    return narrowed.length > 0 ? narrowed : all;
  }
}

/** AUTH_NAME on a name, remembered: a large tree repeats the same few thousand names millions of times. */
const authMemo = new Map<string, boolean>();
function authName(name: string): boolean {
  let v = authMemo.get(name);
  if (v === undefined) { v = AUTH_NAME.test(name); if (authMemo.size < 200_000) authMemo.set(name, v); }
  return v;
}

/** The class a method symbol belongs to: `A.B.m` gives `B`. */
function classOf(s: IndexSymbol): string { const parts = s.qualified.split("."); return parts.length >= 2 ? parts[parts.length - 2]! : ""; }

const lookups = new WeakMap<CodeIndex, Lookup>();
function lookupOf(index: CodeIndex): Lookup {
  let l = lookups.get(index);
  if (!l) { l = new Lookup(index); lookups.set(index, l); }
  return l;
}

export function resolveSymbol(index: CodeIndex, ref: string): IndexSymbol[] {
  if (!NAME_ONLY.test(ref)) return [];
  const exact = index.symbols.filter((s) => s.id === ref);
  if (exact.length) return exact;
  const colon = ref.lastIndexOf(":");
  const file = colon > 0 ? ref.slice(0, colon) : undefined;
  const name = colon > 0 ? ref.slice(colon + 1) : ref;
  return index.symbols.filter((s) => (file === undefined || s.file === file || s.file.endsWith(`/${file}`)) && (s.qualified === name || (s.name === name && s.kind !== "module" && s.kind !== "route-handler")));
}

export interface Hit extends Site { depth: number; via?: string }

export interface CallersResult { targets: Site[]; callers: Hit[]; entryRoutes: Array<{ route: string; file: string; line: number; depth: number; via: string }>; ambiguous: boolean; truncated: boolean }

export function callersOf(index: CodeIndex, ref: string, depth: number, limit: number): CallersResult | { error: string } {
  const lk = lookupOf(index);
  const targets = resolveSymbol(index, ref);
  if (targets.length === 0) return { error: `No symbol named "${ref}" in the index. Search with rg, or check the spelling (use Class.method or path:name).` };
  const callers: Hit[] = [];
  const entryRoutes: CallersResult["entryRoutes"] = [];
  const seen = new Set<string>(targets.map((t) => t.id));
  let frontier = targets.map((t) => ({ sym: t, via: t.qualified }));
  let truncated = false;
  // Routes that run a target directly.
  for (const t of targets) for (const r of lk.routesByHandler.get(t.id) ?? []) entryRoutes.push({ route: `${r.method} ${r.path}`, file: r.file, line: r.line, depth: 0, via: t.qualified });
  for (let d = 1; d <= depth && frontier.length > 0; d++) {
    const next: typeof frontier = [];
    for (const { sym } of frontier) {
      for (const call of lk.callsTo.get(sym.name) ?? []) {
        if (!lk.targets(call).some((t) => t.id === sym.id)) continue;
        const from = lk.byId.get(call.from);
        if (!from) continue;
        const key = `${from.id}>${call.line}`;
        if (seen.has(key)) continue;
        seen.add(key);
        if (callers.length >= limit) { truncated = true; break; }
        callers.push({ ...siteOf(from, call.line), depth: d, via: sym.qualified });
        for (const r of lk.routesByHandler.get(from.id) ?? []) entryRoutes.push({ route: `${r.method} ${r.path}`, file: r.file, line: r.line, depth: d, via: from.qualified });
        if (!seen.has(from.id)) { seen.add(from.id); next.push({ sym: from, via: from.qualified }); }
      }
    }
    frontier = next;
  }
  return { targets: targets.map((t) => siteOf(t)), callers, entryRoutes, ambiguous: targets.length > 1, truncated };
}

export interface CalleeHit extends Site { depth: number; call: string; from: string; resolved: string[]; sink?: { category: SinkCategory } }

export function calleesOf(index: CodeIndex, ref: string, depth: number, limit: number): { targets: Site[]; callees: CalleeHit[]; truncated: boolean } | { error: string } {
  const lk = lookupOf(index);
  const targets = resolveSymbol(index, ref);
  if (targets.length === 0) return { error: `No symbol named "${ref}" in the index. Search with rg, or check the spelling (use Class.method or path:name).` };
  const out: CalleeHit[] = [];
  const seen = new Set<string>(targets.map((t) => t.id));
  let frontier = [...targets];
  let truncated = false;
  for (let d = 1; d <= depth && frontier.length > 0; d++) {
    const next: IndexSymbol[] = [];
    for (const sym of frontier) {
      for (const call of lk.callsFrom.get(sym.id) ?? []) {
        if (out.length >= limit) { truncated = true; break; }
        const resolved = lk.targets(call);
        out.push({ symbol: call.text, file: call.file, line: call.line, depth: d, call: call.text, from: sym.qualified, resolved: resolved.map((r) => `${r.file}:${r.line} ${r.qualified}`), ...(call.sink ? { sink: { category: call.sink.category } } : {}) });
        for (const r of resolved) if (!seen.has(r.id)) { seen.add(r.id); next.push(r); }
      }
    }
    frontier = next;
  }
  return { targets: targets.map((t) => siteOf(t)), callees: out, truncated };
}

export interface AuthSignal { name: string; where: "middleware" | "handler" | "callee"; file?: string; line?: number }
export interface RouteView {
  method: string; path: string; file: string; line: number; handler: string; framework: string;
  middleware: string[]; auth_signals: AuthSignal[]; auth_signal_missing: boolean; sinks_reachable: SinkCategory[];
}

/** Auth-like names on a route: its middleware and the calls its handler makes within `depth` hops. */
function signalsFor(lk: Lookup, route: IndexRoute, depth: number): { signals: AuthSignal[]; sinks: Set<SinkCategory> } {
  const signals: AuthSignal[] = route.middleware.filter((m) => authName(m)).map((name) => ({ name, where: "middleware" as const }));
  // Guard annotations the extractor recognised (for example @Secured), which the name pattern alone would miss.
  for (const name of route.authSignals ?? []) if (!signals.some((s) => s.name === name)) signals.push({ name, where: "middleware" });
  const sinks = new Set<SinkCategory>();
  const start = lk.byId.get(route.handler);
  if (!start) return { signals, sinks };
  const seen = new Set([start.id]);
  let frontier = [start];
  for (let d = 0; d < depth && frontier.length > 0; d++) {
    const next: IndexSymbol[] = [];
    for (const sym of frontier) for (const call of lk.callsFrom.get(sym.id) ?? []) {
      if (call.sink) sinks.add(call.sink.category);
      if (call.auth || authName(call.name)) signals.push({ name: call.text, where: d === 0 ? "handler" : "callee", file: call.file, line: call.line });
      for (const t of lk.targets(call)) if (!seen.has(t.id)) { seen.add(t.id); next.push(t); }
    }
    frontier = next;
  }
  return { signals, sinks };
}

export function routesOf(index: CodeIndex, filter: { pathContains?: string; method?: string; file?: string; withoutAuthSignal?: boolean }, limit: number): { routes: RouteView[]; total: number; truncated: boolean } {
  const lk = lookupOf(index);
  const all = index.routes
    .filter((r) => (!filter.pathContains || r.path.includes(filter.pathContains)) && (!filter.method || r.method === filter.method.toUpperCase() || r.method === "ANY") && (!filter.file || r.file.includes(filter.file)))
    .map((r): RouteView => {
      const { signals, sinks } = signalsFor(lk, r, 3);
      const handler = lk.byId.get(r.handler);
      return { method: r.method, path: r.path, file: r.file, line: r.line, handler: handler ? `${handler.file}:${handler.line} ${handler.qualified}` : r.handler, framework: r.framework, middleware: r.middleware, auth_signals: signals, auth_signal_missing: signals.length === 0, sinks_reachable: [...sinks] };
    })
    .filter((r) => !filter.withoutAuthSignal || r.auth_signal_missing);
  return { routes: all.slice(0, limit), total: all.length, truncated: all.length > limit };
}

export interface TracePath { hops: Site[]; sink: { category: SinkCategory; call: string; file: string; line: number }; auth_signals_on_path: string[] }

export function traceToSink(index: CodeIndex, from: string, sinkFilter: SinkCategory | undefined, maxDepth: number, maxPaths: number): { start: string[]; paths: TracePath[]; truncated: boolean } | { error: string } {
  const lk = lookupOf(index);
  const routeMatch = /^([A-Za-z]+)\s+(\/\S*|\*)$/.exec(from.trim());
  let starts: IndexSymbol[] = [];
  let routeMw: string[] = [];
  let routeAuth: string[] = [];
  if (routeMatch) {
    const method = routeMatch[1]!.toUpperCase();
    const route = index.routes.find((r) => r.path === routeMatch[2] && (r.method === method || r.method === "ANY"));
    const h = route && lk.byId.get(route.handler);
    if (!route || !h) return { error: `No route "${from}" in the index (see the routes tool for the exact spelling).` };
    starts = [h]; routeMw = route.middleware; routeAuth = route.authSignals ?? [];
  } else {
    starts = resolveSymbol(index, from);
    if (starts.length === 0) return { error: `No symbol or route "${from}" in the index.` };
  }
  const paths: TracePath[] = [];
  let nodes = 0;
  let truncated = false;
  const walk = (sym: IndexSymbol, trail: IndexSymbol[], onTrail: Set<string>, depth: number): void => {
    if (paths.length >= maxPaths || nodes++ > NODE_BUDGET) { truncated = true; return; }
    for (const call of lk.callsFrom.get(sym.id) ?? []) {
      if (call.sink && (!sinkFilter || call.sink.category === sinkFilter)) {
        if (paths.length >= maxPaths) { truncated = true; return; }
        const chain = [...trail, sym];
        const names = new Set<string>([...routeMw.filter((m) => authName(m)), ...routeAuth]);
        for (const s of chain) for (const c of lk.callsFrom.get(s.id) ?? []) if (c.auth || authName(c.name)) names.add(c.text);
        paths.push({ hops: chain.map((s, i) => siteOf(s)), sink: { category: call.sink.category, call: call.text, file: call.file, line: call.line }, auth_signals_on_path: [...names] });
      }
    }
    if (depth >= maxDepth) return;
    for (const call of lk.callsFrom.get(sym.id) ?? []) {
      for (const t of lk.targets(call)) {
        if (onTrail.has(t.id)) continue;
        onTrail.add(t.id);
        walk(t, [...trail, sym], onTrail, depth + 1);
        onTrail.delete(t.id);
        if (paths.length >= maxPaths) return;
      }
    }
  };
  for (const s of starts) walk(s, [], new Set([s.id]), 0);
  return { start: starts.map((s) => `${s.file}:${s.line} ${s.qualified}`), paths, truncated };
}

/** What the index covers, for the model to judge how far to trust an empty answer. */
export function coverageOf(index: CodeIndex): { files: number; symbols: number; routes: number; commit: string; engine: string; languages: string[]; unsupported: Record<string, number>; truncated: boolean } {
  const langs = new Set(index.symbols.map((s) => s.language));
  return { files: index.files, symbols: index.symbols.length, routes: index.routes.length, commit: index.commit, engine: index.engine ?? "builtin", languages: [...langs], unsupported: index.unsupported, truncated: index.truncated };
}
