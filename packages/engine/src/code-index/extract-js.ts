import { classifySink } from "./sinks.js";
import { lineOf, lineStarts, maskSource, matchClose } from "./mask.js";
import type { FileExtract, IndexCall, IndexRoute, IndexSymbol } from "./types.js";

const KEYWORDS = new Set(["if", "for", "while", "switch", "catch", "return", "typeof", "function", "await", "async", "void", "delete", "throw", "else", "do", "in", "of", "new", "super", "import", "require_", "with", "yield", "case"]);
const HTTP_METHODS = "get|post|put|patch|delete|all|options|head";
const IDENT = "[A-Za-z_$][\\w$]*";

interface Def { name: string; qualified: string; kind: IndexSymbol["kind"]; nameOffset: number; start: number; end: number }

/** Top-level comma-separated argument ranges of the call whose `(` is at `open`. */
export function splitArgs(masked: string, open: number, close: number): Array<{ start: number; end: number }> {
  const args: Array<{ start: number; end: number }> = [];
  let depth = 0;
  let start = open + 1;
  for (let k = open + 1; k < close; k++) {
    const ch = masked[k];
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth--;
    else if (ch === "," && depth === 0) { args.push({ start, end: k }); start = k + 1; }
  }
  if (masked.slice(start, close).trim()) args.push({ start, end: close });
  return args;
}

/** From the offset after `=>`, the end offset of an arrow body. */
function arrowBodyEnd(masked: string, from: number): number {
  let k = from;
  while (k < masked.length && /\s/.test(masked[k]!)) k++;
  if (masked[k] === "{") { const c = matchClose(masked, k); return c === -1 ? masked.length : c + 1; }
  let depth = 0;
  for (; k < masked.length; k++) {
    const ch = masked[k];
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") { if (depth === 0) return k; depth--; }
    else if (depth === 0 && (ch === ";" || ch === "\n")) return k;
  }
  return masked.length;
}

/** After a parameter list closing at `close`, the end of a `function`-style body (skips a TS return type). */
function bodyAfterParams(masked: string, close: number): { start: number; end: number } | undefined {
  const m = /^\s*(?::[^{;=]*)?\{/.exec(masked.slice(close + 1, close + 300));
  if (!m) return undefined;
  const open = close + m[0].length;
  const end = matchClose(masked, open);
  return { start: open, end: end === -1 ? masked.length : end + 1 };
}

function findDefs(masked: string): Def[] {
  const defs: Def[] = [];
  const seen = new Set<number>();
  const push = (d: Def): void => { if (!seen.has(d.nameOffset)) { seen.add(d.nameOffset); defs.push(d); } };

  // Class ranges first, for method qualification.
  const classes: Array<{ name: string; start: number; end: number }> = [];
  for (const m of masked.matchAll(new RegExp(`\\bclass\\s+(${IDENT})[^{;]*\\{`, "g"))) {
    const open = m.index! + m[0].length - 1;
    const close = matchClose(masked, open);
    classes.push({ name: m[1]!, start: open, end: close === -1 ? masked.length : close });
  }

  for (const m of masked.matchAll(new RegExp(`\\bfunction\\s*\\*?\\s*(${IDENT})\\s*(?:<[^>(]*>)?\\(`, "g"))) {
    const open = m.index! + m[0].length - 1;
    const close = matchClose(masked, open);
    if (close === -1) continue;
    const body = bodyAfterParams(masked, close);
    if (body) push({ name: m[1]!, qualified: m[1]!, kind: "function", nameOffset: m.index! + m[0].indexOf(m[1]!), start: m.index!, end: body.end });
  }

  // `const f = (...) =>`, `const f = async x =>`, `const f = function (...) {}`, also `name: (...) =>` in object literals.
  const assigned = new RegExp(`(?:\\b(?:const|let|var)\\s+|\\b(?:exports|module\\.exports)\\.|[{,]\\s*)(${IDENT})\\s*(?::[^=;{}(]*)?[=:]\\s*(?:async\\s+)?`, "g");
  for (const m of masked.matchAll(assigned)) {
    const nameOffset = m.index! + m[0].indexOf(m[1]!);
    let k = m.index! + m[0].length;
    let bodyEnd = -1;
    if (masked.startsWith("function", k)) {
      const open = masked.indexOf("(", k);
      if (open === -1) continue;
      const close = matchClose(masked, open);
      const body = close === -1 ? undefined : bodyAfterParams(masked, close);
      if (body) bodyEnd = body.end;
    } else if (masked[k] === "(") {
      const close = matchClose(masked, k);
      if (close === -1) continue;
      const arrow = /^\s*(?::[^=;{]*?)?=>/.exec(masked.slice(close + 1, close + 200));
      if (arrow) bodyEnd = arrowBodyEnd(masked, close + 1 + arrow[0].length);
    } else {
      const id = new RegExp(`^(${IDENT})\\s*=>`).exec(masked.slice(k, k + 200));
      if (id) bodyEnd = arrowBodyEnd(masked, k + id[0].length);
    }
    if (bodyEnd !== -1) push({ name: m[1]!, qualified: m[1]!, kind: "function", nameOffset, start: m.index!, end: bodyEnd });
  }

  // Methods: only at the top brace depth of a class body.
  for (const cls of classes) {
    const body = masked.slice(cls.start + 1, cls.end);
    const depthAt: number[] = new Array(body.length);
    let depth = 0;
    for (let i = 0; i < body.length; i++) {
      const ch = body[i]!;
      if (ch === "{" || ch === "(" || ch === "[") { depthAt[i] = depth; depth++; }
      else if (ch === "}" || ch === ")" || ch === "]") { depth--; depthAt[i] = depth; }
      else depthAt[i] = depth;
    }
    const method = new RegExp(`(?:^|[;}\\n])[ \\t]*(?:(?:public|private|protected|static|async|override|readonly|get|set)\\s+)*\\*?\\s*(${IDENT})\\s*(?:<[^>(]*>)?\\(`, "g");
    for (const m of body.matchAll(method)) {
      const nameIdx = m.index! + m[0].lastIndexOf(m[1]!);
      if (depthAt[nameIdx] !== 0 || KEYWORDS.has(m[1]!)) continue;
      const open = cls.start + 1 + m.index! + m[0].length - 1;
      const close = matchClose(masked, open);
      if (close === -1) continue;
      const bodyRange = bodyAfterParams(masked, close);
      if (bodyRange) push({ name: m[1]!, qualified: `${cls.name}.${m[1]}`, kind: "method", nameOffset: cls.start + 1 + nameIdx, start: cls.start + 1 + nameIdx, end: bodyRange.end });
    }
  }
  return defs;
}

export function extractJs(file: string, src: string): FileExtract {
  const masked = maskSource(src, "javascript");
  const starts = lineStarts(src);
  const line = (offset: number): number => lineOf(starts, Math.min(offset, src.length - 1));
  const symbols: IndexSymbol[] = [];
  const ranges: Array<{ id: string; start: number; end: number }> = [];
  const nameOffsets = new Set<number>();
  const mk = (name: string, qualified: string, kind: IndexSymbol["kind"], start: number, end: number): IndexSymbol => {
    const l = line(start);
    const sym: IndexSymbol = { id: `${file}#${qualified}@${l}`, name, qualified, kind, file, line: l, endLine: line(Math.max(start, end - 1)), language: "javascript" };
    symbols.push(sym);
    ranges.push({ id: sym.id, start, end });
    return sym;
  };

  const moduleSym = mk("<module>", "<module>", "module", 0, src.length);
  const defs = findDefs(masked);
  const bySym = new Map<number, IndexSymbol>();
  for (const d of defs) { nameOffsets.add(d.nameOffset); bySym.set(d.nameOffset, mk(d.name, d.qualified, d.kind, d.start, d.end)); }

  // Routes.
  const routes: IndexRoute[] = [];
  const routerMiddleware = new Map<string, string[]>();
  const calleeName = (text: string): string => /^([\w$.]+)/.exec(text.trim())?.[1]?.split(".").pop() ?? "";
  for (const m of masked.matchAll(new RegExp(`\\b(${IDENT})\\s*\\.\\s*(${HTTP_METHODS}|use)\\s*\\(`, "g"))) {
    const open = m.index! + m[0].length - 1;
    const close = matchClose(masked, open);
    if (close === -1) continue;
    const args = splitArgs(masked, open, close);
    const receiver = m[1]!;
    const method = m[2]!;
    const first = args[0] ? src.slice(args[0].start, args[0].end).trim() : "";
    const pathMatch = /^(['"`])([^'"`]*)\1$/.exec(first);
    if (method === "use") {
      // Router-level middleware applies to the routes registered on the same router.
      const names = args.filter((a) => !/^\s*(['"`])/.test(src.slice(a.start, a.end))).map((a) => calleeName(masked.slice(a.start, a.end))).filter(Boolean);
      if (names.length) routerMiddleware.set(receiver, [...(routerMiddleware.get(receiver) ?? []), ...names]);
      continue;
    }
    if (!pathMatch || !(pathMatch[2]!.startsWith("/") || pathMatch[2] === "*") || args.length < 2) continue;
    const rest = args.slice(1);
    const last = rest[rest.length - 1]!;
    const middleware = [...(routerMiddleware.get(receiver) ?? [])];
    for (const a of rest.slice(0, -1)) {
      const text = masked.slice(a.start, a.end).trim();
      middleware.push(calleeName(text) || "<inline>");
    }
    const lastText = masked.slice(last.start, last.end).trim();
    const routeLine = line(m.index!);
    let handler: string;
    if (/^[\w$.]+$/.test(lastText)) handler = `ref:${lastText.split(".").pop()}`;
    else {
      const verb = method.toUpperCase();
      handler = mk(`<${verb} ${pathMatch[2]}>`, `<${verb} ${pathMatch[2]}>`, "route-handler", last.start, last.end).id;
    }
    routes.push({ method: method.toUpperCase(), path: pathMatch[2]!, file, line: routeLine, handler, middleware, framework: "express-like" });
  }

  // NestJS-style decorators: @Controller('p') class ... { @UseGuards(G) @Get('x') method() {} }
  const methodDefs = defs.filter((d) => d.kind === "method").sort((a, b) => a.start - b.start);
  for (const m of masked.matchAll(/@(Get|Post|Put|Patch|Delete|All)\s*\(/g)) {
    const open = m.index! + m[0].length - 1;
    const close = matchClose(masked, open);
    if (close === -1) continue;
    const raw = /^\s*(['"`])([^'"`]*)\1/.exec(src.slice(open + 1, close))?.[2] ?? "";
    const target = methodDefs.find((d) => d.nameOffset > close);
    if (!target) continue;
    const regionStart = Math.max(masked.lastIndexOf("}", m.index!), masked.lastIndexOf(";", m.index!), masked.lastIndexOf("{", m.index!)) + 1;
    const between = masked.slice(regionStart, m.index!) + " " + masked.slice(close, target.nameOffset);
    const mw = [...between.matchAll(/@(\w+)\s*(?:\(([^)]*)\))?/g)].flatMap((d) => d[1] === "UseGuards" ? (d[2] ?? "").split(",").map((s) => s.trim()).filter(Boolean) : [d[1]!]);
    const cls = [...masked.slice(0, m.index!).matchAll(new RegExp(`((?:@\\w+\\s*(?:\\([^)]*\\))?\\s*)*)(?:export\\s+(?:default\\s+)?)?(?:abstract\\s+)?\\bclass\\s+${IDENT}`, "g"))].pop();
    const classDecorators = cls ? [...cls[1]!.matchAll(/@(\w+)\s*(?:\(([^)]*)\))?/g)].flatMap((d) => d[1] === "UseGuards" ? (d[2] ?? "").split(",").map((s) => s.trim()).filter(Boolean) : d[1] === "Controller" ? [] : [d[1]!]) : [];
    const prefix = cls ? (/@Controller\s*\(\s*['"`]([^'"`]*)/.exec(src.slice(cls.index!, cls.index! + cls[0].length))?.[1] ?? "") : "";
    const path = `/${[prefix, raw].map((p) => p.replace(/^\/|\/$/g, "")).filter(Boolean).join("/")}`;
    const handler = bySym.get(target.nameOffset);
    if (handler) routes.push({ method: m[1]!.toUpperCase(), path, file, line: line(m.index!), handler: handler.id, middleware: [...classDecorators, ...mw], framework: "nest" });
  }

  // Calls, attributed to the innermost enclosing symbol.
  const calls: IndexCall[] = [];
  const sorted = [...ranges].sort((a, b) => (a.end - a.start) - (b.end - b.start));
  const innermost = (offset: number): string => sorted.find((r) => offset >= r.start && offset < r.end)?.id ?? moduleSym.id;
  const callRe = new RegExp(`(${IDENT}(?:\\s*(?:\\?\\.|\\.)\\s*#?${IDENT})*)\\s*(?:<[^>()]*>)?\\(`, "g");
  for (const m of masked.matchAll(callRe)) {
    const text = m[1]!.replace(/\s+/g, "").replace(/\?\./g, ".");
    const first = text.split(".")[0]!;
    if (nameOffsets.has(m.index!) || KEYWORDS.has(first)) continue;
    const before = masked.slice(Math.max(0, m.index! - 9), m.index!);
    if (/function\s*\*?\s*$/.test(before) || /\bclass\s+$/.test(before)) continue;
    const name = text.split(".").pop()!;
    const sink = classifySink(text);
    calls.push({ from: innermost(m.index!), name, text, file, line: line(m.index!), ...(sink ? { sink } : {}) });
  }
  return { symbols, calls, routes };
}
