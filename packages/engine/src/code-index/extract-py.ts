import { classifySink } from "./sinks.js";
import { lineOf, lineStarts, maskSource, matchClose } from "./mask.js";
import { splitArgs } from "./extract-js.js";
import { innermostFinder, tick } from "./budget.js";
import type { FileExtract, IndexCall, IndexRoute, IndexSymbol } from "./types.js";

const KEYWORDS = new Set(["if", "elif", "while", "for", "return", "not", "and", "or", "in", "is", "lambda", "assert", "with", "except", "yield", "await", "raise", "import", "from", "del", "def", "class", "print_", "async"]);
const IDENT = "[A-Za-z_]\\w*";
const ROUTE_VERBS = new Set(["route", "get", "post", "put", "patch", "delete", "head", "options"]);

interface Block { name: string; indent: number; start: number; end: number; nameOffset: number; headerEnd: number; isClass: boolean }

export function extractPy(file: string, src: string): FileExtract {
  const masked = maskSource(src, "python");
  const starts = lineStarts(src);
  const line = (offset: number): number => lineOf(starts, Math.min(offset, Math.max(0, src.length - 1)));

  // Statement-start lines (paren depth 0) with their indent.
  const lines = masked.split("\n");
  const stmt: Array<{ offset: number; indent: number; blank: boolean }> = [];
  let depth = 0;
  let off = 0;
  for (const l of lines) {
    const blank = l.trim() === "";
    if (depth === 0 && !blank) stmt.push({ offset: off, indent: /^[ \t]*/.exec(l)![0].length, blank });
    for (const ch of l) { if ("([{".includes(ch)) depth++; else if (")]}".includes(ch)) depth = Math.max(0, depth - 1); }
    off += l.length + 1;
  }
  const endOfBlock = (offset: number, indent: number): number => {
    // First statement after the header (binary search), then forward to the first one that is not deeper.
    let lo = 0, hi = stmt.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (stmt[mid]!.offset > offset) hi = mid; else lo = mid + 1; }
    for (let i = lo; i < stmt.length; i++) { tick(); if (stmt[i]!.indent <= indent) return stmt[i]!.offset; }
    return src.length;
  };

  const blocks: Block[] = [];
  for (const m of masked.matchAll(new RegExp(`^([ \\t]*)(?:(async\\s+)?def|(class))\\s+(${IDENT})`, "gm"))) {
    tick();
    const isClass = m[3] !== undefined;
    const indent = m[1]!.length;
    const nameOffset = m.index! + m[0].length - m[4]!.length;
    let headerEnd = nameOffset;
    const afterName = nameOffset + m[4]!.length;
    const open = /^[ \t]{0,3}\(/.test(masked.slice(afterName, afterName + 4)) ? masked.indexOf("(", afterName) : -1;
    const colonSearch = open !== -1 ? matchClose(masked, open) : nameOffset;
    if (colonSearch !== -1) headerEnd = colonSearch;
    blocks.push({ name: m[4]!, indent, start: m.index! + m[1]!.length, end: endOfBlock(m.index!, indent), nameOffset, headerEnd, isClass });
  }

  const symbols: IndexSymbol[] = [];
  const ranges: Array<{ id: string; start: number; end: number }> = [];
  const mk = (name: string, qualified: string, kind: IndexSymbol["kind"], start: number, end: number): IndexSymbol => {
    const l = line(start);
    const sym: IndexSymbol = { id: `${file}#${qualified}@${l}`, name, qualified, kind, file, line: l, endLine: line(Math.max(start, end - 1)), language: "python" };
    symbols.push(sym);
    ranges.push({ id: sym.id, start, end });
    return sym;
  };
  const moduleSym = mk("<module>", "<module>", "module", 0, src.length);
  const defSyms = new Map<Block, IndexSymbol>();
  // Blocks come in source order and nest by indentation, so a stack of open blocks gives each one's container.
  const openBlocks: Block[] = [];
  for (const b of blocks) {
    tick();
    while (openBlocks.length > 0 && openBlocks[openBlocks.length - 1]!.end < b.end) openBlocks.pop();
    const container = openBlocks[openBlocks.length - 1];
    openBlocks.push(b);
    if (b.isClass) continue;
    const method = container?.isClass === true;
    defSyms.set(b, mk(b.name, method ? `${container!.name}.${b.name}` : b.name, method ? "method" : "function", b.start, b.end));
  }

  // Decorators map to the def that follows them.
  const routes: IndexRoute[] = [];
  const decorators: Array<{ start: number; end: number; text: string }> = [];
  for (const m of masked.matchAll(/^[ \t]*@([\w.]+)/gm)) {
    const at = m.index! + m[0].indexOf("@");
    let end = at + m[0].length - m[0].indexOf("@");
    if (masked[end] === "(") { const c = matchClose(masked, end); end = c === -1 ? end : c + 1; }
    decorators.push({ start: at, end, text: m[1]! });
  }
  for (const b of blocks) {
    const sym = defSyms.get(b);
    if (!sym) continue;
    const own: typeof decorators = [];
    let cursor = b.start;
    let lo = 0, hi = decorators.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (decorators[mid]!.end <= b.start) lo = mid + 1; else hi = mid; }
    for (let i = lo - 1; i >= 0; i--) {
      const d = decorators[i]!;
      if (d.end <= cursor && masked.slice(d.end, cursor).trim() === "") { own.unshift(d); cursor = d.start; } else break;
    }
    if (own.length === 0) continue;
    const header = masked.slice(b.nameOffset, b.headerEnd + 1);
    const depends = [...header.matchAll(new RegExp(`Depends\\s*\\(\\s*(${IDENT}(?:\\.${IDENT})*)`, "g"))].map((x) => x[1]!.split(".").pop()!);
    for (const d of own) {
      const verb = d.text.split(".").pop()!;
      if (!d.text.includes(".") || !ROUTE_VERBS.has(verb)) continue;
      const open = masked.indexOf("(", d.start);
      if (open === -1 || open >= d.end) continue;
      const args = splitArgs(masked, open, d.end - 1);
      const raw = args[0] ? /^\s*(['"])([^'"]*)\1/.exec(src.slice(args[0].start, args[0].end))?.[2] : undefined;
      if (raw === undefined) continue;
      const argText = src.slice(open, d.end);
      let methods = [verb.toUpperCase()];
      if (verb === "route") {
        const list = /methods\s*=\s*[[(]([^\])]*)[\])]/.exec(argText)?.[1];
        methods = list ? [...list.matchAll(/['"](\w+)['"]/g)].map((x) => x[1]!.toUpperCase()) : ["GET"];
        if (methods.length === 0) methods = ["GET"];
      }
      const decoNames = own.filter((o) => o !== d).map((o) => o.text.split(".").pop()!);
      const argDepends = [...masked.slice(open, d.end).matchAll(new RegExp(`Depends\\s*\\(\\s*(${IDENT}(?:\\.${IDENT})*)`, "g"))].map((x) => x[1]!.split(".").pop()!);
      for (const method of methods) routes.push({ method, path: raw, file, line: line(d.start), handler: sym.id, middleware: [...decoNames, ...argDepends, ...depends], framework: "flask-fastapi" });
    }
  }

  // Django URLconf.
  if (/(^|\/)urls[\w]*\.py$/.test(file)) {
    for (const m of masked.matchAll(/\b(?:re_path|path|url)\s*\(/g)) {
      const open = m.index! + m[0].length - 1;
      const close = matchClose(masked, open);
      if (close === -1) continue;
      const args = splitArgs(masked, open, close);
      const raw = args[0] ? /^\s*[rR]?(['"])([^'"]*)\1/.exec(src.slice(args[0].start, args[0].end))?.[2] : undefined;
      const viewText = args[1] ? masked.slice(args[1].start, args[1].end).trim() : "";
      const view = new RegExp(`^(${IDENT}(?:\\.${IDENT})*)`).exec(viewText)?.[1]?.split(".").filter((p) => p !== "as_view").pop();
      if (raw === undefined || !view) continue;
      routes.push({ method: "ANY", path: `/${raw.replace(/^\^|\$$/g, "")}`.replace(/^\/\//, "/"), file, line: line(m.index!), handler: `ref:${view}`, middleware: [], framework: "django" });
    }
  }

  const calls: IndexCall[] = [];
  const innermost = innermostFinder(ranges, moduleSym.id);
  const defNames = new Set(blocks.map((b) => b.nameOffset));
  const callRe = new RegExp(`(?<![\\w])(${IDENT}(?:\\s*\\.\\s*${IDENT}){0,10})\\s*\\(`, "g");
  for (const m of masked.matchAll(callRe)) {
    tick();
    const text = m[1]!.replace(/\s+/g, "");
    if (defNames.has(m.index!) || KEYWORDS.has(text.split(".")[0]!)) continue;
    if (/@\s*$/.test(masked.slice(Math.max(0, m.index! - 4), m.index!))) continue;
    const name = text.split(".").pop()!;
    const sink = classifySink(text);
    calls.push({ from: innermost(m.index!), name, text, file, line: line(m.index!), ...(sink ? { sink } : {}) });
  }
  return { symbols, calls, routes };
}
