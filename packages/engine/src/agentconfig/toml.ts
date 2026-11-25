import { isObject } from "./util.js";

/**
 * A small reader for the TOML a coding tool's config uses: tables, strings, booleans, numbers, one-line arrays and one-line inline tables.
 * Anything else on a line is skipped. It exists so Codex's config.toml can be checked; it is not a general TOML parser.
 */
const UNSAFE = new Set(["__proto__", "constructor", "prototype"]);

function value(raw: string): unknown {
  const text = raw.trim();
  if (text.startsWith("\"")) { try { return JSON.parse(text.slice(0, text.lastIndexOf("\"") + 1)); } catch { return text.slice(1, text.lastIndexOf("\"")); } }
  if (text.startsWith("'")) return text.slice(1, Math.max(1, text.lastIndexOf("'")));
  if (text === "true") return true;
  if (text === "false") return false;
  if (/^-?\d+(?:\.\d+)?$/.test(text)) return Number(text);
  if (text.startsWith("[")) return [...text.matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'/g)].map(match => (match[1] !== undefined ? match[1].replace(/\\(.)/g, "$1") : match[2]!));
  if (text.startsWith("{")) {
    const table: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const match of text.slice(0, 4000).matchAll(/([A-Za-z0-9_.-]+|"[^"]+")\s*=\s*("(?:[^"\\]|\\.)*"|'[^']*'|[^,}]+)/g)) if (!UNSAFE.has(match[1]!.replace(/^"|"$/g, ""))) table[match[1]!.replace(/^"|"$/g, "")] = value(match[2]!);
    return table;
  }
  return undefined;
}

function stripComment(raw: string): string {
  let quote = "";
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i]!;
    if (quote) {
      if (ch === "\\" && quote === "\"") i++;
      else if (ch === quote) quote = "";
    } else if (ch === "\"" || ch === "'") {
      quote = ch;
    } else if (ch === "#") {
      return raw.slice(0, i);
    }
  }
  return raw;
}

const path = (header: string): string[] => [...header.matchAll(/"([^"]*)"|'([^']*)'|([A-Za-z0-9_-]+)/g)].map(match => match[1] ?? match[2] ?? match[3]!);

export function parseSimpleToml(text: string): Record<string, unknown> {
  const root: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  let table = root;
  for (const rawLine of text.split(/\r\n|\r|\n/).slice(0, 20000)) {
    if (rawLine.length > 4000) continue;
    const line = rawLine.replace(/^\s+/, "");
    if (!line || line.startsWith("#")) continue;
    const header = /^\[\[?([^\]]+)\]\]?\s*(?:#.*)?$/.exec(line);
    if (header) {
      table = root;
      for (const part of path(header[1]!).slice(0, 8)) { if (UNSAFE.has(part)) { table = Object.create(null) as Record<string, unknown>; break; } const next = table[part]; table = isObject(next) ? next : (table[part] = Object.create(null)) as Record<string, unknown>; }
      continue;
    }
    const pair = /^("[^"]+"|[A-Za-z0-9_.-]+)\s*=\s*(.*)$/.exec(line);
    if (!pair) continue;
    const parsed = value(stripComment(pair[2]!));
    if (parsed !== undefined && !UNSAFE.has(pair[1]!.replace(/^"|"$/g, ""))) table[pair[1]!.replace(/^"|"$/g, "")] = parsed;
  }
  return root;
}
