import { isObject } from "./util.js";

/**
 * A small reader for the TOML a coding tool's config uses: tables, strings, booleans, numbers, one-line arrays and one-line inline tables.
 * Anything else on a line is skipped. It exists so Codex's config.toml can be checked; it is not a general TOML parser.
 */
function value(raw: string): unknown {
  const text = raw.trim();
  if (text.startsWith("\"")) { try { return JSON.parse(text.slice(0, text.lastIndexOf("\"") + 1)); } catch { return text.slice(1, text.lastIndexOf("\"")); } }
  if (text.startsWith("'")) return text.slice(1, Math.max(1, text.lastIndexOf("'")));
  if (text === "true") return true;
  if (text === "false") return false;
  if (/^-?\d+(?:\.\d+)?$/.test(text)) return Number(text);
  if (text.startsWith("[")) return [...text.matchAll(/"((?:[^"\\]|\\.)*)"|'([^']*)'/g)].map(match => (match[1] !== undefined ? match[1].replace(/\\(.)/g, "$1") : match[2]!));
  if (text.startsWith("{")) {
    const table: Record<string, unknown> = {};
    for (const match of text.matchAll(/([A-Za-z0-9_.-]+|"[^"]+")\s*=\s*("(?:[^"\\]|\\.)*"|'[^']*'|[^,}]+)/g)) table[match[1]!.replace(/^"|"$/g, "")] = value(match[2]!);
    return table;
  }
  return undefined;
}

const path = (header: string): string[] => [...header.matchAll(/"([^"]*)"|'([^']*)'|([A-Za-z0-9_-]+)/g)].map(match => match[1] ?? match[2] ?? match[3]!);

export function parseSimpleToml(text: string): Record<string, unknown> {
  const root: Record<string, unknown> = {};
  let table = root;
  for (const rawLine of text.split(/\r\n|\r|\n/)) {
    const line = rawLine.replace(/^\s+/, "");
    if (!line || line.startsWith("#")) continue;
    const header = /^\[\[?([^\]]+)\]\]?\s*(?:#.*)?$/.exec(line);
    if (header) {
      table = root;
      for (const part of path(header[1]!)) { const next = table[part]; table = isObject(next) ? next : (table[part] = {}) as Record<string, unknown>; }
      continue;
    }
    const pair = /^("[^"]+"|[A-Za-z0-9_.-]+)\s*=\s*(.*)$/.exec(line);
    if (!pair) continue;
    const parsed = value(pair[2]!.replace(/\s+#[^"']*$/, ""));
    if (parsed !== undefined) table[pair[1]!.replace(/^"|"$/g, "")] = parsed;
  }
  return root;
}
