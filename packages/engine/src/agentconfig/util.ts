import { scrub } from "./secrets.js";
import { ruleOf, type AgentConfigFinding, type AgentConfigSeverity } from "./rules.js";

/** Makes text safe to print and to send to GitHub: no control characters, no HTML, no mentions, bounded length. */
export function neutralize(text: string, max = 160): string {
  const flat = text.slice(0, max * 4).replace(/[\p{Cc}\p{Cf}\p{Co}\p{Cn}\u2028\u2029]/gu, " ");
  const clean = flat.replace(/\s+/g, " ").trim().replace(/</g, "\u2039").replace(/>/g, "\u203a").replace(/@/g, "(at)").replace(/&/g, "and").replace(/`/g, "'").replace(/\[/g, "(").replace(/\]/g, ")").replace(/#(?=\d)/g, "No. ");
  return clean.length > max ? `${clean.slice(0, max - 3)}...` : clean;
}

/** A path from the repository as text for a report: control, format and bidirectional characters become a question mark. */
export const safePath = (path: string): string => path.slice(0, 500).replace(/[\p{Cc}\p{Cf}\p{Co}\p{Cn}\u2028\u2029]/gu, "?");

export function finding(ruleId: string, file: string, line: number, snippet: string, message: string, options: { severity?: AgentConfigSeverity; column?: number; heuristicOverride?: boolean } = {}): AgentConfigFinding {
  const rule = ruleOf(ruleId);
  return {
    ruleId, severity: options.severity ?? rule.severity, heuristic: rule.heuristic, file: safePath(file), line: Math.max(1, line),
    ...(options.column ? { column: options.column } : {}), snippet: neutralize(scrub(snippet.slice(0, 2000))), message: neutralize(scrub(message.slice(0, 2000)), 400), cwe: rule.cwe, explanation: rule.explanation, fix: rule.fix,
  };
}

/** Finds where a string sits in a file. Asking again for the same text returns its next occurrence, so repeated values get distinct lines. */
export function locator(text: string): (needle: string, from?: number) => number {
  const cursor = new Map<string, number>();
  const starts: number[] = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  const lineAt = (index: number): number => { let lo = 0, hi = starts.length - 1; while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid]! <= index) lo = mid; else hi = mid - 1; } return lo + 1; };
  return (needle, from = 0) => {
    const start = Math.max(from, cursor.get(needle) ?? 0);
    let index = text.indexOf(needle, start);
    if (index < 0) index = text.indexOf(needle);
    if (index < 0 && needle.length > 2 && needle.startsWith("\"") && needle.endsWith("\"")) { const bare = needle.slice(1, -1); index = text.indexOf(bare, start); if (index < 0) index = text.indexOf(bare); }
    if (index < 0) return 1;
    cursor.set(needle, index + needle.length);
    return lineAt(index);
  };
}

const MAX_JSON_DEPTH = 64;

/** Strips comments and trailing commas (JSONC) without touching strings, then parses. Returns undefined when it is not JSON. */
export function parseJsonc(text: string): unknown {
  if (text.length > 4 * 1024 * 1024) return undefined;
  let out = "";
  let nesting = 0;
  let i = 0;
  const n = text.length;
  while (i < n) {
    const ch = text[i]!;
    if (ch === "\"") {
      let j = i + 1;
      while (j < n && text[j] !== "\"") j += text[j] === "\\" ? 2 : 1;
      out += text.slice(i, j + 1); i = j + 1;
    } else if (ch === "/" && text[i + 1] === "/") { while (i < n && text[i] !== "\n") i++; }
    else if (ch === "/" && text[i + 1] === "*") { const end = text.indexOf("*/", i + 2); i = end < 0 ? n : end + 2; }
    else { if (ch === "{" || ch === "[") { if (++nesting > MAX_JSON_DEPTH) return undefined; } else if (ch === "}" || ch === "]") nesting--; out += ch; i++; }
  }
  try { return JSON.parse(out.replace(/^﻿/, "").replace(/,(\s*[}\]])/g, "$1")); } catch { return undefined; }
}

export const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
