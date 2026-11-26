/**
 * Blank out comments and string contents so later regexes never match inside them.
 * The result has the same length and the same newlines as the input, so offsets map back.
 */
export function maskSource(src: string, lang: "javascript" | "python"): string {
  const out = src.split("");
  const n = src.length;
  const blank = (from: number, to: number): void => {
    for (let k = from; k < to && k < n; k++) if (out[k] !== "\n") out[k] = " ";
  };
  let i = 0;
  while (i < n) {
    const c = src[i]!;
    const next = src[i + 1];
    if (lang === "javascript" && c === "/" && next === "/") {
      let j = i; while (j < n && src[j] !== "\n") j++;
      blank(i, j); i = j; continue;
    }
    if (lang === "javascript" && c === "/" && next === "*") {
      const end = src.indexOf("*/", i + 2);
      const j = end === -1 ? n : end + 2;
      blank(i, j); i = j; continue;
    }
    if (lang === "python" && c === "#") {
      let j = i; while (j < n && src[j] !== "\n") j++;
      blank(i, j); i = j; continue;
    }
    if (c === '"' || c === "'" || (lang === "javascript" && c === "`")) {
      const triple = lang === "python" && src.startsWith(c.repeat(3), i);
      const q = triple ? c.repeat(3) : c;
      let j = i + q.length;
      while (j < n) {
        if (src[j] === "\\") { j += 2; continue; }
        if (src.startsWith(q, j)) break;
        if (!triple && c !== "`" && src[j] === "\n") break;
        j++;
      }
      // Keep the quotes, blank the content.
      blank(i + q.length, j);
      i = Math.min(n, j + q.length); continue;
    }
    i++;
  }
  return out.join("");
}

let matchedFor: string | undefined;
let matched: Int32Array | undefined;

/** For every opening bracket of a masked text, the offset of its partner (-1 when unbalanced). One pass, cached for the last text. */
function bracketPairs(masked: string): Int32Array {
  if (matched && matchedFor === masked) return matched;
  const out = new Int32Array(masked.length).fill(-1);
  const stacks: Record<string, number[]> = { "(": [], "{": [], "[": [] };
  const opener: Record<string, string> = { ")": "(", "}": "{", "]": "[" };
  for (let k = 0; k < masked.length; k++) {
    const ch = masked[k]!;
    const stack = stacks[ch];
    if (stack) { stack.push(k); continue; }
    const open = opener[ch];
    if (open) { const at = stacks[open]!.pop(); if (at !== undefined) out[at] = k; }
  }
  matchedFor = masked; matched = out;
  return out;
}

/** Offset of the bracket that closes the one at `open`, or -1. Works on masked text, in constant time after one pass. */
export function matchClose(masked: string, open: number): number {
  if (open < 0 || open >= masked.length || !"({[".includes(masked[open]!)) return -1;
  return bracketPairs(masked)[open]!;
}

export function lineStarts(src: string): number[] {
  const starts = [0];
  for (let i = 0; i < src.length; i++) if (src[i] === "\n") starts.push(i + 1);
  return starts;
}

/** 1-based line of an offset. */
export function lineOf(starts: readonly number[], offset: number): number {
  let lo = 0, hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid]! <= offset) lo = mid; else hi = mid - 1;
  }
  return lo + 1;
}
