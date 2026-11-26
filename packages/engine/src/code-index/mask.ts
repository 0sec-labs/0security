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

/** Offset of the bracket that closes the one at `open`, or -1. Works on masked text. */
export function matchClose(masked: string, open: number): number {
  const pairs: Record<string, string> = { "(": ")", "{": "}", "[": "]" };
  const o = masked[open]!;
  const c = pairs[o];
  if (!c) return -1;
  let depth = 0;
  for (let k = open; k < masked.length; k++) {
    const ch = masked[k];
    if (ch === o) depth++;
    else if (ch === c && --depth === 0) return k;
  }
  return -1;
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
