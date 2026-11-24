import type { AgentConfigFinding } from "./rules.js";
import { finding } from "./util.js";

/** Rule agent-config/hidden-unicode. Reads code points, never normalises or executes anything. */
const ZERO_WIDTH = new Set([0x200b, 0x200c, 0x200d, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x180e, 0xfeff, 0x034f, 0x115f, 0x1160, 0x3164, 0xffa0]);
const isBidi = (cp: number): boolean => (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069);
const isTag = (cp: number): boolean => cp >= 0xe0000 && cp <= 0xe007f;
const isVariation = (cp: number): boolean => (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);
const MAX_RUNS_PER_FILE = 20;
const JOINING_SCRIPTS = /^[\p{Script=Arabic}\p{Script=Devanagari}\p{Script=Bengali}\p{Script=Gujarati}\p{Script=Gurmukhi}\p{Script=Kannada}\p{Script=Malayalam}\p{Script=Oriya}\p{Script=Tamil}\p{Script=Telugu}\p{Script=Sinhala}\p{Script=Khmer}\p{Script=Myanmar}]$/u;
const PICTOGRAPH = /^\p{Extended_Pictographic}$/u;
const hex = (cp: number): string => `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;

interface Mark { cp: number; kind: "zero-width" | "bidi" | "tag" | "variation"; line: number; column: number }

export function scanHiddenUnicode(file: string, text: string): AgentConfigFinding[] {
  const points = [...text].map(ch => ch.codePointAt(0)!);
  const marks: Mark[] = [];
  let line = 1, column = 0;
  const at = (i: number): string => (i >= 0 && i < points.length ? String.fromCodePoint(points[i]!) : "");
  for (let i = 0; i < points.length; i++) {
    const cp = points[i]!;
    column++;
    if (cp === 10) { line++; column = 0; continue; }
    if (cp < 0x80 && !isTag(cp)) continue;
    if (cp === 0xfeff && i === 0) continue;
    if (isBidi(cp)) { marks.push({ cp, kind: "bidi", line, column }); continue; }
    if (isTag(cp)) {
      // A flag emoji such as England is a black flag, tag letters and a cancel tag.
      let start = i; while (start > 0 && isTag(points[start - 1]!)) start--;
      let end = i; while (end + 1 < points.length && isTag(points[end + 1]!)) end++;
      if (start > 0 && points[start - 1] === 0x1f3f4 && points[end] === 0xe007f) continue;
      marks.push({ cp, kind: "tag", line, column }); continue;
    }
    if (cp === 0x200d || cp === 0x200c) {
      let back = i - 1; while (back >= 0 && (points[back] === 0xfe0f || points[back] === 0xfe0e || (points[back]! >= 0x1f3fb && points[back]! <= 0x1f3ff))) back--;
      if (PICTOGRAPH.test(at(back)) && PICTOGRAPH.test(at(i + 1))) continue;
      if (JOINING_SCRIPTS.test(at(i - 1)) && JOINING_SCRIPTS.test(at(i + 1))) continue;
      marks.push({ cp, kind: "zero-width", line, column }); continue;
    }
    if (ZERO_WIDTH.has(cp)) { marks.push({ cp, kind: "zero-width", line, column }); continue; }
    if (isVariation(cp)) {
      const run = isVariation(points[i - 1] ?? 0) || isVariation(points[i + 1] ?? 0);
      const prev = at(i - 1);
      const normal = /^[\p{Emoji}\p{Script=Han}]$/u.test(prev) && !(cp >= 0xe0100 && !/^\p{Script=Han}$/u.test(prev));
      if (run || !normal) marks.push({ cp, kind: "variation", line, column });
    }
  }
  // Join neighbours on the same line into one finding.
  const runs: Mark[][] = [];
  for (const mark of marks) {
    const last = runs[runs.length - 1];
    const tail = last?.[last.length - 1];
    if (last && tail && tail.line === mark.line && mark.column - tail.column <= 1) last.push(mark); else runs.push([mark]);
  }
  const lines = text.split(/\r\n|\r|\n/);
  const found: AgentConfigFinding[] = [];
  for (const run of runs.slice(0, MAX_RUNS_PER_FILE)) {
    const first = run[0]!;
    const counts = new Map<number, number>();
    for (const mark of run) counts.set(mark.cp, (counts.get(mark.cp) ?? 0) + 1);
    const listed = [...counts].slice(0, 6).map(([cp, count]) => `${hex(cp)}${count > 1 ? ` x${count}` : ""}`).join(", ") + (counts.size > 6 ? `, and ${counts.size - 6} more` : "");
    const kinds = [...new Set(run.map(mark => mark.kind))];
    const hidden = run.filter(mark => mark.kind === "tag").map(mark => mark.cp - 0xe0000).filter(code => code >= 0x20 && code < 0x7f).map(code => String.fromCharCode(code)).join("");
    const strong = kinds.some(kind => kind !== "zero-width") || run.length >= 4;
    const label = kinds.join(" and ");
    const context = (lines[first.line - 1] ?? "").replace(/[\p{Cf}\p{Cc}\p{Co}\p{Cn}\u034f\u115f\u1160\u3164\uffa0\ufe00-\ufe0f\u{e0100}-\u{e01ef}]/gu, "").slice(0, 100);
    found.push(finding("agent-config/hidden-unicode", file, first.line, context || "(line shows nothing visible)",
      `${run.length} hidden ${label} character${run.length === 1 ? "" : "s"} (${listed}) at line ${first.line}, column ${first.column}${hidden ? `; the tag characters spell: ${hidden.slice(0, 80)}` : ""}.`,
      { severity: strong ? "high" : "medium", column: first.column }));
  }
  if (runs.length > MAX_RUNS_PER_FILE) found.push(finding("agent-config/hidden-unicode", file, runs[MAX_RUNS_PER_FILE]!.at(0)!.line, "", `${runs.length - MAX_RUNS_PER_FILE} more runs of hidden characters in this file are not listed.`, { severity: "high" }));
  return found;
}
