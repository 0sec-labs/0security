/**
 * The markdown report read in a terminal. The report is written for a file or a pull request comment, so it carries
 * `**bold**`, backticks, tables and `<details>` blocks that show up as raw characters on screen. This turns them into plain
 * text with a little colour. It is for display only: files, pipes and `--output` still get the markdown untouched.
 */
const bold = (text: string): string => `\u001b[1m${text}\u001b[22m`;
const dim = (text: string): string => `\u001b[2m${text}\u001b[22m`;
const cyan = (text: string): string => `\u001b[36m${text}\u001b[39m`;

/** Backslash escapes and the three HTML entities the report writer adds to user text. */
const unescape = (text: string): string => text
  .replace(/\\([\\`*_{}[\]()#+!~|])/g, "$1")
  .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");

function inline(text: string, color: boolean): string {
  const out = color
    ? text.replace(/\*\*([^*]+)\*\*/g, (_, inner: string) => bold(inner)).replace(/`([^`]+)`/g, (_, inner: string) => cyan(inner))
    : text.replace(/\*\*([^*]+)\*\*/g, "$1").replace(/`([^`]+)`/g, "$1");
  return unescape(out);
}

export function renderMarkdownForTerminal(markdown: string, options: { color?: boolean } = {}): string {
  const color = options.color ?? true;
  const lines: string[] = [];
  let fenced = false;
  for (const raw of markdown.split("\n")) {
    if (/^\s*```/.test(raw)) { fenced = !fenced; continue; }
    if (fenced) { lines.push(`    ${color ? dim(raw) : raw}`); continue; }
    if (/^\s*<\/?details>\s*$/.test(raw)) continue;
    const summary = /^\s*<summary>(.*)<\/summary>\s*$/.exec(raw);
    if (summary) { lines.push(color ? bold(unescape(summary[1]!)) : unescape(summary[1]!)); continue; }
    if (/^\s*\|[\s:|-]+\|\s*$/.test(raw)) continue;
    const row = /^\s*\|(.*)\|\s*$/.exec(raw);
    if (row) { lines.push(row[1]!.split("|").map(cell => inline(cell.trim(), color)).join("   ").trimEnd()); continue; }
    const heading = /^(#{1,6})\s+(.*)$/.exec(raw);
    if (heading) {
      const text = inline(heading[2]!, false);
      const shown = heading[1]!.length === 1 ? text.toUpperCase() : text;
      lines.push("", color ? bold(shown) : shown);
      continue;
    }
    lines.push(inline(raw, color));
  }
  return `${lines.join("\n").replace(/\n{3,}/g, "\n\n").trim()}\n`;
}
