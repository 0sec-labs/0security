/**
 * Deterministic checks on the Mermaid "Threat map" section of a threat-model draft.
 * The checks are structural only (fences, diagram type, subgraph balance, node count); they never fail the command.
 */

export const THREAT_MAP_HEADING = "Threat map";

/** Problems with the threat map section, in words a person can act on. Empty when it looks fine. */
export function checkThreatMap(text: string | undefined): string[] {
  if (text === undefined) return [];
  const section = new RegExp(`^##\\s+${THREAT_MAP_HEADING}\\s*$`, "mi").exec(text);
  if (!section) return [`no "## ${THREAT_MAP_HEADING}" section: the draft has no diagram`];
  const rest = text.slice(section.index + section[0].length);
  const next = /^##\s/m.exec(rest);
  const body = next ? rest.slice(0, next.index) : rest;

  const lines = body.split(/\r?\n/);
  const blocks: string[][] = [];
  let current: string[] | undefined;
  let kind = "";
  for (const line of lines) {
    const fence = /^\s*(```+|~~~+)\s*([\w-]*)/.exec(line);
    if (fence) {
      if (current === undefined) { current = []; kind = fence[2]!.toLowerCase(); }
      else { if (kind === "mermaid") blocks.push(current); current = undefined; }
      continue;
    }
    if (current !== undefined && kind === "mermaid") current.push(line);
  }
  const problems: string[] = [];
  if (current !== undefined) problems.push("the threat map has a code fence that is never closed");
  if (kind === "mermaid" && current !== undefined) blocks.push(current);
  if (blocks.length === 0) return [...problems, "the threat map section has no ```mermaid block"];
  if (blocks.length > 1) problems.push("the threat map has more than one mermaid block; only the first is checked");

  const code = blocks[0]!.filter(line => line.trim() !== "" && !/^\s*%%/.test(line));
  const first = code[0]?.trim() ?? "";
  // A leading init directive (%%{init: ...}%%) is a comment line above and is skipped by the filter.
  if (!/^(flowchart|graph)\b(\s+(TB|TD|BT|RL|LR))?\s*;?$/i.test(first)) problems.push(`the mermaid block should start with "flowchart" (for example "flowchart LR"), not "${first.slice(0, 30)}"`);
  let depth = 0;
  for (const line of code.slice(1)) {
    const word = line.trim().split(/\s+/)[0];
    if (word === "subgraph") depth++;
    else if (word === "end") { depth--; if (depth < 0) { problems.push('the mermaid block has an "end" without a "subgraph"'); depth = 0; } }
  }
  if (depth > 0) problems.push(`the mermaid block has ${depth} "subgraph" without a matching "end"`);
  const edges = code.filter(line => /(-->|---|-\.->|==>|-\.-|--[ox])/.test(line)).length;
  if (code.length > 1 && edges === 0) problems.push("the mermaid block has no data flows (no arrows)");
  if (code.length <= 1) problems.push("the mermaid block is empty");
  return problems;
}
