/**
 * The inputs of a second-opinion scan (`--known`) and of a pre-pass-only tier: other tools' SARIF, read as data, and
 * scanner leads turned into findings that say no model reviewed them.
 */
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { locationLabel, parseSarif, type Finding, type ImportedFinding, type KnownItem } from "@0/engine/shared";
import { UsageError } from "./commands/output.js";

const MAX_KNOWN_FILE_BYTES = 20 * 1024 * 1024;
const MAX_KNOWN_ITEMS = 20_000;

export interface KnownSet { items: ImportedFinding[]; tools: string[]; files: string[] }

/** The items in the SARIF files named with --known. Paths are made relative to the scanned folder; an item outside it keeps no location. */
export function loadKnown(files: readonly string[], roots: readonly string[]): KnownSet {
  const items: ImportedFinding[] = [];
  const tools = new Set<string>();
  const used: string[] = [];
  for (const raw of files) {
    const path = resolve(raw);
    let size: number;
    try { if (!statSync(path).isFile()) throw new Error("not a file"); size = statSync(path).size; }
    catch { throw new UsageError(`--known ${raw} is not a file.`); }
    if (size > MAX_KNOWN_FILE_BYTES) throw new UsageError(`--known ${raw} is ${size} bytes; the limit is ${MAX_KNOWN_FILE_BYTES}.`);
    try {
      const parsed = parseSarif(readFileSync(path, "utf8"), { roots });
      items.push(...parsed.findings);
      for (const tool of parsed.tools) tools.add(tool);
    } catch (error) { throw new UsageError(`--known ${raw}: ${error instanceof Error ? error.message : String(error)}`); }
    used.push(path);
  }
  if (items.length > MAX_KNOWN_ITEMS) throw new UsageError(`--known files hold ${items.length} items; the limit is ${MAX_KNOWN_ITEMS}.`);
  return { items, tools: [...tools], files: used };
}

/** The known items that sit in these files (a batch lists only its own), keeping those without a location out of it. */
export function knownIn(items: readonly KnownItem[], files: ReadonlySet<string>): KnownItem[] {
  return items.filter(item => item.path !== undefined && files.has(item.path));
}

export const PREPASS_ONLY_LABEL = "Pre-pass only, not reviewed by a model.";

/**
 * Scanner leads as findings, for a tier that runs the pattern scanners only. The same shape `0 findings import` stores for a
 * SARIF log, with the label on the description and in the evidence so no format can show one without it.
 */
export function leadsToFindings(leads: readonly ImportedFinding[], now: Date): Finding[] {
  const seen = new Set<string>();
  return leads.map((item, index) => {
    let key = item.fingerprint.replace(/^sarif:/, "");
    if (seen.has(key)) key = `${key}-${index}`;
    seen.add(key);
    const id = `prepass-${createHash("sha256").update(key).digest("hex").slice(0, 16)}`;
    const where = locationLabel(item);
    return {
      id, fingerprint: `${id}`, templateId: `${item.tool}/${item.ruleId}`, title: item.title,
      description: `${PREPASS_ONLY_LABEL} ${item.description}`.trim(), category: item.category, severity: item.severity, tool: item.tool,
      evidence: { request: where, response: item.snippet ?? "", analysis: `${PREPASS_ONLY_LABEL} Reported by ${item.tool}${item.toolVersion ? ` ${item.toolVersion}` : ""}; the pattern may be wrong.${item.cwe.length ? ` ${item.cwe.join(", ")}.` : ""}` },
      ...(item.path && item.startLine ? { reviewAnnotation: { path: item.path, startLine: item.startLine, ...(item.endLine && item.endLine >= item.startLine ? { endLine: item.endLine } : {}) } } : {}),
      timestamp: now.getTime(), status: "discovered", triageStatus: "new", workflowStatus: "backlog",
    } as Finding;
  });
}
