/**
 * How much of a small folder a one-thread scan looked at. A scan that records nothing and never named most of the
 * source files in a command or tool call has not shown that the code is clean, so the report says which files were not opened.
 * The check reads the thread's tool calls (the model opens files with `cat`, `sed` or a read tool), so it is a
 * heuristic: a file read through a glob or a recursive search is not seen and is listed as not opened.
 */
import { buildInventory } from "@0/engine";

export interface ReviewDepth {
  /** Source files the inventory found in the folder (or in the changed files). */
  sourceFiles: number;
  /** How many of them a tool call of the thread named. */
  opened: number;
  /** The source files no tool call named (at most 25). */
  notOpened: string[];
}

type Json = Record<string, unknown>;

/** The text of every tool call the thread made (the inputs only, not what came back, so a file listing does not count as opening). */
export function toolCallText(snapshot: Json): string {
  const messages = Array.isArray(snapshot.messages) ? snapshot.messages as Json[] : [];
  const parts: string[] = [];
  for (const message of messages) {
    if (message.role !== "assistant" || !Array.isArray(message.content)) continue;
    for (const block of message.content as Json[]) if (block.type === "tool_use" && block.input !== undefined) parts.push(JSON.stringify(block.input));
  }
  return parts.join("\n").replace(/\\\//g, "/");
}

/** The shell globs in the calls (such as routes/*.js), as patterns over a path relative to the folder. A glob without a slash matches in the top folder only. */
function globPatterns(calls: string): RegExp[] {
  const found = new Set<string>();
  // A pattern given to find or a search tool (-name '*.js', --glob '!x/*') selects files to list, not files to read.
  for (const match of calls.matchAll(/[\w.\-/]*\*[\w.\-/*]*/g)) {
    if (!/(?:-i?name|-i?path|-g|--glob|--include|--exclude)[\s=]*['"\\]*!?$/.test(calls.slice(Math.max(0, match.index - 24), match.index))) found.add(match[0]);
  }
  const patterns: RegExp[] = [];
  for (const raw of found) {
    const glob = raw.replace(/^\.\//, "");
    if (glob.replace(/[*/.]/g, "") === "" && glob !== "*") continue;
    const source = glob.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*\*\//g, "\u0000").replace(/\*/g, "[^/]*").replace(/\u0000/g, "(?:.*/)?");
    patterns.push(new RegExp(`^${source}$`));
  }
  return patterns;
}

/** Which source files of `folder` the tool calls named, or undefined when the folder has no source files. */
export function reviewDepth(folder: string, calls: string, scope?: readonly string[]): ReviewDepth | undefined {
  const inventory = buildInventory(folder, scope ? { only: new Set(scope) } : {});
  const files = new Set<string>();
  for (const unit of inventory.units) { if (unit.files) for (const file of unit.files) files.add(file); else files.add(unit.path); }
  if (!files.size) return undefined;
  const globs = globPatterns(calls);
  const notOpened = [...files].sort().filter(file => !calls.includes(file) && !calls.includes(file.slice(file.lastIndexOf("/") + 1)) && !globs.some(pattern => pattern.test(file)));
  return { sourceFiles: files.size, opened: files.size - notOpened.length, notOpened: notOpened.slice(0, 25) };
}

/** The warning for a scan that found nothing and did not open every source file, or undefined when it did. */
export function shallowReviewWarning(depth: ReviewDepth | undefined): string | undefined {
  if (!depth || !depth.notOpened.length) return undefined;
  const unopened = depth.sourceFiles - depth.opened;
  return `Shallow review: no findings, and the scan opened ${depth.opened} of ${depth.sourceFiles} source file${depth.sourceFiles === 1 ? "" : "s"}. Not opened: ${depth.notOpened.join(", ")}${unopened > depth.notOpened.length ? `, and ${unopened - depth.notOpened.length} more` : ""}. A scan that did not open the code says nothing about it; run it again or use --passes 2.`;
}
