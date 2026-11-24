/**
 * Reads the files AI coding tools take instructions and configuration from, as text, and reports what could steer or endanger an agent.
 * Nothing is executed, imported or downloaded, there is no model call and no network use, and the walk stays inside the folder.
 */
import { closeSync, fstatSync, lstatSync, openSync, readSync, realpathSync, readdirSync } from "node:fs";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { scanInjection } from "./injection.js";
import { extractMcpServers, scanMcp } from "./mcp.js";
import type { AgentConfigFinding } from "./rules.js";
import { scanAllowedTools, scanSettings } from "./settings.js";
import { parseSimpleToml } from "./toml.js";
import { scanHiddenUnicode } from "./unicode.js";
import { parseJsonc } from "./util.js";

export const MAX_FILE_BYTES = 1024 * 1024;
export const MAX_ENTRIES = 60_000;
export const MAX_FILES = 1500;
const MAX_DEPTH = 14;
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "target", "vendor", ".venv", "venv", "__pycache__", ".next", ".turbo", "coverage", ".cache", ".tox", "bower_components", ".gradle", ".idea"]);
const TOOL_DIRS = /^\.(?:cursor|claude|gemini|codex|windsurf|continue|github|vscode|clinerules)$/i;
const TEXT = /\.(?:md|mdc|markdown|txt|json|jsonc|toml|ya?ml)$/i;

/** Paths (lowercase, forward slashes) of the files agents read. Matched anywhere in the tree, so a monorepo's nested files count. */
const AGENT_FILES: RegExp[] = [
  /(?:^|\/)(?:claude|agents|gemini)\.md$/, /(?:^|\/)claude\.local\.md$/, /(?:^|\/)\.cursorrules$/, /(?:^|\/)\.clinerules(?:\/.+)?$/, /(?:^|\/)opencode\.jsonc?$/,
  /(?:^|\/)\.cursor\/(?:rules\/.+|mcp\.json|cli\.json|hooks\.json)$/,
  /(?:^|\/)\.github\/(?:copilot-instructions\.md|instructions\/.+|prompts\/.+|agents\/.+)$/,
  /(?:^|\/)\.claude\/(?:settings(?:\.local)?\.json|commands\/.+|agents\/.+|skills\/.+)$/,
  /(?:^|\/)\.(?:gemini|codex|windsurf|continue)\/.+/,
  /(?:^|\/)\.vscode\/(?:mcp|settings)\.json$/, /(?:^|\/)\.?mcp\.json$/, /(?:^|\/)skill\.md$/, /(?:^|\/)skills\/[^/]+\/.+\.md$/,
];
export const isAgentFile = (rel: string): boolean => AGENT_FILES.some(pattern => pattern.test(rel.toLowerCase())) && (TEXT.test(rel) || !/[^.]\.[a-z0-9]+$/i.test(rel.split("/").pop()!));

export interface ScanOptions {
  /** Hosts a remote MCP server may use; `*.example.com` allows subdomains. */
  allowHosts?: readonly string[];
  maxFileBytes?: number;
}
export interface SkippedFile { file: string; reason: "too-large" | "symlink-outside" | "not-a-regular-file" | "unreadable" | "not-valid-json" }
export interface AgentConfigReport {
  root: string;
  filesScanned: string[];
  findings: AgentConfigFinding[];
  skipped: SkippedFile[];
  /** True when the walk stopped at a limit, so some files were not looked at. */
  truncated: boolean;
}

function readText(path: string, limit: number): { text: string } | { reason: SkippedFile["reason"] } {
  let fd: number | undefined;
  try {
    fd = openSync(path, "r");
    const info = fstatSync(fd);
    if (!info.isFile()) return { reason: "not-a-regular-file" };
    if (info.size > limit) return { reason: "too-large" };
    const buffer = Buffer.alloc(info.size);
    let read = 0;
    while (read < info.size) { const n = readSync(fd, buffer, read, info.size - read, read); if (n <= 0) break; read += n; }
    return { text: buffer.subarray(0, read).toString("utf8") };
  } catch { return { reason: "unreadable" }; } finally { if (fd !== undefined) try { closeSync(fd); } catch { /* already closed */ } }
}

const inside = (root: string, target: string): boolean => { const rel = relative(root, target); return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel)); };

/** Analyses one file's text. Pure: the same text and path give the same findings. */
export function scanText(rel: string, text: string, options: Pick<ScanOptions, "allowHosts"> = {}): { findings: AgentConfigFinding[]; invalidJson: boolean } {
  const findings: AgentConfigFinding[] = [...scanHiddenUnicode(rel, text), ...scanInjection(rel, text)];
  const lower = rel.toLowerCase();
  let invalidJson = false;
  if (/\.(?:json|jsonc)$/.test(lower) || /\.toml$/.test(lower)) {
    const parsed = lower.endsWith(".toml") ? parseSimpleToml(text) : parseJsonc(text);
    if (parsed === undefined) invalidJson = true;
    else { findings.push(...scanSettings(rel, text, parsed), ...scanMcp(rel, text, extractMcpServers(parsed), options.allowHosts ? { allowHosts: options.allowHosts } : {})); }
  } else if (/\.(?:md|mdc|markdown)$/.test(lower)) findings.push(...scanAllowedTools(rel, text));
  return { findings, invalidJson };
}

const order = (a: AgentConfigFinding, b: AgentConfigFinding): number => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line || (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : a.message < b.message ? -1 : a.message > b.message ? 1 : 0));

export function scanAgentConfig(path: string, options: ScanOptions = {}): AgentConfigReport {
  const limit = options.maxFileBytes ?? MAX_FILE_BYTES;
  const start = resolve(path);
  const report: AgentConfigReport = { root: start, filesScanned: [], findings: [], skipped: [], truncated: false };
  const first = lstatSync(start);
  const analyse = (real: string, rel: string): void => {
    const got = readText(real, limit);
    if ("reason" in got) { report.skipped.push({ file: rel, reason: got.reason }); return; }
    const { findings, invalidJson } = scanText(rel, got.text, options.allowHosts ? { allowHosts: options.allowHosts } : {});
    report.filesScanned.push(rel);
    report.findings.push(...findings);
    if (invalidJson) report.skipped.push({ file: rel, reason: "not-valid-json" });
  };
  if (first.isFile()) {
    // A file named by the operator is scanned whatever its name is.
    const name = start.split(sep).pop()!;
    analyse(start, name);
    report.findings.sort(order);
    report.root = start;
    return report;
  }
  const root = realpathSync(start);
  report.root = root;
  const seen = new Set<string>([root]);
  let entries = 0;
  const walk = (dir: string, depth: number): void => {
    if (report.truncated) return;
    let names: string[];
    try { names = readdirSync(dir).sort(); } catch { return; }
    for (const name of names) {
      if (++entries > MAX_ENTRIES || report.filesScanned.length + report.skipped.length >= MAX_FILES) { report.truncated = true; return; }
      const full = join(dir, name);
      const rel = relative(root, full).split(sep).join("/");
      let info;
      try { info = lstatSync(full); } catch { continue; }
      let real = full;
      if (info.isSymbolicLink()) {
        try { real = realpathSync(full); } catch { continue; }
        if (!inside(root, real)) { if (isAgentFile(rel) || rel.split("/").some(part => TOOL_DIRS.test(part))) report.skipped.push({ file: rel, reason: "symlink-outside" }); continue; }
        try { info = lstatSync(real); } catch { continue; }
      }
      if (info.isDirectory()) {
        if (SKIP_DIRS.has(name) || name.startsWith(".venv") || depth >= MAX_DEPTH || seen.has(real)) continue;
        seen.add(real);
        walk(real === full ? full : real, depth + 1);
      } else if (info.isFile() && isAgentFile(rel)) analyse(real, rel);
      else if (isAgentFile(rel) && !info.isFile()) report.skipped.push({ file: rel, reason: "not-a-regular-file" });
    }
  };
  walk(root, 0);
  report.findings.sort(order);
  return report;
}
