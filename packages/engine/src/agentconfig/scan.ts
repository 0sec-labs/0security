/**
 * Reads the files AI coding tools take instructions and configuration from, as text, and reports what could steer or endanger an agent.
 * Nothing is executed, imported or downloaded, there is no model call and no network use, and the walk stays inside the folder.
 */
import { closeSync, constants as fsConstants, fstatSync, lstatSync, opendirSync, openSync, readSync, realpathSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { scanInjection } from "./injection.js";
import { extractMcpServers, scanMcp } from "./mcp.js";
import type { AgentConfigFinding } from "./rules.js";
import { scanAllowedTools, scanSettings } from "./settings.js";
import { parseSimpleToml } from "./toml.js";
import { scanHiddenUnicode } from "./unicode.js";
import { finding, parseJsonc } from "./util.js";

export const MAX_FILE_BYTES = 1024 * 1024;
export const MAX_ENTRIES = 60_000;
export const MAX_FILES = 1500;
/** The most bytes read from all files in one scan. */
export const MAX_TOTAL_BYTES = 64 * 1024 * 1024;
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
  /** Stop reading once this many bytes have been read in total (default 64 MiB). */
  maxTotalBytes?: number;
}
export interface SkippedFile { file: string; reason: "too-large" | "symlink" | "hardlinked" | "not-a-regular-file" | "unreadable" | "not-valid-json" | "budget" }
export interface AgentConfigReport {
  root: string;
  filesScanned: string[];
  findings: AgentConfigFinding[];
  skipped: SkippedFile[];
  /** True when the walk stopped at a limit, so some files were not looked at. */
  truncated: boolean;
}

/** UTF-16 files (with a byte order mark) are decoded as UTF-16, because a tool may read them that way; everything else is UTF-8. */
export function decodeText(buffer: Buffer): string {
  if (buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xfe) return buffer.subarray(2).toString("utf16le");
  if (buffer.length >= 2 && buffer[0] === 0xfe && buffer[1] === 0xff) { const swapped = Buffer.from(buffer.subarray(2)); swapped.swap16(); return swapped.toString("utf16le"); }
  return buffer.toString("utf8");
}

/** Opens without following a symbolic link, checks the open descriptor (not the path), and reads at most the limit. A FIFO or device is never read. */
function readText(path: string, limit: number): { text: string; bytes: number } | { reason: SkippedFile["reason"] } {
  let fd: number | undefined;
  try {
    fd = openSync(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0) | (fsConstants.O_NONBLOCK ?? 0));
    const info = fstatSync(fd);
    if (!info.isFile()) return { reason: "not-a-regular-file" };
    if (info.nlink > 1) return { reason: "hardlinked" };
    if (info.size > limit) return { reason: "too-large" };
    const buffer = Buffer.alloc(info.size);
    let read = 0;
    while (read < info.size) { const n = readSync(fd, buffer, read, info.size - read, read); if (n <= 0) break; read += n; }
    return { text: decodeText(buffer.subarray(0, read)), bytes: read };
  } catch { return { reason: "unreadable" }; } finally { if (fd !== undefined) try { closeSync(fd); } catch { /* already closed */ } }
}

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
  return { findings: findings.slice(0, 500), invalidJson };
}

const order = (a: AgentConfigFinding, b: AgentConfigFinding): number => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line || (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : a.message < b.message ? -1 : a.message > b.message ? 1 : 0));

export function scanAgentConfig(path: string, options: ScanOptions = {}): AgentConfigReport {
  const limit = options.maxFileBytes ?? MAX_FILE_BYTES;
  const start = resolve(path);
  const report: AgentConfigReport = { root: start, filesScanned: [], findings: [], skipped: [], truncated: false };
  let total = 0;
  const analyse = (real: string, rel: string): void => {
    if (total >= (options.maxTotalBytes ?? MAX_TOTAL_BYTES)) { report.truncated = true; report.skipped.push({ file: rel, reason: "budget" }); return; }
    const got = readText(real, limit);
    if ("reason" in got) { report.skipped.push({ file: rel, reason: got.reason }); return; }
    total += got.bytes;
    const { findings, invalidJson } = scanText(rel, got.text, options.allowHosts ? { allowHosts: options.allowHosts } : {});
    report.filesScanned.push(rel);
    report.findings.push(...findings);
    if (invalidJson) report.skipped.push({ file: rel, reason: "not-valid-json" });
  };
  const symlink = (rel: string): void => {
    report.skipped.push({ file: rel, reason: "symlink" });
    report.findings.push(finding("agent-config/symlinked-config", rel, 1, "", `${rel} is a symbolic link, so it was not read.`));
  };
  const first = lstatSync(start);
  if (first.isSymbolicLink()) { symlink(start.split(sep).pop()!); return report; }
  if (first.isFile()) {
    // A file named by the operator is scanned whatever its name is.
    analyse(start, start.split(sep).pop()!);
    report.findings.sort(order);
    return report;
  }
  const root = realpathSync(start);
  report.root = root;
  let entries = 0;
  const walk = (dir: string, base: string, depth: number): void => {
    if (report.truncated) return;
    // The folder must still be where the walk thinks it is: a folder swapped for a link after the check is not entered.
    try { if (realpathSync(dir) !== (base ? join(root, ...base.split("/")) : root)) return; } catch { return; }
    // Read entries one at a time so a folder with millions of files cannot be loaded whole.
    const names: string[] = [];
    try {
      const handle = opendirSync(dir);
      try { for (let entry = handle.readSync(); entry; entry = handle.readSync()) { if (++entries > MAX_ENTRIES) { report.truncated = true; break; } names.push(entry.name); } } finally { handle.closeSync(); }
    } catch { return; }
    names.sort();
    for (const name of names) {
      if (report.filesScanned.length + report.skipped.length >= MAX_FILES) { report.truncated = true; return; }
      const full = join(dir, name);
      const rel = base ? `${base}/${name}` : name;
      let info;
      try { info = lstatSync(full); } catch { continue; }
      if (info.isSymbolicLink()) { if (isAgentFile(rel) || rel.split("/").some(part => TOOL_DIRS.test(part))) symlink(rel); continue; }
      if (info.isDirectory()) {
        if (SKIP_DIRS.has(name) || name.startsWith(".venv") || depth >= MAX_DEPTH) continue;
        walk(full, rel, depth + 1);
      } else if (isAgentFile(rel)) { if (info.isFile()) analyse(full, rel); else report.skipped.push({ file: rel, reason: "not-a-regular-file" }); }
    }
  };
  walk(root, "", 0);
  report.findings.sort(order);
  return report;
}
