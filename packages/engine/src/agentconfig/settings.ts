import { launcherIssues } from "./launchers.js";
import type { AgentConfigFinding, AgentConfigSeverity } from "./rules.js";
import { finding, isObject, locator } from "./util.js";

/** Rules agent-config/broad-permission and agent-config/hook-command, for settings files of coding tools. */
const MAX_FINDINGS = 200;
const RISKY_PROGRAMS = new Set(["curl", "wget", "rm", "sudo", "sh", "bash", "zsh", "eval", "ssh", "scp", "nc", "ncat", "dd", "chmod", "chown", "powershell", "pwsh"]);
const NETWORK = /\b(?:curl|wget|nc|ncat|ssh|scp|sftp|ftp|telnet|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b|https?:\/\/|\b(?:fetch|requests\.(?:get|post)|urllib)\b/i;

/** Why a permission entry such as Bash(curl:*) lets an agent act without a meaningful check, or undefined when it is narrow. */
export function broadPermission(entry: string): string | undefined {
  const text = entry.trim();
  if (text === "*" || text === "**") return "allows every tool";
  const match = /^([A-Za-z_][\w.-]*)(?:\(([\s\S]*)\))?$/.exec(text);
  if (!match) return undefined;
  const tool = match[1]!;
  const inner = match[2]?.trim();
  if (tool.toLowerCase() === "bash" || tool.toLowerCase() === "shell") {
    if (inner === undefined || inner === "" || inner === "*" || inner === ":*" || inner === "**") return "allows any shell command";
    const program = /^([^\s:*]+)\s*(?::\*|\s\*|\*)?$/.exec(inner);
    if (program && RISKY_PROGRAMS.has(program[1]!.toLowerCase()) && /(?::\*|\s\*|\*)$/.test(inner)) return `allows ${program[1]} with any arguments`;
    if (/^(?:sh|bash|zsh)\s+-c\b/.test(inner)) return "allows any script string run through a shell";
  }
  return undefined;
}


export function scanSettings(file: string, text: string, parsed: unknown): AgentConfigFinding[] {
  const found: AgentConfigFinding[] = [];
  const where = locator(text);
  const full = (): boolean => found.length >= MAX_FINDINGS;
  const add = (needle: string, snippet: string, message: string, severity?: AgentConfigSeverity): void => { if (full()) return; found.push(finding("agent-config/broad-permission", file, where(needle), snippet, message, severity ? { severity } : {})); };
  const hook = (command: string, event: string): void => {
    if (full()) return;
    const line = where(JSON.stringify(command));
    const issues = launcherIssues(command).filter(issue => issue.severity === "high");
    const network = NETWORK.test(command);
    const severity: AgentConfigSeverity = issues.length ? "high" : network ? "medium" : "low";
    const detail = issues.length ? "downloads a script and runs it" : network ? "uses the network" : "runs a shell command";
    found.push(finding("agent-config/hook-command", file, line, command, `Hook${event ? ` for ${event}` : ""} ${detail}: ${command.length > 120 ? `${command.slice(0, 117)}...` : command}`, { severity }));
  };
  const walk = (node: unknown, path: string[], depth: number): void => {
    if (depth > 12 || full()) return;
    if (Array.isArray(node)) { node.slice(0, 500).forEach((item, index) => walk(item, [...path, String(index)], depth + 1)); return; }
    if (!isObject(node)) return;
    const inHooks = path.includes("hooks");
    for (const [key, value] of Object.entries(node).slice(0, 1000)) {
      const here = [...path, key];
      const dotted = here.join(".");
      if (key === "allow" && path[path.length - 1] === "permissions" && Array.isArray(value)) { // Claude Code and Cursor CLI: permissions.allow
        for (const entry of value.slice(0, 500)) if (typeof entry === "string") { const why = broadPermission(entry); if (why) add(JSON.stringify(entry), entry, `Permission ${entry} ${why}.`); }
      }
      if (key === "defaultMode" && value === "bypassPermissions") add(JSON.stringify(value), `${key}: ${value}`, "defaultMode bypassPermissions turns off permission prompts. Claude Code ignores it in project settings files, so remove it.", "medium");
      if (key === "skipDangerousModePermissionPrompt" && value === true) add(JSON.stringify(key), `${key}: true`, "skipDangerousModePermissionPrompt hides the warning that Claude Code shows before bypass permissions mode.", "medium");
      if (key === "enableAllProjectMcpServers" && value === true) add(JSON.stringify(key), `${key}: true`, "enableAllProjectMcpServers approves every server in the project .mcp.json without a prompt once the folder is trusted.");
      if (key === "enabledMcpjsonServers" && Array.isArray(value) && value.length) add(JSON.stringify(key), `${key}: ${value.slice(0, 5).map(String).join(", ")}`, `enabledMcpjsonServers pre-approves ${value.length} MCP server${value.length === 1 ? "" : "s"} defined in the repository.`, "medium");
      if (key === "trust" && value === true && path.some(part => /mcp/i.test(part))) add(JSON.stringify(key), `${dotted}: true`, `MCP server "${path[path.length - 1]}" is trusted, so its tool calls skip confirmation.`);
      if ((key === "chat.tools.global.autoApprove" && value === true) || (key === "chat.tools.terminal.autoApprove" && isObject(value) && Object.entries(value).some(([k, v]) => v === true && /^\/?\.\*\/?$/.test(k)))) add(JSON.stringify(key), `${key}: ${value === true ? "true" : "a rule that matches every command"}`, `${key} approves agent actions without asking. The VS Code documentation says to set it in User settings.`);
      if ((key === "approval_policy" && value === "never") || (key === "sandbox_mode" && value === "danger-full-access")) add(JSON.stringify(key), `${key} = ${String(value)}`, `${key} ${String(value)} removes the check before an agent runs commands.`);
      if (key === "hooks" && !inHooks) hookTree(value, "");
      if (typeof value === "string" && /--dangerously-skip-permissions|--allow-dangerously-skip-permissions|--yolo\b|--trust-all-tools/.test(value)) add(JSON.stringify(value), `${dotted}: ${value.slice(0, 120)}`, `${dotted} passes a flag that turns off the permission check.`);
      walk(value, here, depth + 1);
    }
  };
  const hookTree = (node: unknown, event: string, depth = 0): void => {
    if (depth > 12 || full()) return;
    if (Array.isArray(node)) { node.slice(0, 500).forEach(item => hookTree(item, event, depth + 1)); return; }
    if (!isObject(node)) return;
    for (const [key, value] of Object.entries(node)) {
      if (typeof value === "string" && key === "command") hook(value, event);
      else hookTree(value, event || key, depth + 1);
    }
  };
  walk(parsed, [], 0);
  return found;
}

/** `allowed-tools` in the front matter of a command, agent or skill file. */
export function scanAllowedTools(file: string, text: string): AgentConfigFinding[] {
  const head = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text.replace(/^﻿/, ""));
  if (!head) return [];
  const where = locator(text);
  const found: AgentConfigFinding[] = [];
  const match = /^allowed-tools\s*:\s*(.*)$/im.exec(head[1]!);
  if (!match) return [];
  const listed = match[1]!.trim() ? match[1]! : (head[1]!.slice(match.index + match[0].length).match(/^(?:\s*-\s+.*(?:\r?\n|$))+/)?.[0] ?? "").replace(/^\s*-\s+/gm, ",");
  const entries: string[] = [];
  let depth = 0, current = "";
  for (const ch of listed.replace(/^\[|\]$/g, "")) {
    if (ch === "(") depth++; if (ch === ")") depth = Math.max(0, depth - 1);
    if ((ch === "," || ch === "\n" || /\s/.test(ch)) && depth === 0) { entries.push(current); current = ""; } else current += ch;
  }
  entries.push(current);
  for (const raw of entries) {
    const entry = raw.trim().replace(/^["']|["']$/g, "");
    const why = entry ? broadPermission(entry) : undefined;
    if (why) found.push(finding("agent-config/broad-permission", file, where(entry), `allowed-tools: ${entry}`, `allowed-tools ${entry} ${why}.`));
  }
  return found;
}
