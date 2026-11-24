import { launcherIssues } from "./launchers.js";
import type { AgentConfigFinding } from "./rules.js";
import { looksLikeSecret, providerShape } from "./secrets.js";
import { finding, isObject, locator } from "./util.js";

/** One MCP server entry, whatever tool's file it came from. */
export interface McpServer {
  name: string;
  /** The program followed by its arguments. */
  command?: string[];
  url?: string;
  env: Record<string, string>;
  headers: Record<string, string>;
  disabled: boolean;
}

const strings = (value: unknown): Record<string, string> => Object.fromEntries(Object.entries(isObject(value) ? value : {}).filter(([, v]) => typeof v === "string" || typeof v === "number").map(([k, v]) => [k, String(v)]));

function entryOf(name: string, raw: unknown): McpServer | undefined {
  if (!isObject(raw)) return undefined;
  const args = Array.isArray(raw.args) ? raw.args.map(String) : [];
  const command = Array.isArray(raw.command) ? raw.command.map(String) : typeof raw.command === "string" ? [raw.command, ...args] : undefined;
  const url = [raw.url, raw.serverUrl, raw.httpUrl, raw.baseUrl].find((item): item is string => typeof item === "string");
  if (!command && !url) return undefined;
  return { name, ...(command ? { command } : {}), ...(url ? { url } : {}), env: strings(raw.env ?? raw.environment), headers: strings(raw.headers ?? raw.http_headers), disabled: raw.disabled === true || raw.enabled === false };
}

/** Finds the server tables in the places the supported tools keep them: mcpServers, servers, mcp (opencode, VS Code settings) and mcp_servers (Codex). */
export function extractMcpServers(parsed: unknown): McpServer[] {
  if (!isObject(parsed)) return [];
  const tables: unknown[] = [parsed.mcpServers, parsed.mcp_servers, parsed.servers];
  if (isObject(parsed.mcp)) tables.push(isObject(parsed.mcp.servers) ? parsed.mcp.servers : parsed.mcp);
  const out: McpServer[] = [];
  for (const table of tables) if (isObject(table)) for (const [name, raw] of Object.entries(table).slice(0, 200)) { const entry = entryOf(name, raw); if (entry) out.push(entry); }
  return out;
}

const LOOPBACK = /^(?:localhost|.*\.localhost|127(?:\.\d{1,3}){3}|\[?::1\]?)$/i;
const hostAllowed = (host: string, allow: readonly string[]): boolean => allow.some(entry => { const a = entry.toLowerCase(); return a.startsWith("*.") ? host.endsWith(a.slice(1)) : host === a; });

export function scanMcp(file: string, text: string, servers: McpServer[], options: { allowHosts?: readonly string[] }): AgentConfigFinding[] {
  const found: AgentConfigFinding[] = [];
  const where = locator(text);
  for (const server of servers) {
    const line = where(JSON.stringify(server.name));
    const label = `MCP server "${server.name}"`;
    const full = server.command?.join(" ");
    if (server.command && full) {
      for (const issue of launcherIssues(full)) found.push(finding("agent-config/mcp-unpinned-launcher", file, where(JSON.stringify(server.command[0]!)) || line, full, `${label} runs ${issue.launcher} with ${issue.spec}: ${issue.reason}.`, { severity: issue.severity }));
      for (const arg of server.command.slice(1)) { const kind = providerShape(arg.replace(/^--?[\w-]+=/, "")); if (kind) found.push(finding("agent-config/mcp-secret", file, where(JSON.stringify(arg)), "(argument)", `${label} has a ${kind} in its arguments.`)); }
    }
    for (const [section, table] of [["env", server.env], ["headers", server.headers]] as const) {
      for (const [key, raw] of Object.entries(table)) {
        const secret = looksLikeSecret(raw);
        if (secret) found.push(finding("agent-config/mcp-secret", file, where(JSON.stringify(key)), `${section}.${key} = ${secret.redacted}`, `${label} has a ${secret.kind} in ${section}.${key}: ${secret.redacted}.`, { severity: secret.kind === "high-entropy value" ? "medium" : "high" }));
      }
    }
    if (server.url) {
      let parsed: URL | undefined;
      try { parsed = new URL(server.url); } catch { /* not a URL: nothing to judge */ }
      const urlLine = where(JSON.stringify(server.url));
      if (parsed) {
        const host = parsed.hostname.toLowerCase();
        const plain = parsed.protocol === "http:" || parsed.protocol === "ws:";
        if (plain && !LOOPBACK.test(host)) found.push(finding("agent-config/mcp-remote-insecure", file, urlLine, `${parsed.protocol}//${host}${parsed.port ? `:${parsed.port}` : ""}`, `${label} connects to ${host} over plain ${parsed.protocol.slice(0, -1)}.`));
        else if (options.allowHosts?.length && !LOOPBACK.test(host) && !hostAllowed(host, options.allowHosts)) found.push(finding("agent-config/mcp-remote-insecure", file, urlLine, `${parsed.protocol}//${host}`, `${label} connects to ${host}, which is not in the allowed hosts.`));
        for (const [key, raw] of parsed.searchParams) {
          const secret = /key|token|secret|auth|password|sig/i.test(key) ? looksLikeSecret(raw) : providerShape(raw) ? looksLikeSecret(raw) : undefined;
          if (secret) found.push(finding("agent-config/mcp-secret", file, urlLine, `url query ${key} = ${secret.redacted}`, `${label} has a ${secret.kind} in the URL query "${key}": ${secret.redacted}.`, { severity: secret.kind === "high-entropy value" ? "medium" : "high" }));
        }
        if (parsed.password) found.push(finding("agent-config/mcp-secret", file, urlLine, "url password", `${label} has a password in its URL.`));
      }
    }
    if (!server.disabled) found.push(finding("agent-config/mcp-project-autostart", file, line, full ?? server.url ?? "", `${label} is defined in the repository and ${server.command ? "starts a local process" : "connects to a remote host"} when a tool loads this project. Requires approval in your tool; verify.`));
  }
  return found;
}
