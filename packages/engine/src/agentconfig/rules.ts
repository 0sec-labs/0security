/**
 * The agent-config rules: what each one looks for, which incident or reference it comes from, and what to do about it.
 * Every finding carries its rule's explanation and fix hint. The scanner reads files as text and never runs anything.
 */
export type AgentConfigSeverity = "critical" | "high" | "medium" | "low" | "info";
export const SEVERITIES: readonly AgentConfigSeverity[] = ["critical", "high", "medium", "low", "info"];

export interface AgentConfigRule {
  id: string;
  title: string;
  /** The usual severity. A finding can be higher or lower when the evidence says so. */
  severity: AgentConfigSeverity;
  /** True when the rule matches wording or shape and is not a fact about the file. */
  heuristic: boolean;
  cwe: string[];
  /** Why this matters, citing the incident or reference. */
  explanation: string;
  fix: string;
}

export interface AgentConfigFinding {
  ruleId: string;
  severity: AgentConfigSeverity;
  heuristic: boolean;
  /** Path relative to the scanned folder, with forward slashes. */
  file: string;
  line: number;
  column?: number;
  /** The matching text. Secrets are never included; see the secrets rule. */
  snippet: string;
  /** What was found, for this file. */
  message: string;
  cwe: string[];
  explanation: string;
  fix: string;
}

const r = (rule: AgentConfigRule): AgentConfigRule => rule;

export const RULES: readonly AgentConfigRule[] = [
  r({
    id: "agent-config/hidden-unicode", title: "Hidden or bidirectional Unicode in an instruction file", severity: "high", heuristic: false, cwe: ["CWE-1007"],
    explanation: "AI coding tools read instruction files as one stream of text, so characters a person cannot see can carry instructions. This is the rules file backdoor disclosed by Pillar Security in 2025: zero-width and bidirectional characters hid a prompt in a rules file. Unicode tag characters (U+E0000 to U+E007F) can spell out a full hidden prompt, and Trojan Source (CVE-2021-42574) uses bidirectional overrides to change how text reads. A zero-width joiner inside an emoji sequence and one leading byte order mark are normal and are not reported.",
    fix: "Open the file in an editor that shows invisible characters, delete the listed code points and review the surrounding text. Find out how they got in before you trust the file.",
  }),
  r({
    id: "agent-config/injection-phrase", title: "Wording that tries to steer or deceive an agent (heuristic)", severity: "low", heuristic: true, cwe: ["CWE-1427"],
    explanation: "Text an agent reads can tell it to ignore its earlier instructions, to hide what it does from the user, or to send secrets to a URL. Tool poisoning attacks on MCP servers (Invariant Labs, 2025) and the prompt injection shipped in the Amazon Q Developer extension (2025) used wording of this kind. This rule matches phrases, so it can fire on harmless text and can miss a rephrased attack. In files written as rules (for example CLAUDE.md) it reports only text that is hidden in an HTML comment or encoded.",
    fix: "Read the text in context. Remove it if you did not write it. Keep it if it is a legitimate instruction and you accept the wording.",
  }),
  r({
    id: "agent-config/mcp-unpinned-launcher", title: "MCP server or command that fetches code that can change", severity: "medium", heuristic: false, cwe: ["CWE-494"],
    explanation: "A launcher such as npx, uvx, bunx, pipx run, pnpm dlx, yarn dlx or docker run downloads and runs whatever the package or tag points to at that moment. A version that is not exact, or the tag latest, lets a later publish change what runs on your machine. The Nx s1ngularity attack (2025) shipped malware through a published package, and a configuration approved once and changed later is the MCPoison pattern (CVE-2025-54136). Piping curl into a shell is the same risk with no record at all.",
    fix: "Pin an exact version (package@1.2.3 or package==1.2.3) or an image digest (image@sha256:...). Download scripts, review them and run them from a file.",
  }),
  r({
    id: "agent-config/mcp-secret", title: "Secret in an MCP server's env or headers", severity: "high", heuristic: false, cwe: ["CWE-798"],
    explanation: "A token written into a configuration file is stored in git history and read by every tool and person with the repository. The finding shows only the first characters and the length of the value, never the value. It matches well-known provider key shapes, and long high-entropy values in env or headers, so a random-looking value that is not a secret can be reported.",
    fix: "Revoke the token and issue a new one. Read it from the environment instead, for example ${API_TOKEN} in tools that expand variables. Remove the old value from history.",
  }),
  r({
    id: "agent-config/broad-permission", title: "Permission or auto-approval that lets an agent act without asking", severity: "high", heuristic: false, cwe: ["CWE-250"],
    explanation: "Settings such as Bash(*), Bash(curl:*), Bash(rm:*), bypassPermissions, --dangerously-skip-permissions, enableAllProjectMcpServers, enabledMcpjsonServers, a Cursor yolo or auto-run mode or Copilot chat.tools.autoApprove remove the prompt that stops an injected instruction from running a command. The Nx s1ngularity malware (2025) started local AI command line tools with flags like these to search for secrets. A setting committed to the repository applies to everyone who opens it.",
    fix: "Allow only the exact commands you need, for example Bash(git status). Remove blanket allows and auto-approval from files in the repository. Set personal choices in your user settings.",
  }),
  r({
    id: "agent-config/hook-command", title: "Hook that runs a shell command on an agent event", severity: "low", heuristic: false, cwe: ["CWE-78"],
    explanation: "A hook runs a command with your permissions each time an agent event fires, for example before or after a tool call. A hook committed to the repository runs for everyone who opens it and trusts the project. Every hook is listed with its command. A hook that uses the network is reported as medium, and one that pipes a download into a shell as high.",
    fix: "Read each command. Remove hooks you do not recognise. Keep hooks local, short and free of network calls and downloaded scripts.",
  }),
  r({
    id: "agent-config/mcp-remote-insecure", title: "Remote MCP server over plain http or on a host you did not allow", severity: "medium", heuristic: false, cwe: ["CWE-319"],
    explanation: "A remote MCP server supplies the tool descriptions and results an agent trusts. Over plain http, anyone on the path can change them. A host you have not allowed can change them as well, which is how tool poisoning works. Plain http to localhost is not reported. Pass --allow-host to list the hosts you accept; without it only plain http is reported.",
    fix: "Use https. Add the host to the list you pass with --allow-host after you have checked who runs it, or remove the server.",
  }),
  r({
    id: "agent-config/mcp-project-autostart", title: "MCP server defined in the repository (requires approval in your tool; verify)", severity: "low", heuristic: false, cwe: ["CWE-829"],
    explanation: "A server defined in a project file is started or contacted by the tool when someone opens the repository, usually after an approval prompt. Cursor shipped flaws where an approved configuration could be swapped without a new prompt (MCPoison, CVE-2025-54136) and where a message could write a configuration (CVE-2025-54135). This finding does not say the server is unsafe. It says a person must check it before approving.",
    fix: "Check the command, arguments and host of each server before you approve it. Re-check after every pull that changes the file.",
  }),
  r({
    id: "agent-config/symlinked-config", title: "Agent file or folder that is a symbolic link", severity: "medium", heuristic: false, cwe: ["CWE-59"],
    explanation: "This scan never follows a symbolic link, so it cannot judge what the link points to. A tool that does follow it reads the target as instructions or settings. A link in a repository can point at a file the scan never sees, or outside the repository. Hidden settings behind a link would otherwise pass the scan.",
    fix: "Replace the link with the real file, or scan the folder it points to as well. Remove the link if you do not know why it is there.",
  }),
];

const byId = new Map(RULES.map(rule => [rule.id, rule] as const));
export const ruleOf = (id: string): AgentConfigRule => byId.get(id)!;
