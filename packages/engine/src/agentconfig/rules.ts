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
  /** Primary sources for the rule's claims (advisories, vendor documentation, research posts). Never empty. */
  reference: string[];
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

// Every claim in an explanation below is taken from the sources listed in its reference field, checked against those pages.
// Where a source does not say something, the explanation does not either.
export const RULES: readonly AgentConfigRule[] = [
  r({
    id: "agent-config/hidden-unicode", title: "Hidden or bidirectional Unicode in an instruction file", severity: "high", heuristic: false, cwe: ["CWE-451"],
    // https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents (rules file backdoor, March 2025)
    // https://nvd.nist.gov/vuln/detail/CVE-2021-42574 and https://trojansource.codes/ (bidirectional control characters)
    // https://en.wikipedia.org/wiki/Tags_(Unicode_block) (tag characters, flag emoji sequences)
    reference: [
      "https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents",
      "https://nvd.nist.gov/vuln/detail/CVE-2021-42574",
      "https://trojansource.codes/",
      "https://en.wikipedia.org/wiki/Tags_(Unicode_block)",
    ],
    explanation: "AI coding tools read rules and instruction files as plain text, so characters a person cannot see can carry instructions. Pillar Security (March 2025) described a rules file backdoor: instructions hidden in rule files for GitHub Copilot and Cursor with invisible characters such as zero-width joiners and bidirectional text markers. Bidirectional control characters can also make text read differently from how a program processes it (Trojan Source, CVE-2021-42574). Unicode tag characters were designed to tag text invisibly. This rule reports all of these, and variation selectors that are not part of an emoji or ideograph sequence. A zero-width joiner inside an emoji sequence, a flag tag sequence and one leading byte order mark are normal and are not reported.",
    fix: "Open the file in an editor that shows invisible characters, delete the listed code points and review the surrounding text. Find out how they got in before you trust the file.",
  }),
  r({
    id: "agent-config/injection-phrase", title: "Wording that tries to steer or deceive an agent (heuristic)", severity: "low", heuristic: true, cwe: ["CWE-1427"],
    // https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks (tool poisoning, April 2025)
    // https://cwe.mitre.org/data/definitions/1427.html
    reference: ["https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks", "https://cwe.mitre.org/data/definitions/1427.html"],
    explanation: "Text an agent reads can tell it to ignore its earlier instructions, to keep something from the user, or to send data to a URL. Invariant Labs (April 2025) described tool poisoning: malicious instructions placed in an MCP tool description, which the model reads and the user usually does not see. This rule matches phrases, so it can fire on harmless text and can miss a rephrased attack. In files written as rules (for example CLAUDE.md) it reports only text that is hidden in an HTML comment or encoded.",
    fix: "Read the text in context. Remove it if you did not write it. Keep it if it is a legitimate instruction and you accept the wording.",
  }),
  r({
    id: "agent-config/mcp-unpinned-launcher", title: "MCP server or command that fetches code that can change", severity: "medium", heuristic: false, cwe: ["CWE-494"],
    // https://github.com/cursor/cursor/security/advisories/GHSA-24mc-g4xr-4395 (CVE-2025-54136: a trusted MCP configuration changed to a malicious command without a new prompt)
    // https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c (malicious Nx versions published to npm, August 2025)
    reference: [
      "https://github.com/cursor/cursor/security/advisories/GHSA-24mc-g4xr-4395",
      "https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c",
      "https://cwe.mitre.org/data/definitions/494.html",
    ],
    explanation: "A launcher such as npx, uvx, bunx, pipx run, pnpm dlx, yarn dlx or docker run downloads and runs whatever the package or tag points to at that moment. A version that is not exact, or the tag latest, lets a later publish change what runs on your machine. In August 2025 malicious versions of Nx were published to npm (GHSA-cxm3-wv7p-598c). CVE-2025-54136 is a Cursor flaw where an approved MCP configuration could be changed to a different command without a new prompt. Piping curl into a shell runs a script nobody reviewed.",
    fix: "Pin an exact version (package@1.2.3 or package==1.2.3) or an image digest (image@sha256:...). Download scripts, review them and run them from a file.",
  }),
  r({
    id: "agent-config/mcp-secret", title: "Secret in an MCP server's env or headers", severity: "high", heuristic: false, cwe: ["CWE-798"],
    // https://cwe.mitre.org/data/definitions/798.html
    reference: ["https://cwe.mitre.org/data/definitions/798.html"],
    explanation: "A token written into a configuration file is stored in git history and read by every tool and person with the repository. The finding shows only the first characters and the length of the value, never the value. It matches well-known provider key shapes, and long high-entropy values in env or headers, so a random-looking value that is not a secret can be reported.",
    fix: "Revoke the token and issue a new one. Read it from the environment instead, for example ${API_TOKEN} in tools that expand variables. Remove the old value from history.",
  }),
  r({
    id: "agent-config/broad-permission", title: "Permission or auto-approval that lets an agent act without asking", severity: "high", heuristic: false, cwe: ["CWE-250"],
    // Claude Code: https://code.claude.com/docs/en/permissions.md (Bash(*) is equivalent to Bash; the :* suffix), https://code.claude.com/docs/en/cli-reference.md (--dangerously-skip-permissions),
    //   https://code.claude.com/docs/en/settings-reference.md (enableAllProjectMcpServers, enabledMcpjsonServers), https://code.claude.com/docs/en/permission-modes.md (defaultMode bypassPermissions)
    // Cursor CLI: https://cursor.com/docs/cli/reference/permissions.md (.cursor/cli.json permissions.allow, Shell(curl:*))
    // Gemini CLI: https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md (mcpServers trust, --yolo)
    // VS Code: https://code.visualstudio.com/docs/agents/run/approvals (chat.tools.global.autoApprove, chat.tools.terminal.autoApprove)
    // Codex: https://developers.openai.com/codex/config-basic (approval_policy, sandbox_mode)
    // Nx s1ngularity: https://www.wiz.io/blog/s1ngularitys-aftermath (the malware's CLI flags)
    reference: [
      "https://code.claude.com/docs/en/permissions",
      "https://code.claude.com/docs/en/settings-reference",
      "https://code.claude.com/docs/en/cli-reference",
      "https://cursor.com/docs/cli/reference/permissions",
      "https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md",
      "https://code.visualstudio.com/docs/agents/run/approvals",
      "https://developers.openai.com/codex/config-basic",
      "https://www.wiz.io/blog/s1ngularitys-aftermath",
    ],
    explanation: "These settings remove the prompt that stops an injected instruction from running a command: a Claude Code allow rule such as Bash(*) (the same as Bash), Bash(curl:*) or Bash(rm:*); defaultMode bypassPermissions; enableAllProjectMcpServers and enabledMcpjsonServers, which approve the servers in a project's .mcp.json; a Cursor CLI Shell(curl:*) allow in .cursor/cli.json; a Gemini CLI MCP server with trust set to true; VS Code chat.tools.global.autoApprove; and Codex approval_policy never or sandbox_mode danger-full-access. The same goes for the flags --dangerously-skip-permissions, --yolo and --trust-all-tools. The Nx s1ngularity malware (August 2025) started the Claude, Gemini and Amazon Q command line tools with these flags (Wiz analysis). Where a tool honours these settings depends on the tool: Claude Code ignores enableAllProjectMcpServers and enabledMcpjsonServers from a project file until you trust the folder, and ignores bypassPermissions as defaultMode in project settings files. The VS Code documentation says to set the auto-approve settings in User settings.",
    fix: "Allow only the exact commands you need, for example Bash(git status). Remove blanket allows and auto-approval from files in the repository. Set personal choices in your user settings.",
  }),
  r({
    id: "agent-config/hook-command", title: "Hook that runs a shell command on an agent event", severity: "low", heuristic: false, cwe: ["CWE-78"],
    // https://code.claude.com/docs/en/hooks.md (settings hooks run commands; held back until workspace trust)
    // https://cursor.com/docs/hooks.md (project .cursor/hooks.json hooks run, including in cloud agents)
    reference: ["https://code.claude.com/docs/en/hooks", "https://cursor.com/docs/hooks"],
    explanation: "A hook runs a command each time an agent event fires, for example before or after a tool call. Claude Code reads hooks from settings files and holds them back until you accept the workspace trust dialog for the folder. Cursor reads project hooks from .cursor/hooks.json. Every hook is listed with its command. A hook that uses the network is reported as medium, and one that pipes a download into a shell as high.",
    fix: "Read each command. Remove hooks you do not recognise. Keep hooks local, short and free of network calls and downloaded scripts.",
  }),
  r({
    id: "agent-config/mcp-remote-insecure", title: "Remote MCP server over plain http or on a host you did not allow", severity: "medium", heuristic: false, cwe: ["CWE-319"],
    // https://cwe.mitre.org/data/definitions/319.html
    // https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks (tool descriptions come from the server)
    reference: ["https://cwe.mitre.org/data/definitions/319.html", "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"],
    explanation: "A remote MCP server supplies the tool descriptions and results an agent reads. Over plain http, anyone on the network path can read and change them. A host you have not allowed is a server whose descriptions you have not reviewed; a malicious description is the tool poisoning attack Invariant Labs described. Plain http to localhost is not reported. Pass --allow-host to list the hosts you accept; without it only plain http is reported.",
    fix: "Use https. Add the host to the list you pass with --allow-host after you have checked who runs it, or remove the server.",
  }),
  r({
    id: "agent-config/mcp-project-autostart", title: "MCP server defined in the repository (requires approval in your tool; verify)", severity: "low", heuristic: false, cwe: ["CWE-829"],
    // https://github.com/cursor/cursor/security/advisories/GHSA-24mc-g4xr-4395 (CVE-2025-54136) and https://github.com/cursor/cursor/security/advisories/GHSA-4cxx-hrm3-49rm (CVE-2025-54135)
    // https://code.claude.com/docs/en/mcp.md (project .mcp.json servers need approval), https://code.visualstudio.com/docs/agents/run/security.md (workspace .vscode/mcp.json inherits Workspace Trust)
    reference: [
      "https://github.com/cursor/cursor/security/advisories/GHSA-24mc-g4xr-4395",
      "https://github.com/cursor/cursor/security/advisories/GHSA-4cxx-hrm3-49rm",
      "https://code.claude.com/docs/en/mcp",
      "https://code.visualstudio.com/docs/agents/run/security",
    ],
    explanation: "A server defined in a project file is started or contacted by your tool after you approve it: Claude Code asks you to approve the servers in a project's .mcp.json, and VS Code starts servers from a workspace .vscode/mcp.json only in a trusted workspace. Two Cursor flaws show why the file deserves a look. CVE-2025-54136: an approved MCP configuration could be changed to a different command without a new prompt. CVE-2025-54135: the agent could be made to create .cursor/mcp.json through a prompt injection, with no approval. This finding does not say the server is unsafe. It says a person must check it before approving.",
    fix: "Check the command, arguments and host of each server before you approve it. Re-check after every pull that changes the file.",
  }),
  r({
    id: "agent-config/symlinked-config", title: "Agent file or folder that is a symbolic link", severity: "medium", heuristic: false, cwe: ["CWE-59"],
    // https://cwe.mitre.org/data/definitions/59.html
    reference: ["https://cwe.mitre.org/data/definitions/59.html"],
    explanation: "This scan never follows a symbolic link, so it cannot judge what the link points to. A tool that does follow it reads the target as instructions or settings. A link in a repository can point at a file the scan never sees, or outside the repository. Hidden settings behind a link would otherwise pass the scan.",
    fix: "Replace the link with the real file, or scan the folder it points to as well. Remove the link if you do not know why it is there.",
  }),
];

const byId = new Map(RULES.map(rule => [rule.id, rule] as const));
export const ruleOf = (id: string): AgentConfigRule => byId.get(id)!;
