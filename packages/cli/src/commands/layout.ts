/**
 * Light layout facts about the command tree: where commands live and how the root help
 * is grouped. This file imports only the `commander` types, so the startup fast path can
 * print `0 --help` without loading any command module or the engine.
 */
import { Option, type Command, type Help } from "commander";
import { GROUP_DESCRIPTIONS, TOP_LEVEL_COMMANDS, VISIBLE_NESTED_GROUPS, VISIBLE_SUBCOMMANDS } from "./manifest.js";

export type Registrar = (parent: Command) => void;

export function child(parent: Command, name: string): Command {
  const found = parent.commands.find((command) => command.name() === name);
  if (!found) throw new Error(`Command tree: \`${name}\` must be registered before its children`);
  return found;
}

export function nest(parent: Command, group: string, registrars: readonly Registrar[]): void {
  const target = child(parent, group);
  for (const register of registrars) register(target);
}

/** Commands registered at the top by their module, then moved under their group. */
export const NEW_HOME: Readonly<Record<string, string>> = {
  reports: "findings",
  connections: "models", usage: "models",
  "audit-log": "config", "audit-export": "config", "audit-verify": "config", "audit-prune": "config", team: "config", db: "config", github: "config",
  upgrade: "doctor", workbench: "doctor",
};

/** Move already-registered top-level commands under their new parent, keeping each command object (and handler) as is. `only` limits it to one parent (the lazy loader builds one group at a time). */
export function adoptCommands(program: Command, only?: string): void {
  for (const [name, group] of Object.entries(NEW_HOME)) {
    if (only !== undefined && group !== only) continue;
    const index = program.commands.findIndex((command) => command.name() === name);
    if (index < 0) throw new Error(`Command tree: \`${name}\` is not registered`);
    const [moved] = (program.commands as Command[]).splice(index, 1);
    child(program, group).addCommand(moved!);
  }
}

export const HELP_GROUPS: readonly (readonly [string, readonly string[]])[] = [
  ["Work", ["scan", "threat-model", "probe", "sbom", "findings", "evidence", "threads", "sentinels"]],
  ["Setup", ["skills", "models", "computers", "config"]],
];

/** Root `--help`: the visible commands grouped by purpose instead of one flat list. */
export function configureGroupedHelp(program: Command): void {
  program.configureHelp({
    formatHelp(cmd: Command, helper: Help): string {
      const width = Math.max(helper.padWidth(cmd, helper), ...(cmd.parent ? [] : ROOT_OPTIONS.map(([term]) => term.length)));
      const item = (term: string, description: string): string => helper.formatItem(term, width, description, helper);
      const out = [`Usage: ${helper.commandUsage(cmd)}`, "", helper.commandDescription(cmd), ""];
      out.push("Options:", ...helper.visibleOptions(cmd).map((option) => item(helper.optionTerm(option), helper.optionDescription(option))));
      if (!cmd.parent) out.push(...ROOT_OPTIONS.map(([term, description]) => item(term, description)));
      out.push("");
      const visible = new Map(helper.visibleCommands(cmd).map((command) => [command.name(), command]));
      for (const [title, names] of HELP_GROUPS) {
        out.push(`${title}:`);
        for (const name of names) {
          const command = visible.get(name);
          if (command) out.push(item(helper.subcommandTerm(command), helper.subcommandDescription(command)));
        }
        out.push("");
      }
      if (!cmd.parent) out.push("Run `0security <command>` to list its subcommands; `0security <command> <subcommand> --help` for flags.", "", examplesBlock(ROOT_EXAMPLES));
      return out.join("\n").replace(/\n+$/, "\n");
    },
  });
}

/** Headless entry points live outside the command tree (main.ts runs them), so the root help lists them by hand. */
const ROOT_OPTIONS: readonly (readonly [string, string])[] = [
  ["-p, --print <prompt>", "Run one prompt headless: only the answer goes to stdout"],
  ["-c, --continue", "With -p: continue the most recent thread"],
  ["-r, --resume <id>", "With -p: continue a saved thread"],
];
const ROOT_EXAMPLES: readonly string[] = [
  '0security -p "Review ./app for injection bugs"',
  '0security threads start "Map the login flow" --wait',
  "0security findings list --severity high --format json",
  "0security sentinels list --presets",
];
const examplesBlock = (lines: readonly string[]): string => `Examples:\n${lines.map((line) => `  ${line}`).join("\n")}\n`;

/** Short, real examples for the visible commands, keyed by command path. */
const EXAMPLES: Readonly<Record<string, readonly string[]>> = {
  scan: ["0security scan ~/code/app", "0security scan ~/code/app --format sarif -o scan.sarif --fail-on high", "0security scan https://github.com/acme/app --budget 2 --format json", "0security scan . --context .0/threat-model.md --policy ./policies --org-policy ~/org-policies", "0security scan . --scope SECURITY.md --fail-on high", "0security scan --scanner nuclei --target-url http://127.0.0.1:8080 --scope-file scope.txt"],
  probe: ["0security probe https://api.example.com/v1/chat/completions -H \"Authorization: Bearer $OPENAI_API_KEY\" --model gpt-4o-mini", "0security probe https://app.example.com/api/chat --body '{\"message\":\"{{prompt}}\"}' --response-path reply", "0security probe https://app.example.com/api/chat --i-own-this app.example.com --secret sk-live-1234 --format sarif -o probe.sarif --fail-on medium"],
  "threat-model": ["0security threat-model", "0security threat-model ~/code/app --pr", "0security threat-model --interview", "0security threat-model --output THREAT_MODEL.md", "0security scan ~/code/app --context ~/code/app/.0/threat-model.md"],
  sbom: ["0security sbom generate . -o sbom.cdx.json", "0security sbom check sbom.cdx.json", "0security sbom check sbom.cdx.json --format json", "0security sbom scan-models ./models", "0security sbom agent-config ."],
  "sbom agent-config": ["0security sbom agent-config .", "0security sbom agent-config . --fail-on high", "0security sbom agent-config . --format sarif -o agent-config.sarif --allow-host mcp.example.com"],
  "sbom scan-models": ["0security sbom scan-models ./models", "0security sbom scan-models model.pkl", "0security sbom scan-models . --format sarif > models.sarif"],
  "sbom generate": ["0security sbom generate . -o sbom.cdx.json", "0security sbom generate ~/code/app --name app"],
  "sbom reachability": ["0security sbom reachability sbom.cdx.json .", "0security sbom check sbom.cdx.json --source . --format json"],
  "sbom java-usage": ["0security sbom java-usage sbom.cdx.json .", "0security sbom java-usage sbom.cdx.json ~/code/app --format json"],
  "sbom licenses": ["0security sbom licenses . --preset permissive", "0security sbom licenses sbom.cdx.json --deny 'GPL-*,AGPL-*'", "0security sbom licenses . --policy license-policy.yaml --resolve --format sarif > licenses.sarif"],
  "sbom check": ["0security sbom check sbom.cdx.json", "0security sbom check sbom.cdx.json --format json", "0security sbom check sbom.cdx.json --usage ."],
  findings: ["0security findings list --severity high", "0security findings show 3f2a", '0security findings update 3f2a --status accepted --reason "fix scheduled" --expires 90d --approver "security lead"'],
  "findings list": ["0security findings list --expiring 30", "0security findings list --context context.json", "0security findings list --severity high --status verified", "0security findings list --format json", "0security findings list --format sarif -o findings.sarif"],
  "findings show": ["0security findings show 3f2a", "0security findings show 3f2a --context context.json"],
  "findings context": ["0security findings context check context.json"],
  "findings context check": ["0security findings context check context.json", "0security findings context check context.json --repository acme/api --json"],
  evidence: ["0security evidence verify ./evidence --pub evidence-key.pub.pem"],
  "config audit-prune": ["0security config audit-prune --older-than 365d --archive audit-2025.ndjson", "0security config audit-prune --older-than 365d --archive audit-2025.ndjson --yes"],
  "config audit-verify": ["0security config audit-verify", "0security config audit-verify --file audit-2025.ndjson"],
  "evidence verify": ["0security evidence verify ./evidence --pub evidence-key.pub.pem", "0security evidence verify ./evidence --pub evidence-key.pub.pem --json"],
  "findings evidence": ["0security findings evidence ./evidence --repo .", "0security findings evidence ./evidence --repo . --sign evidence-key.pem", "0security findings evidence ./evidence --repo . --check-advisories"],
  "findings export-fixes": ["0security findings export-fixes", "0security findings export-fixes --check-merged -o ./fix-report", "0security findings export-fixes --repo . --since 2026-01-01 --format json"],
  "findings report-draft": ["0security findings report-draft 3f2a --stage early-warning --product app --contact \"Jo, security@example.com\"", "0security findings report-draft 3f2a --stage notification --facts facts.json -o notification.md"],
  "findings issues": ["0security findings issues --repo acme/app --dry-run", "0security findings issues --repo acme/app --min-severity high --max 10"],
  "findings update": ['0security findings update 3f2a --status accepted --reason "fix scheduled" --expires 90d --approver "security lead"', '0security findings update 3f2a --status false-positive --reason "test fixture"'],
  "findings reproduce": ["0security findings reproduce 3f2a --image node:24-bookworm-slim@sha256:<digest> --folder ~/code/app", "0security findings reproduce 3f2a --image node:24-bookworm-slim@sha256:<digest> --start \"node app.js\" --json", "0security findings reproduce 3f2a --image node:24-bookworm-slim@sha256:<digest> --allow-unbounded-storage"],
  "findings verify": ["0security findings verify --severity high,medium --folder ~/code/app", "0security findings verify 3f2a --folder ~/code/app", "0security findings verify --apply --budget 1 --folder ~/code/app"],
  "findings rollup": ["0security findings rollup", "0security findings rollup api.json web.json --format html -o rollup.html", "0security findings rollup --export api.json --repository api", "0security findings rollup api.json web.json --since last-month.json --labels labels.yaml", "0security findings rollup scanner.sarif --repository api"],
  "findings metrics": ["0security findings metrics", "0security findings metrics --since 7d --command fix", "0security findings metrics --by week", "0security findings metrics --by model --format csv"],
  "findings burndown": ["0security findings burndown --severity high --limit 10 --test \"pnpm test\"", "0security findings burndown --dry-run", "0security findings burndown --history --format json"],
  threads: ['0security threads start "Map the login flow" --folder ~/code/app --wait', "0security threads list", "0security threads show <id>", '0security threads send <id> "Now the logout path" --wait', "0security threads stop <id>"],
  "threads list": ["0security threads list", "0security threads list --format json"],
  "threads show": ["0security threads show <id>", "0security threads show <id> --wait", "0security threads show <id> --format json"],
  "threads start": ['id=$(0security threads start "Review ./app for injection bugs")', '0security threads start "Summarize open findings" --wait', '0security threads start "Audit CI" --skill workflow-hardening --wait --timeout 900'],
  "threads send": ['0security threads send <id> "Also check the API routes" --wait', '0security threads send new "Review ./app"'],
  "threads stop": ["0security threads stop <id>"],
  sentinels: ["0security sentinels list --presets", '0security sentinels set --create --preset dependency-watcher --name "Nightly check"', "0security sentinels set <id> --state active", '0security sentinels run <id> --task "Re-test login" --yes'],
  "sentinels list": ["0security sentinels list", "0security sentinels list <id>", "0security sentinels list --presets"],
  "sentinels bitbucket review": ["0security sentinels bitbucket review --platform cloud --repo acme/app --checkout ~/code/app --pr 42", "0security sentinels bitbucket review --platform dc --repo PROJ/app --checkout ~/code/app --pr 42 --url https://bitbucket.example.com"],
  "sentinels bitbucket watch": ["0security sentinels bitbucket watch --platform cloud --repo acme/app --checkout ~/code/app", "0security sentinels bitbucket watch --platform dc --repo PROJ/app --checkout ~/code/app --url https://bitbucket.example.com --listen 127.0.0.1:7777", "0security sentinels bitbucket watch --platform cloud --repo acme/app --checkout ~/code/app --once"],
  "sentinels run": ['0security sentinels run <id> --task "Re-test login" --yes', "0security sentinels run <id> --history"],
  "sentinels set": ['0security sentinels set --create --preset pr-security-reviewer --name "PR review"', "0security sentinels set <id> --state paused", "0security sentinels set <id> --trigger add --kind schedule --frequency daily --at 09:00", "0security sentinels set <id> --files put NOTES.md --file ./notes.md"],
  skills: ["0security skills list", "0security skills list pr-diff-review", "0security skills add owner/repo@<full-sha>", "0security skills add ./my-skills"],
  "skills list": ["0security skills list", "0security skills list pr-diff-review", "0security skills list --catalog"],
  "skills add": ["0security skills add ./my-skills", "0security skills add owner/repo@<full-sha> --yes"],
  models: ["0security models connect", "0security models connect anthropic --key-env ANTHROPIC_API_KEY", "0security models list", "0security models set claude-sonnet-4-6 --provider anthropic"],
  "models list": ["0security models list", "0security models list --provider anthropic --format json"],
  "models set": ["0security models set", "0security models set claude-sonnet-4-6 --provider anthropic"],
  "models connect": ["0security models connect", "0security models connect anthropic --key-env ANTHROPIC_API_KEY", "0security models connect anthropic --test", "0security models connect anthropic --remove --yes"],
  computers: ["0security computers list", "0security computers add --ssh me@build-box", "0security computers stop <id>"],
  "computers add": ["0security computers add --ssh me@build-box"],
  config: ["0security config doctor", "0security config get approvals", "0security config set approvals ask", "0security config get --all"],
  "config get": ["0security config get", "0security config get approvals", "0security config get --all --format json"],
  "config set": ["0security config set approvals ask", "0security config set approvals auto --project"],
  "config doctor": ["0security config doctor", "0security config doctor --fix"],
};

const isLeaf = (command: Command): boolean => command.commands.length === 0;
const longs = (command: Command): Set<string> => new Set(command.options.map((option) => option.long ?? ""));

/**
 * Every list/show command takes `--format text|json` and the short `--json`; one of them is documented
 * (`--format`), the other still works. Commands whose own --format means a file type (export) keep it.
 */
function unifyOutputFlags(command: Command): void {
  const flags = longs(command);
  if (flags.has("--json") && !flags.has("--format")) {
    const json = command.options.find((option) => option.long === "--json")!;
    json.hidden = true;
    command.addOption(new Option("--format <format>", "Output: text or json").choices(["text", "json"]));
    command.on("option:format", (value: string) => command.setOptionValue("json", value === "json"));
  } else if (flags.has("--format") && !flags.has("--json")) {
    const format = command.options.find((option) => option.long === "--format")!;
    if (!(format.argChoices ?? []).length && /json or text/i.test(format.description)) {
      command.addOption(new Option("--json").hideHelp());
      command.on("option:json", () => command.setOptionValue("format", "json"));
    }
  }
}

/** A group with no subcommand prints its help (exit 0); an unknown word is a usage error with the closest match. */
function groupBehaviour(top: Command): void {
  if (!top.commands.length) return;
  const hadAction = (top as unknown as { _actionHandler?: unknown })._actionHandler != null;
  top.helpCommand(true);
  if (hadAction) return; // findings: its own action lists findings
  top.allowExcessArguments(true).action(function (this: Command) {
    if (this.args[0]) (this as unknown as { unknownCommand(): never }).unknownCommand();
    this.help();
  });
}

function polish(command: Command, path: string): void {
  const examples = EXAMPLES[path];
  if (examples && !(command as unknown as { _hidden?: boolean })._hidden) command.addHelpText("after", `\n${examplesBlock(examples)}`);
  if (isLeaf(command)) unifyOutputFlags(command);
  for (const sub of command.commands) polish(sub, `${path} ${sub.name()}`);
}

interface NewFormStub { readonly name: string; readonly args: string; readonly description: string; readonly usage?: string; readonly options?: readonly (readonly [string, string])[] }

/** Visible subcommands that have no implementation command of their own: `command-grammar.ts` rewrites them before parsing, so the action only runs on incomplete input. */
const NEW_FORM_STUBS: Readonly<Record<string, readonly NewFormStub[]>> = {
  findings: [{ name: "update", args: "<id>", description: "Change a finding's status", usage: "0security findings update <id> --status accepted|suppressed|open|false-positive [--note <text>] [--reason <text> --expires <date|90d> --approver <name>]", options: [["--status <status>", "accepted | suppressed | open | false-positive"], ["--note <text>", "Why (optional)"], ["--reason <text>", "Why; required with accepted and false-positive"], ["--expires <date|90d>", "Accepted: when the acceptance ends (required)"], ["--approver <name>", "Accepted: who approved it, a label not a login"], ["--db-path <path>", "Path to SQLite database"]] }],
  models: [
    { name: "set", args: "[model]", description: "Show or choose the default model", usage: "0security models set <model> --provider <id>", options: [["--provider <provider>", "Provider of the model"]] },
    { name: "connect", args: "[provider]", description: "Add, list, test or remove a provider connection", options: [["--key-env <VAR>", "Add: read the API key from this environment variable"], ["--stdin", "Add: read the API key from stdin"], ["--list", "List connections (the default with no provider)"], ["--test", "Test a connection"], ["--remove", "Remove a connection (with --yes)"]] },
  ],
  config: [{ name: "doctor", args: "[checks...]", description: "Check this machine and the engine, then suggest the next command", options: [["--fix", "Repair the local database"], ["--json", "Print JSON"]] }],
};

/** Flags the new grammar adds to commands that already existed; shown at the end of their help. */
const NEW_FORM_HELP: Readonly<Record<string, string>> = {
  "threads list": "With an id: show that thread. Then --events, --export, --rename <title>, --set, --clear, --close, --archive or --delete act on it.",
  "threads send": "`send new <prompt>` starts a thread. With an id: --retry, --resume or --decide <decision-id>.",
  "sentinels list": "With an id: show that Sentinel. --presets lists the starting points.",
  "sentinels run": "--history lists past activations.",
  "sentinels set": "--create --preset <id> --name <name> makes a Sentinel. With an id: --state active|paused|acknowledged|archived|deleted, --trigger <list|add|enable|disable|check|rm> ... (see `0security sentinels set <id> --trigger add --help`), --files <list|get|put|rm> ...",
  "skills list": "With a name: show that skill. --catalog browses the catalog. Extensions: `0security skills extensions list|info|enable|disable|update|remove`; --info, --enable, --disable and --mcp-remove on a name reach them.",
  "skills add": "<src> may be a catalog id, a repository, a folder of skills or a bundle. An extension is <repo>@<full sha>: you see one prompt first. Also: --mcp <url> adds an MCP server as a local extension, --preview checks a folder, --remove <name> removes a skill.",
  "models list": "Also: --usage shows tokens and cost, --recommended the suggested models.",
  "computers list": "--hosts lists SSH hosts you could add.",
  "computers add": "--repair <id> reconnects a computer.",
  "config get": "No key: show the configuration. --all lists every setting, --export [file] writes it. Namespaces: audit, team, github, api.keys.",
  "config set": "--from-file <file> imports, --reset [keys...] resets. Namespaces: api.key <name> [--revoke <id>], team <init|add-user>, db <repair|reset>, github <connect|repos>.",
  "findings list": "Also: --format sarif|json|md exports, --import <report> imports a report.",
};

function setHidden(command: Command, hidden: boolean): void {
  (command as unknown as { _hidden: boolean })._hidden = hidden;
}

/** Make `top` the 0.35 surface: its description, only the listed subcommands visible, and the new-grammar help. Everything old stays registered but hidden. */
export function applyNewSurface(top: Command): void {
  const visible = VISIBLE_SUBCOMMANDS[top.name()];
  const description = GROUP_DESCRIPTIONS[top.name()];
  if (!visible || !description) {
    if (TOP_LEVEL_COMMANDS.some((entry) => entry.name === top.name() && entry.hidden)) setHidden(top, true);
    // A visible command with no subcommands (`scan`) still prints its examples.
    else if (EXAMPLES[top.name()]) top.addHelpText("after", `\n${examplesBlock(EXAMPLES[top.name()]!)}`);
    return;
  }
  top.description(description);
  const topHelp = NEW_FORM_HELP[top.name()];
  if (topHelp) top.addHelpText("after", `\n${topHelp}\n`);
  for (const stub of NEW_FORM_STUBS[top.name()] ?? []) {
    if (top.commands.some((command) => command.name() === stub.name)) continue;
    const added = top.createCommand(stub.name).description(stub.description).arguments(stub.args).allowUnknownOption().allowExcessArguments();
    for (const [flags, text] of stub.options ?? []) added.option(flags, text);
    added.action(() => {
      const opts = added.opts<Record<string, unknown>>();
      if (top.name() === "findings" && stub.name === "update" && opts["status"] === "false-positive" && !opts["reason"]) throw new Error("--reason <text> is required with --status false-positive: say why the finding is not real, for example 0security findings update <id> --status false-positive --reason \"test fixture\".");
      throw new Error(`${stub.usage ? `Usage: ${stub.usage}. ` : "Incomplete. "}See \`0 ${top.name()} ${stub.name} --help\`.`);
    });
    top.addCommand(added);
  }
  // Visible subcommands first, in the documented order.
  const rank = (command: Command): number => { const at = visible.indexOf(command.name()); return at < 0 ? visible.length : at; };
  (top.commands as Command[]).sort((a, b) => rank(a) - rank(b));
  for (const command of top.commands) {
    const keep = visible.includes(command.name());
    setHidden(command, !keep);
    const hide = (node: Command): void => { for (const child of node.commands) { setHidden(child, true); hide(child); } };
    if (!(keep && VISIBLE_NESTED_GROUPS.includes(`${top.name()} ${command.name()}`))) hide(command);
    const extra = NEW_FORM_HELP[`${top.name()} ${command.name()}`];
    if (extra && keep) command.addHelpText("after", `\n${extra}\n`);
  }
  for (const command of top.commands) polish(command, `${top.name()} ${command.name()}`);
  const own = EXAMPLES[top.name()];
  if (own) top.addHelpText("after", `\n${examplesBlock(own)}`);
  groupBehaviour(top);
}

/** Usage errors exit 2 (not commander's 1) and say where to look; `--help` and `--version` exit 0. Applied to the finished tree. */
export function applyErrorPolicy(command: Command, path = "0"): void {
  command.exitOverride((error) => process.exit(error.exitCode === 0 || error.code === "commander.helpDisplayed" || error.code === "commander.version" ? 0 : 2));
  command.configureOutput({
    outputError: (text, write) => { write(`${text.replace(/\s+$/, "")}\nRun \`${path} --help\` for usage.\n`); },
  });
  for (const sub of command.commands) applyErrorPolicy(sub, `${path} ${sub.name()}`);
}
