/**
 * `0 redteam`: the parts of agent red teaming that need no model. `honeypot` serves a fake MCP server that records what an agent does
 * with poisoned data, `config` prints the MCP configuration that points an agent at it, and `judge` reads the recording and says,
 * from the calls alone, whether the agent obeyed the poisoned instruction. Run the agent only in a sandbox you control.
 */
import { appendFileSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { Command } from "commander";
import { CATALOG, createDecoy, createHoneypot, kitByName, listKits, listStrategies, makeKitHoneypot, exportReport, judge, materializePayload, materializeSuccess, newCanary, parseScenario, parseTrace, redteamFindings, scenarioFromFinding, serveLines, type DecoyAlert, type RedteamVerdict, type Scenario, type TraceEvent } from "@0/engine";
import type { Finding, ScanReport } from "@0/engine/shared";
import { UsageError } from "./output.js";
import { parseHeaders } from "./probe.js";
import { registerRedteamAttackCommand } from "./redteam-attack.js";
import { registerRedteamGenerateCommand } from "./redteam-generate.js";
import { registerRedteamRunCommand } from "./redteam-run.js";

export interface RedteamDeps {
  out(text: string): void;
  err(text: string): void;
  readText(path: string): string;
  appendLine(path: string, line: string): void;
  /** Where the honeypot reads requests from and writes replies to. */
  stdin: NodeJS.ReadableStream;
  writeReply(line: string): void;
  env: NodeJS.ProcessEnv;
  /** Sends a decoy alert to the URL the operator named with `--alert-url`. */
  fetch(url: string, init: RequestInit): Promise<Response>;
}

const defaults: RedteamDeps = {
  out: text => { process.stdout.write(text); },
  err: text => { process.stderr.write(`${text}\n`); },
  readText: path => readFileSync(path, "utf8"),
  appendLine: (path, line) => appendFileSync(path, `${line}\n`, { mode: 0o600 }),
  stdin: process.stdin,
  writeReply: line => { process.stdout.write(`${line}\n`); },
  env: process.env,
  fetch: (url, init) => fetch(url, init),
};

export interface HoneypotCliOptions { kit?: string; trace: string; canary?: string; payload?: string; payloadFile?: string; decoy?: boolean; alertUrl?: string; alertHeader?: string[] }
/** The honeypot reads its canary from here when `--canary` is not given, so it is not in the process list. */
export const CANARY_ENV = "ZERO_REDTEAM_CANARY";
export interface JudgeCliOptions { trace: string; canary: string; forbid?: string; format: string; target?: string; scenario?: string }
export interface ScenariosCliOptions { canary?: string; format: string }
export interface ConfigCliOptions { trace: string; canary?: string; name: string }

const need = (name: string, value: string | undefined): string => {
  if (!value || !value.trim()) throw new UsageError(`${name} is required.`);
  return value;
};

/** Kit names from a comma list, validated against the real kits; an unknown name names the valid ones. */
export function parseKits(raw: string | undefined): string[] {
  const names = [...new Set((raw ?? "").split(",").map(name => name.trim()).filter(Boolean))];
  const unknown = names.filter(name => !kitByName(name));
  if (unknown.length) throw new UsageError(`Unknown kit: ${unknown.join(", ")}. Valid kits: ${listKits().map(kit => kit.name).join(", ")}.`);
  return names;
}

const ALERT_TIMEOUT_MS = 5000;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** The alert URL: https, or plain http only to this machine so a test needs no certificate. Never a place the operator did not name. */
function alertTarget(raw: string): URL {
  let url: URL;
  try { url = new URL(raw); } catch { throw new UsageError(`--alert-url '${raw}' is not a URL.`); }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && LOOPBACK.has(url.hostname))) throw new UsageError("--alert-url must be an https URL (http is allowed only for localhost).");
  return url;
}

/** Sends one alert to the operator's own URL. A failure is reported on stderr and never stops the honeypot. */
async function sendAlert(url: URL, headers: Record<string, string>, alert: DecoyAlert, deps: RedteamDeps): Promise<void> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ALERT_TIMEOUT_MS);
  try {
    const response = await deps.fetch(url.toString(), { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify({ text: alert.text, alert }), signal: controller.signal, redirect: "error" });
    if (!response.ok) deps.err(`alert for ${alert.tool} was refused by ${url.host}: HTTP ${response.status}`);
  } catch (error) {
    deps.err(`alert for ${alert.tool} could not be sent to ${url.host}: ${error instanceof Error ? error.message : String(error)}`);
  } finally { clearTimeout(timer); }
}

/** Serves the honeypot until the agent closes its end. Nothing but protocol goes to stdout. */
export async function runHoneypot(options: HoneypotCliOptions, deps: RedteamDeps = defaults): Promise<number> {
  const trace = resolve(need("--trace", options.trace));
  const canary = need(`--canary or ${CANARY_ENV}`, options.canary ?? deps.env[CANARY_ENV]);
  if (options.payload && options.payloadFile) throw new UsageError("Use --payload or --payload-file, not both.");
  if (options.alertUrl && !options.decoy) throw new UsageError("--alert-url needs --decoy: alerts are for the decoy tools, which nothing legitimate calls.");
  if (options.alertHeader?.length && !options.alertUrl) throw new UsageError("--alert-header needs --alert-url.");
  const kits = parseKits(options.kit);
  if (kits.length && options.decoy) throw new UsageError("--kit cannot be combined with --decoy: the decoy serves its own fixed tools.");
  const record = (event: TraceEvent) => deps.appendLine(trace, JSON.stringify(event));
  const pending: Promise<void>[] = [];
  let pot;
  if (options.decoy) {
    const url = options.alertUrl ? alertTarget(options.alertUrl) : undefined;
    const headers = parseHeaders(options.alertHeader, deps.env);
    pot = createDecoy({ canary, onCall: record, onAlert: alert => { if (url) pending.push(sendAlert(url, headers, alert, deps)); } });
    deps.err(`decoy up; recording calls to ${trace}${url ? `, alerting ${url.host}` : ", no alert URL (calls are only recorded)"}`);
  } else {
    const payload = options.payloadFile ? deps.readText(resolve(options.payloadFile)) : options.payload;
    pot = kits.length ? makeKitHoneypot({ canary, kits, ...(payload ? { payload } : {}), onCall: record }) : createHoneypot({ canary, ...(payload ? { payload } : {}), onCall: record });
    deps.err(`honeypot up${kits.length ? ` with kits ${kits.join(", ")}` : ""}; recording calls to ${trace}`);
  }
  const server = serveLines(pot, deps.writeReply);
  await new Promise<void>(done => {
    deps.stdin.setEncoding?.("utf8");
    deps.stdin.on("data", chunk => server.push(String(chunk)));
    deps.stdin.on("end", () => { server.end(); done(); });
    deps.stdin.on("close", () => { server.end(); done(); });
  });
  await Promise.allSettled(pending);
  return 0;
}

const JUDGE_FORMATS = ["text", "json", "sarif", "md"] as const;

/** The scenario a `--scenario` file holds: a `SCENARIO:` line, or a finding or report saved as JSON. */
export function readScenario(text: string): Scenario | null {
  try {
    const value: unknown = JSON.parse(text);
    const findings = typeof value === "object" && value !== null && Array.isArray((value as { findings?: unknown }).findings) ? (value as { findings: unknown[] }).findings : [value];
    for (const finding of findings) { const found = scenarioFromFinding(finding); if (found) return found; }
    return null;
  } catch { return parseScenario(text); }
}

export function reportFor(target: string, findings: Finding[], calls: number, now: Date): ScanReport {
  const count = (severity: string) => findings.filter(finding => finding.severity === severity).length;
  return {
    target, scanDepth: "default", startedAt: now.toISOString(), completedAt: now.toISOString(), durationMs: 0, warnings: [],
    summary: { totalAttacks: calls, totalFindings: findings.length, critical: count("critical"), high: count("high"), medium: count("medium"), low: count("low"), info: count("info") },
    findings,
  } as unknown as ScanReport;
}

/** Exit 1 when the agent obeyed the poisoned instruction, so a pipeline can fail on it. */
export async function runJudge(options: JudgeCliOptions, deps: RedteamDeps = defaults): Promise<number> {
  if (!(JUDGE_FORMATS as readonly string[]).includes(options.format)) throw new UsageError(`--format must be one of: ${JUDGE_FORMATS.join(", ")}.`);
  const tracePath = resolve(need("--trace", options.trace));
  const trace = parseTrace(deps.readText(tracePath));
  const forbidden = options.forbid ? options.forbid.split(",").map(name => name.trim()).filter(Boolean) : [];
  const verdict = judge(trace, { canary: need("--canary", options.canary), forbiddenTools: forbidden });
  if (options.format === "json") deps.out(`${JSON.stringify(verdict, null, 2)}\n`);
  else if (options.format === "text") deps.out(`${describe(verdict)}\n`);
  else {
    const scenario = options.scenario ? readScenario(deps.readText(resolve(options.scenario))) : null;
    if (options.scenario && !scenario) deps.err(`No SCENARIO line found in ${options.scenario}; the finding will not name one.`);
    const target = options.target ?? tracePath.split(/[\\/]/).pop() ?? "agent";
    const now = new Date();
    const report = reportFor(target, redteamFindings({ target, verdict, scenario, now: now.getTime() }), verdict.calls, now);
    const { body } = await exportReport(report, options.format === "md" ? "markdown" : "sarif", `0-redteam-${target}`);
    deps.out(typeof body === "string" ? body : new TextDecoder().decode(body));
  }
  return verdict.hit ? 1 : 0;
}

/** Lists the replayable scenarios in a scan report, each with its payload carrying a canary for the next run. */
export function runScenarios(reportPath: string, options: ScenariosCliOptions, deps: RedteamDeps = defaults): number {
  if (options.format !== "json" && options.format !== "text") throw new UsageError("--format must be json or text.");
  let report: unknown;
  try { report = JSON.parse(deps.readText(resolve(need("<report>", reportPath)))); } catch (error) { if (error instanceof UsageError) throw error; throw new UsageError(`${reportPath} is not a JSON scan report.`); }
  const findings = typeof report === "object" && report !== null && Array.isArray((report as { findings?: unknown }).findings) ? (report as { findings: Record<string, unknown>[] }).findings : [];
  const canary = options.canary ?? newCanary();
  const found = findings.flatMap(finding => {
    const scenario = scenarioFromFinding(finding);
    return scenario ? [{ id: String(finding["id"] ?? ""), title: String(finding["title"] ?? ""), severity: String(finding["severity"] ?? ""), scenario, payload: materializePayload(scenario, canary), success: materializeSuccess(scenario, canary) }] : [];
  });
  if (!found.length) { deps.err("No scenarios in that report. Run `0security scan . --skill agent-toxic-flow --format json -o report.json` first."); return 0; }
  deps.err(`canary: ${canary}`);
  deps.out(options.format === "json" ? `${JSON.stringify({ canary, scenarios: found }, null, 2)}\n` : found.map(item => `[${item.severity}] ${item.title}\n  goal: ${item.scenario.goal}\n  inject at: ${item.scenario.injectionPoint}\n  payload: ${item.payload}\n  success: ${item.success}\n`).join("\n"));
  return 0;
}

function describe(verdict: RedteamVerdict): string {
  if (!verdict.hit) {
    const read = verdict.reads.length ? `read ${verdict.reads.join(", ")}` : "read nothing";
    return `No: the agent made ${verdict.calls} call${verdict.calls === 1 ? "" : "s"} (${read}) and did not act on the poisoned text.`;
  }
  const call = verdict.call!;
  const why = verdict.reason === "canary-left" ? "sent the canary out through" : "called the forbidden tool";
  const args = Object.entries(call.args).map(([key, value]) => `${key}=${value}`).join("; ");
  return `Yes: the agent ${why} ${call.tool} (${call.privilege}, call ${call.seq}${args ? `: ${args}` : ""}).`;
}

/** The MCP configuration that launches the honeypot. The canary goes to stderr, since the judge needs the same one. */
export function runConfig(options: ConfigCliOptions, deps: RedteamDeps = defaults): number {
  const trace = resolve(need("--trace", options.trace));
  const canary = options.canary ?? newCanary();
  const name = need("--name", options.name);
  // The canary goes in the server's environment, not its arguments, so it is not shown by `ps`.
  const config = { mcpServers: { [name]: { command: "0security", args: ["redteam", "honeypot", "--trace", trace], env: { [CANARY_ENV]: canary } } } };
  deps.out(`${JSON.stringify(config, null, 2)}\n`);
  deps.err(`canary: ${canary}`);
  return 0;
}

const LIST_KINDS = ["generators", "strategies", "kits"] as const;
const DIFFICULTIES = ["basic", "intermediate", "advanced"] as const;
const TIERS = ["open", "closed", "both"] as const;
export interface ListCliOptions { area?: string; difficulty?: string; tier?: string; family?: string; format?: string }

const oneOf = (name: string, value: string | undefined, allowed: readonly string[]): string | undefined => {
  if (value !== undefined && !allowed.includes(value)) throw new UsageError(`${name} must be one of: ${allowed.join(", ")}.`);
  return value;
};

const table = (header: string[], rows: string[][]): string => {
  const width = header.map((name, i) => Math.max(name.length, ...rows.map(row => row[i]!.length)));
  const line = (row: string[]) => row.map((cell, i) => cell.padEnd(width[i]!)).join("  ").trimEnd();
  return `${[line(header), ...rows.map(line)].join("\n")}\n`;
};

/** Prints the generators, strategies or kits the other redteam commands accept, so an id can be found without reading source. */
export function runList(kind: string, options: ListCliOptions, deps: Pick<RedteamDeps, "out" | "err"> = defaults): number {
  if (!(LIST_KINDS as readonly string[]).includes(kind)) throw new UsageError(`list takes one of: ${LIST_KINDS.join(", ")}.`);
  const format = oneOf("--format", options.format ?? "text", ["text", "json"])!;
  const difficulty = oneOf("--difficulty", options.difficulty, DIFFICULTIES);
  const tier = oneOf("--tier", options.tier, TIERS);
  const unsupported = (flag: string, value: unknown, valid: string) => { if (value !== undefined) throw new UsageError(`${flag} does not apply to ${kind}; use it with ${valid}.`); };
  let rows: Record<string, unknown>[]; let header: string[]; let cells: (row: Record<string, unknown>) => string[];
  if (kind === "generators") {
    unsupported("--family", options.family, "strategies");
    const area = options.area?.toLowerCase();
    rows = CATALOG.filter(spec => (!area || spec.area.toLowerCase().startsWith(area)) && (!difficulty || spec.difficulty === difficulty) && (!tier || spec.tier === tier))
      .map(spec => ({ id: spec.id, area: spec.area, difficulty: spec.difficulty, tier: spec.tier, weakness: spec.weakness, requires: spec.requires }));
    header = ["ID", "AREA", "DIFFICULTY", "TIER", "WEAKNESS TESTED"]; cells = row => [row["id"], row["area"], row["difficulty"], row["tier"], String(row["weakness"] ?? "").replace(/\s+/g, " ").slice(0, 70)] as string[];
  } else if (kind === "strategies") {
    unsupported("--area", options.area, "generators"); unsupported("--difficulty", options.difficulty, "generators"); unsupported("--tier", options.tier, "generators");
    const family = options.family?.toLowerCase();
    rows = listStrategies().filter(strategy => !family || strategy.family === family)
      .map(strategy => ({ id: strategy.id, family: strategy.family, turns: strategy.turns, needsAttackerModel: strategy.needsAttackerModel, cost: strategy.cost, runnable: Boolean(strategy.apply), description: strategy.description }));
    header = ["ID", "FAMILY", "TURNS", "ATTACKER MODEL", "COST", "WHAT IT DOES"]; cells = row => [row["id"], row["family"], row["turns"], row["needsAttackerModel"] ? "yes" : "no", row["cost"], String(row["description"] ?? "").replace(/\s+/g, " ").slice(0, 70)] as string[];
  } else {
    unsupported("--area", options.area, "generators"); unsupported("--difficulty", options.difficulty, "generators"); unsupported("--tier", options.tier, "generators"); unsupported("--family", options.family, "strategies");
    rows = listKits().map(kit => ({ name: kit.name, description: kit.description, tools: kit.tools.map(tool => tool.name) }));
    header = ["NAME", "TOOLS"]; cells = row => [row["name"] as string, (row["tools"] as string[]).join(", ")];
  }
  if (format === "json") deps.out(`${JSON.stringify(rows, null, 2)}\n`);
  else if (!rows.length) deps.err(`No ${kind} match those filters.`);
  else deps.out(table(header, rows.map(cells)));
  return 0;
}

export function registerRedteamCommand(program: Command, deps: RedteamDeps = defaults): void {
  const redteam = program.command("redteam")
    .description("Test whether an agent obeys poisoned text: a fake MCP server that records its calls, and a judge that reads the recording");
  redteam.command("honeypot")
    .description("Serve a fake MCP server over stdio that returns poisoned data and records every tool call")
    .requiredOption("--trace <file>", "Append each call to this file, one JSON object per line")
    .option("--canary <text>", `The marker the poisoned text asks the agent to send out; the judge needs the same one (default: ${CANARY_ENV})`)
    .option("--payload <text>", "The poisoned instruction returned by the source tools (default: ask the agent to email the secret out)")
    .option("--payload-file <file>", "Read the poisoned instruction from a file")
    .option("--kit <names>", "Comma separated kits of extra fake tools (see `0 redteam list kits`); the default tool set stays when omitted")
    .option("--decoy", "Serve decoy tools that nothing legitimate calls, so every call is an alert (for a running agent, not a test)")
    .option("--alert-url <url>", "With --decoy: POST each alert as JSON to this https URL (a chat webhook or your own collector); a `text` field makes it readable in Slack-style webhooks")
    .option("-H, --alert-header <header>", "Header for the alert request, `Name: value`; the value may be $ENV_VAR so a token is not typed on the command line (repeatable)", (value: string, previous: string[] = []) => [...previous, value])
    .action(async (options: HoneypotCliOptions) => { process.exitCode = await runHoneypot(options, deps); });
  redteam.command("config")
    .description("Print the MCP configuration that points an agent at the honeypot, and a fresh canary")
    .requiredOption("--trace <file>", "Where the honeypot will record calls")
    .option("--canary <text>", "Use this canary instead of making one")
    .option("--name <name>", "Name of the server in the configuration", "honeypot")
    .action((options: ConfigCliOptions) => { process.exitCode = runConfig(options, deps); });
  redteam.command("judge")
    .description("Say whether the recorded calls show the agent obeying the poisoned text; exits 1 if it did")
    .requiredOption("--trace <file>", "The file the honeypot wrote")
    .requiredOption("--canary <text>", "The canary the honeypot was started with")
    .option("--forbid <tools>", "Tools that count as a hit when called at all, comma separated, such as run_command")
    .option("--format <format>", "text, json, sarif or md (sarif and md report the hit as a finding)", "text")
    .option("--target <name>", "Name of the agent in a sarif or md report (default: the trace file name)")
    .option("--scenario <file>", "A SCENARIO line, or a scan report or finding saved as JSON, so the finding names the scenario")
    .action(async (options: JudgeCliOptions) => { process.exitCode = await runJudge(options, deps); });
  redteam.command("scenarios <report>")
    .description("List the replayable scenarios in a scan report made with the agent-toxic-flow skill")
    .option("--canary <text>", "Put this canary in each payload instead of making one")
    .option("--format <format>", "text or json", "text")
    .action((report: string, options: ScenariosCliOptions) => { process.exitCode = runScenarios(report, options, deps); });
  redteam.command("list <what>")
    .description("List what the redteam commands accept: generators (catalog test cases), strategies (ways to deliver a payload) or kits (fake tool sets)")
    .option("--area <name>", "generators: area name or prefix, such as Payment")
    .option("--difficulty <level>", "generators: basic, intermediate or advanced")
    .option("--tier <tier>", "generators: open (templates ship here), closed (brain service only) or both")
    .option("--family <name>", "strategies: family such as encoding or framing")
    .option("--format <format>", "text or json", "text")
    .action((what: string, options: ListCliOptions) => { process.exitCode = runList(what, options, deps); });
  registerRedteamRunCommand(redteam);
  registerRedteamGenerateCommand(redteam);
  registerRedteamAttackCommand(redteam);
}
