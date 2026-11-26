import { readFile, stat } from "node:fs/promises";
import { Option, type Command } from "commander";
import { SENTINEL_STATUSES, SCHEDULE_FREQUENCIES, SENTINEL_RESULTS_MODES } from "@0/engine/shared";
import { givenAccessOption, noteIgnoredAccessFlags } from "../ignored-access-flags.js";
import type { ConsoleClient } from "../console-embed-client.js";
import { registerSentinelsBitbucketCommands } from "./sentinels-bitbucket.js";
import { registerSentinelsSyncCommands } from "./sentinels-sync.js";
import { consoleDefaults, consoleFlags, enc, readJsonObject, renderFields, renderTable, requireYes, resolveId, UsageError, withConsole, type ConsoleCommandDeps, type ConsoleFlags } from "./console-command.js";

const ROOT = "/api/console/sentinels";
const WEBHOOK_ROOT = "/api/console/github/webhook";
interface WebhookView { serverMode: boolean; configured?: boolean; payloadUrl?: string; lastDeliveryAt?: string; lastResult?: string; lastReason?: string; graceUntil?: string; deliveries?: Array<{ at: string; result: string; event?: string; reason?: string }> }
const webhookText = (view: WebhookView): string => !view.serverMode ? "Not available: the webhook exists only in server mode (0security --server-mode). Polling is used."
  : renderFields({ configured: view.configured ? "yes" : "no (run: 0security sentinels webhook secret rotate --yes)", "payload URL": view.payloadUrl ?? "set --public-url on the server", "content type": "application/json", events: "Pull requests", "last delivery": view.lastDeliveryAt ? `${view.lastDeliveryAt} ${view.lastResult}${view.lastReason ? ` (${view.lastReason})` : ""}` : "none yet", "old secret valid until": view.graceUntil })
    + (view.deliveries?.length ? `\n\n${renderTable(view.deliveries, [{ header: "TIME", value: d => d.at }, { header: "RESULT", value: d => d.result }, { header: "EVENT", value: d => d.event }, { header: "REASON", value: d => d.reason }])}` : "");

interface Sentinel { id: string; name: string; mission?: string; dailyBudgetUsd?: number | null; monthlyBudgetUsd?: number | null; automationIds?: string[]; status: string; version: number; attention?: { needsYou: boolean; reason?: string } }
interface Trigger { id: string; automationId: string; kind: string; enabled: boolean; version: number; nextFireAt: string | null; summary?: string; lastStatus?: string; bitbucket?: { repo: string; platform: string }; github?: { repo: string; commentOnPr?: boolean; includeForks?: boolean; results?: string } }
interface SentinelFile { path: string; revision: number; content?: string; updatedAt?: string }

async function sentinel(client: ConsoleClient, reference: string): Promise<Sentinel> {
  const all = ((await client.request("GET", ROOT)) as { sentinels: Sentinel[] }).sentinels;
  return resolveId(all, reference, "Sentinel");
}
const view = (value: { sentinel: Sentinel }) => value.sentinel;
const detail = (item: Sentinel) => renderFields({ id: item.id, name: item.name, status: item.status, purpose: item.mission, version: item.version, "daily limit": usdLimit(item.dailyBudgetUsd), "monthly limit": usdLimit(item.monthlyBudgetUsd), "needs you": item.attention?.needsYou ? item.attention.reason ?? "yes" : undefined });
const usdLimit = (value: number | null | undefined): string | undefined => typeof value === "number" ? `$${value} (USD)` : undefined;
/** A spend limit flag: a positive amount, or "none" to remove the limit. */
function limitFlag(name: string, value: string | undefined): number | null | undefined {
  if (value === undefined) return undefined;
  return value.toLowerCase() === "none" ? null : positive(name, value);
}
const ignoredAccessOptions = (command: Command): Command => command
  .addOption(new Option("--access <level>").hideHelp()).addOption(new Option("--autonomy <level>").hideHelp())
  .addOption(new Option("--tool-access <level>").hideHelp()).addOption(new Option("--mode <mode>").hideHelp()).addOption(new Option("--yolo").hideHelp());
const oneOf = (name: string, allowed: readonly string[], value: string | undefined): string | undefined => {
  if (value !== undefined && !allowed.includes(value)) throw new UsageError(`${name} must be one of: ${allowed.join(", ")}.`);
  return value;
};
function positive(name: string, value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) throw new UsageError(`${name} must be a positive number.`);
  return number;
}
const WEEKDAYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
/** Schedule flags to the schedule object; the engine checks the combination and says what is missing. */
function scheduleFrom(options: { frequency?: string; every?: string; at?: string; weekday?: string; cron?: string; timezone?: string }, fromFile: unknown): Record<string, unknown> {
  const inferred = options.frequency ?? (options.cron ? "cron" : options.every ? "minutes" : options.at ? "daily" : undefined);
  const base = fromFile && typeof fromFile === "object" ? fromFile as Record<string, unknown> : {};
  if (!inferred && !base.frequency) throw new UsageError(`Say how often: --frequency ${SCHEDULE_FREQUENCIES.join("|")} (daily needs --at HH:MM).`);
  oneOf("--frequency", SCHEDULE_FREQUENCIES, inferred);
  const day = options.weekday === undefined ? undefined : WEEKDAYS.includes(options.weekday.slice(0, 3).toLowerCase()) ? WEEKDAYS.indexOf(options.weekday.slice(0, 3).toLowerCase()) : Number(options.weekday);
  if (day !== undefined && !(Number.isInteger(day) && day >= 0 && day <= 6)) throw new UsageError("--weekday must be sun to sat, or 0 to 6.");
  const every = positive("--every", options.every);
  return { ...base, ...(inferred ? { frequency: inferred } : {}), ...(every !== undefined ? { every } : {}), ...(options.at ? { time: options.at } : {}), ...(day !== undefined ? { weekday: day } : {}), ...(options.cron ? { cron: options.cron } : {}), ...(options.timezone ? { timezone: options.timezone } : {}) };
}
const triggerTable = (rows: Trigger[]) => renderTable(rows, [
  { header: "ID", value: t => t.id }, { header: "KIND", value: t => t.kind }, { header: "AUTOMATION", value: t => t.automationId },
  { header: "ENABLED", value: t => (t.enabled ? "yes" : "no") }, { header: "WHEN", value: t => t.summary ?? (t.bitbucket ? t.bitbucket.repo : t.github ? `${t.github.repo}${t.github.commentOnPr ? ", comments on" : ""}${t.github.includeForks ? ", forks" : ""}${t.github.results && t.github.results !== "off" ? `, results ${t.github.results}` : ""}` : t.nextFireAt) ?? "-" },
]);

/** `0 sentinels`: everything the Sentinels page does. Reads and edits work offline; runs need the engine. */
export function registerSentinelsCommand(program: Command, deps: ConsoleCommandDeps = consoleDefaults): void {
  const group = program.command("sentinels").description("Create, inspect and control Sentinels");
  registerSentinelsSyncCommands(group);
  registerSentinelsBitbucketCommands(group);

  consoleFlags(group.command("list").description("List Sentinels").option("--status <status>", `Only ${SENTINEL_STATUSES.join(", ")}`))
    .action((options: ConsoleFlags & { status?: string }) => withConsole(options, deps, async client => {
      const status = oneOf("--status", SENTINEL_STATUSES, options.status);
      return ((await client.request("GET", `${ROOT}${status ? `?status=${status}` : ""}`)) as { sentinels: Sentinel[] }).sentinels;
    }, rows => renderTable(rows, [{ header: "ID", value: s => s.id }, { header: "NAME", value: s => s.name }, { header: "STATUS", value: s => s.status }, { header: "NEEDS YOU", value: s => (s.attention?.needsYou ? "yes" : "") }])));

  consoleFlags(group.command("show <id>").description("Show a Sentinel (full or prefix ID)"))
    .action((id: string, options: ConsoleFlags) => withConsole(options, deps, async client => sentinel(client, id), detail));

  consoleFlags(group.command("presets").description("List Sentinel presets"))
    .action((options: ConsoleFlags) => withConsole(options, deps, async client => ((await client.request("GET", "/api/console/sentinel-presets")) as { presets: Array<{ id: string; name: string; description: string }> }).presets,
      rows => renderTable(rows, [{ header: "ID", value: p => p.id }, { header: "NAME", value: p => p.name }, { header: "DESCRIPTION", value: p => p.description }])));

  ignoredAccessOptions(consoleFlags(group.command("create").description("Create a Sentinel from a preset or a JSON definition")
    .option("--preset <id>", "Start from a preset (see `0security sentinels list --presets`)").option("--name <name>", "Name").option("--file <path>", "Sentinel JSON object (overrides preset fields)")))
    .action((options: ConsoleFlags & { preset?: string; name?: string; access?: string; autonomy?: string; file?: string }) => withConsole(options, deps, async client => {
      noteIgnoredAccessFlags(givenAccessOption(options as Record<string, unknown>), { json: options.json });
      if (!options.preset && !options.file) throw new UsageError("Provide --preset <id> or --file <path>.");
      const body = { ...(options.file ? await readJsonObject(options.file, "Sentinel definition") : {}), ...(options.preset ? { preset: options.preset } : {}), ...(options.name ? { name: options.name } : {})};
      return view(await client.request("POST", ROOT, body) as { sentinel: Sentinel });
    }, detail));

  ignoredAccessOptions(consoleFlags(group.command("set <id>").description("Create a Sentinel (--create), or change one: name, purpose, state, triggers, files")
    .option("--name <name>", "Name").option("--purpose <text>", "One-line purpose").addOption(new Option("--mission <text>").hideHelp())
    .option("--file <path>", "Patch JSON object").option("--version <n>", "Reviewed version (default: the current one)")
    .option("--daily-budget <usd>", "Most the Sentinel may spend per UTC day; runs are refused after that (none removes the limit)")
    .option("--monthly-budget <usd>", "Most the Sentinel may spend per UTC month; runs are refused after that (none removes the limit)")
    .option("--state <state>", "active, paused, acknowledged, archived or deleted")))
    .action((id: string, options: ConsoleFlags & { state?: string; name?: string; purpose?: string; mission?: string; access?: string; autonomy?: string; toolAccess?: string; file?: string; version?: string; dailyBudget?: string; monthlyBudget?: string }) => withConsole(options, deps, async client => {
      // A valid --state is rewritten to pause, resume, ... before parsing (command-grammar.ts); only a bad value arrives here.
      if (options.state !== undefined) throw new UsageError(`Unknown state "${options.state}". Use active, paused, acknowledged, archived or deleted.`);
      noteIgnoredAccessFlags(givenAccessOption(options as Record<string, unknown>), { json: options.json });
      const current = await sentinel(client, id);
      const patch: Record<string, unknown> = {
        ...(options.file ? await readJsonObject(options.file, "Sentinel patch") : {}),
        ...(options.name !== undefined ? { name: options.name } : {}), ...((options.purpose ?? options.mission) !== undefined ? { mission: options.purpose ?? options.mission } : {}),
        ...(limitFlag("--daily-budget", options.dailyBudget) !== undefined ? { dailyBudgetUsd: limitFlag("--daily-budget", options.dailyBudget) } : {}),
        ...(limitFlag("--monthly-budget", options.monthlyBudget) !== undefined ? { monthlyBudgetUsd: limitFlag("--monthly-budget", options.monthlyBudget) } : {}),
      };
      if (!Object.keys(patch).length) throw new UsageError("Nothing to change: pass a setting flag or --file.");
      const version = positive("--version", options.version) ?? current.version;
      return view(await client.request("PATCH", `${ROOT}/${enc(current.id)}`, { ...patch, version }) as { sentinel: Sentinel });
    }, detail));

  for (const [verb, text, path] of [["pause", "Pause a Sentinel", "pause"], ["resume", "Resume a paused Sentinel", "resume"]] as const) {
    const command = group.command(`${verb} <id>`).description(text);
    if (verb === "resume") command.option("--acknowledge", "Also acknowledge review of changed model or tools");
    consoleFlags(command).action((id: string, options: ConsoleFlags & { acknowledge?: boolean }) => withConsole(options, deps, async client => {
      const current = await sentinel(client, id);
      return view(await client.request("POST", `${ROOT}/${enc(current.id)}/${path}`, { version: current.version, ...(options.acknowledge ? { acknowledge: true } : {}) }) as { sentinel: Sentinel });
    }, detail));
  }
  consoleFlags(group.command("acknowledge <id>").description("Mark changed model or tools as reviewed"))
    .action((id: string, options: ConsoleFlags) => withConsole(options, deps, async client => {
      const current = await sentinel(client, id);
      return view(await client.request("POST", `${ROOT}/${enc(current.id)}/acknowledge`, { version: current.version }) as { sentinel: Sentinel });
    }, detail));
  consoleFlags(group.command("archive <id>").description("Archive a Sentinel; its history stays"))
    .action((id: string, options: ConsoleFlags) => withConsole(options, deps, async client => {
      const current = await sentinel(client, id);
      return view(await client.request("PATCH", `${ROOT}/${enc(current.id)}`, { status: "archived", version: current.version }) as { sentinel: Sentinel });
    }, detail));
  consoleFlags(group.command("delete <id>").description("Delete a Sentinel; what it owns is detached, not deleted").option("--yes", "Confirm deletion"))
    .action((id: string, options: ConsoleFlags & { yes?: boolean }) => withConsole(options, deps, async client => {
      requireYes(options.yes, "Deleting a Sentinel cannot be undone.");
      const current = await sentinel(client, id);
      return { ...(await client.request("DELETE", `${ROOT}/${enc(current.id)}?version=${current.version}`) as object), id: current.id };
    }, result => `Deleted Sentinel ${result.id}`));

  consoleFlags(group.command("run <id>").description("Run a Sentinel now; starts a thread (needs a running engine)")
    .option("--task <text>", "Task for this run").option("--yes", "Confirm that this run is authorized"))
    .action((id: string, options: ConsoleFlags & { task?: string; yes?: boolean }) => withConsole(options, deps, async client => {
      requireYes(options.yes, "Running a Sentinel starts an autonomous thread in its folder.");
      const current = await sentinel(client, id);
      return await client.request("POST", `${ROOT}/${enc(current.id)}/run`, { approval: "launch-authorized-run", version: current.version, ...(options.task ? { task: options.task } : {}) }) as { activation: { id: string; status: string; missionId?: string } };
    }, ({ activation }) => `${renderFields({ activation: activation.id, status: activation.status, thread: activation.missionId })}${activation.missionId ? `\nRead it: 0security threads show ${activation.missionId} --wait` : ""}`, { requireHost: "Running a Sentinel" }));

  consoleFlags(group.command("activations <id>").description("List a Sentinel's recent runs").option("--limit <n>", "Maximum rows (1-200)", "50"))
    .action((id: string, options: ConsoleFlags & { limit: string }) => withConsole(options, deps, async client => {
      const current = await sentinel(client, id);
      const limit = Number(options.limit);
      if (!Number.isInteger(limit) || limit < 1 || limit > 200) throw new UsageError("--limit must be an integer from 1 to 200.");
      return ((await client.request("GET", `${ROOT}/${enc(current.id)}/activations?limit=${limit}`)) as { activations: Array<{ id: string; status: string; trigger?: { kind: string }; startedAt?: string; missionId?: string }> }).activations;
    }, rows => renderTable(rows, [{ header: "ID", value: a => a.id }, { header: "STATUS", value: a => a.status }, { header: "TRIGGER", value: a => a.trigger?.kind }, { header: "STARTED", value: a => a.startedAt }, { header: "THREAD", value: a => a.missionId }])));

  const files = group.command("files").description("Read and edit a Sentinel's instructions and notes files");
  consoleFlags(files.command("list <id>").description("List files"))
    .action((id: string, options: ConsoleFlags) => withConsole(options, deps, async client => ((await client.request("GET", `${ROOT}/${enc((await sentinel(client, id)).id)}/files`)) as { files: SentinelFile[] }).files,
      rows => renderTable(rows, [{ header: "PATH", value: f => f.path }, { header: "REVISION", value: f => f.revision }, { header: "UPDATED", value: f => f.updatedAt }])));
  consoleFlags(files.command("get <id> <path>").description("Print a file's content"))
    .action((id: string, path: string, options: ConsoleFlags) => withConsole(options, deps, async client => ((await client.request("GET", filePath(await sentinel(client, id), path))) as { file: SentinelFile }).file, file => file.content ?? ""));
  consoleFlags(files.command("put <id> <path>").description("Create or replace a file from --file or --content")
    .option("--file <path>", "Read content from a local text file").option("--content <text>", "Inline content"))
    .action((id: string, path: string, options: ConsoleFlags & { file?: string; content?: string }) => withConsole(options, deps, async client => {
      if (Boolean(options.file) === (options.content !== undefined)) throw new UsageError("Provide exactly one of --file or --content.");
      let content = options.content ?? "";
      if (options.file) {
        const info = await stat(options.file).catch(() => { throw new UsageError(`Cannot read file: ${options.file}`); });
        if (!info.isFile() || info.size > 256 * 1024) throw new UsageError("--file must be a regular file of at most 256 KiB.");
        content = await readFile(options.file, "utf8");
      }
      const target = filePath(await sentinel(client, id), path);
      const existing = await client.request("GET", target).then(value => (value as { file: SentinelFile }).file, error => { if ((error as { status?: number }).status === 404) return null; throw error; });
      return ((await client.request("PUT", target, { content, revision: existing ? existing.revision : null })) as { file: SentinelFile }).file;
    }, file => `Saved ${file.path} (revision ${file.revision})`));
  consoleFlags(files.command("rm <id> <path>").description("Delete a file").option("--yes", "Confirm deletion"))
    .action((id: string, path: string, options: ConsoleFlags & { yes?: boolean }) => withConsole(options, deps, async client => {
      requireYes(options.yes, "Deleting a file cannot be undone.");
      const target = filePath(await sentinel(client, id), path);
      const existing = ((await client.request("GET", target)) as { file: SentinelFile }).file;
      await client.request("DELETE", `${target}?revision=${existing.revision}`);
      return { ok: true, path };
    }, result => `Deleted ${result.path}`));

  const triggers = group.command("triggers").description("Control what starts a Sentinel's automations");
  consoleFlags(triggers.command("list <id>").description("List triggers"))
    .action((id: string, options: ConsoleFlags) => withConsole(options, deps, async client => ((await client.request("GET", `${ROOT}/${enc((await sentinel(client, id)).id)}/triggers`)) as { triggers: Trigger[] }).triggers, triggerTable));
  consoleFlags(triggers.command("add <id>").description("Add a schedule, github-pr, bitbucket-pr, release, check-completed or webhook trigger; it stays disabled unless --enable --yes")
    .option("--automation <id>", "What the trigger starts (default: the only one this Sentinel owns)").option("--kind <kind>", "schedule | manual | github-pr | bitbucket-pr | release | check-completed | webhook")
    .option("--file <path>", "Trigger JSON object with schedule, github, bitbucket, release or check settings").option("--enable", "Enable immediately").option("--yes", "Confirm that an enabled trigger was reviewed")
    .option("--frequency <frequency>", `schedule: ${SCHEDULE_FREQUENCIES.join(", ")}`).option("--every <minutes>", "schedule, minutes: interval (5 or more)")
    .option("--at <HH:MM>", "schedule, daily, weekdays, weekly: time of day in --timezone (default UTC)").option("--weekday <day>", "schedule, weekly: sun, mon, ... or 0-6").option("--cron <expression>", "schedule, cron: five fields").option("--timezone <zone>", "schedule: IANA timezone (default UTC)")
    .option("--repo <owner/name>", "github-pr: repository to watch; bitbucket-pr: workspace/repo (Cloud) or PROJECT/repo (Data Center)").option("--base-branch <branch>", "github-pr: only pull requests into this branch")
    .option("--comment", "github-pr: comment on each pull request with one short summary, edited in place on later pushes (default: off)")
    .option("--include-forks", "github-pr: also review pull requests from forks, marked untrusted (default: skipped)")
    .option("--results <mode>", `github-pr, release, check-completed: send findings back to GitHub: ${SENTINEL_RESULTS_MODES.join(", ")} (default: off). sarif uploads to code scanning; comment posts one pull request comment`)
    .option("--label <text>", "webhook: a name for this webhook (default: webhook)")
    .option("--platform <platform>", "bitbucket-pr: cloud or dc (Data Center)").option("--url <url>", "bitbucket-pr, Data Center: server URL, for example https://bitbucket.example.com")
    .option("--checkout <folder>", "bitbucket-pr: absolute path of a local clone whose origin is the Bitbucket repository")
    .option("--token-env <name>", "bitbucket-pr: name of the environment variable that holds the token (default: BITBUCKET_TOKEN)")
    .option("--events <list>", "bitbucket-pr: opened, updated or opened,updated (default: both)")
    .option("--max-files <n>", "bitbucket-pr: skip a pull request that changes more files than this (default: 50)")
    .option("--budget <usd>", "bitbucket-pr: spend limit for one pull request scan (default: 2)")
    .option("--daily-budget <usd>", "Most this trigger may spend per UTC day; its runs are refused after that")
    .option("--monthly-budget <usd>", "Most this trigger may spend per UTC month; its runs are refused after that"))
    .action((id: string, options: ConsoleFlags & { dailyBudget?: string; monthlyBudget?: string; automation?: string; kind?: string; file?: string; enable?: boolean; yes?: boolean; repo?: string; baseBranch?: string; comment?: boolean; includeForks?: boolean; results?: string; label?: string; platform?: string; url?: string; checkout?: string; tokenEnv?: string; events?: string; maxFiles?: string; budget?: string; frequency?: string; every?: string; at?: string; weekday?: string; cron?: string; timezone?: string }) => withConsole(options, deps, async client => {
      const fromFile = options.file ? await readJsonObject(options.file, "Trigger definition") : {};
      const flags = { ...(options.repo ? { repo: options.repo } : {}), ...(options.baseBranch ? { baseBranch: options.baseBranch } : {}), ...(options.comment ? { commentOnPr: true } : {}), ...(options.includeForks ? { includeForks: true } : {}) };
      const scheduled = [options.frequency, options.every, options.at, options.weekday, options.cron, options.timezone].some(value => value !== undefined);
      const kind = options.kind ?? (scheduled ? "schedule" : undefined) ?? fromFile.kind;
      if (scheduled && kind !== "schedule") throw new UsageError("--frequency, --every, --at, --weekday, --cron and --timezone apply to --kind schedule.");
      const schedule = scheduled ? { schedule: scheduleFrom(options, fromFile.schedule) } : {};
      if (options.results !== undefined) oneOf("--results", SENTINEL_RESULTS_MODES, options.results);
      if (options.results !== undefined && kind !== "github-pr" && kind !== "release" && kind !== "check-completed") throw new UsageError("--results applies to --kind github-pr, release and check-completed.");
      const { repo: repoFlag, ...githubOnly } = flags;
      if (Object.keys(githubOnly).length && kind !== "github-pr") throw new UsageError("--base-branch, --comment and --include-forks apply to --kind github-pr.");
      if (repoFlag && kind !== "github-pr" && kind !== "bitbucket-pr" && !(options.results !== undefined && (kind === "release" || kind === "check-completed"))) throw new UsageError("--repo applies to --kind github-pr and bitbucket-pr (and release or check-completed together with --results).");
      const bitbucketFlags = { ...(options.platform ? { platform: options.platform } : {}), ...(repoFlag ? { repo: repoFlag } : {}), ...(options.url ? { baseUrl: options.url } : {}), ...(options.checkout ? { checkout: options.checkout } : {}), ...(options.tokenEnv ? { tokenEnv: options.tokenEnv } : {}),
        ...(options.events ? { events: options.events.split(",").map(item => item.trim()).filter(Boolean) } : {}), ...(options.maxFiles !== undefined ? { maxFiles: positive("--max-files", options.maxFiles) } : {}), ...(options.budget !== undefined ? { budgetUsd: positive("--budget", options.budget) } : {}) };
      if (kind !== "bitbucket-pr" && Object.keys(bitbucketFlags).some(key => key !== "repo")) throw new UsageError("--platform, --url, --checkout, --token-env, --events, --max-files and --budget apply to --kind bitbucket-pr.");
      const bitbucket = kind === "bitbucket-pr" ? { bitbucket: { ...(fromFile.bitbucket && typeof fromFile.bitbucket === "object" ? fromFile.bitbucket : {}), ...bitbucketFlags } } : {};
      const githubFlags = { ...flags, ...(options.results !== undefined ? { results: options.results } : {}) };
      const github = Object.keys(githubFlags).length && kind === "github-pr" ? { github: { ...(fromFile.github && typeof fromFile.github === "object" ? fromFile.github : {}), ...githubFlags } } : {};
      const eventKey = kind === "release" ? "release" : kind === "check-completed" ? "check" : undefined;
      const eventResults = eventKey && options.results !== undefined ? { [eventKey]: { ...(fromFile[eventKey] && typeof fromFile[eventKey] === "object" ? fromFile[eventKey] : {}), ...(repoFlag ? { repo: repoFlag } : {}), results: options.results } } : {};
      const owner = await sentinel(client, id);
      const owned = owner.automationIds ?? [];
      const automationId = options.automation ?? (typeof fromFile.automationId === "string" ? fromFile.automationId : owned.length === 1 ? owned[0] : undefined);
      if (options.label !== undefined && kind !== "webhook") throw new UsageError("--label applies to --kind webhook.");
      const webhookSettings = kind === "webhook" ? { webhook: { ...(fromFile.webhook && typeof fromFile.webhook === "object" ? fromFile.webhook : {}), ...(options.label !== undefined ? { label: options.label } : {}) } } : {};
      const triggerLimits = { ...(positive("--daily-budget", options.dailyBudget) !== undefined ? { dailyBudgetUsd: positive("--daily-budget", options.dailyBudget) } : {}), ...(positive("--monthly-budget", options.monthlyBudget) !== undefined ? { monthlyBudgetUsd: positive("--monthly-budget", options.monthlyBudget) } : {}) };
      const body = { ...fromFile, ...triggerLimits, ...github, ...eventResults, ...bitbucket, ...schedule, ...webhookSettings, ...(automationId ? { automationId } : {}), ...(kind ? { kind } : {}) };
      if (!body.kind) throw new UsageError("Say what kind: --kind schedule | manual | github-pr | bitbucket-pr | release | check-completed | webhook (a schedule also needs --frequency; bitbucket-pr needs --platform, --repo and --checkout; release and check-completed take their settings with --file).");
      if (!body.automationId) throw new UsageError(owned.length ? `This Sentinel owns ${owned.length} things a trigger can start. Pick one with --automation <id>: ${owned.join(", ")}.` : "A trigger needs something to start, and this Sentinel owns nothing yet that the CLI can list. Create it from a YAML file with `0security sentinels sync <folder> --apply`, which can include a schedule, or add the automation in the console and pass its full id with --automation <id>.");
      if (options.enable) requireYes(options.yes, "Enabling a trigger lets the Sentinel start runs unattended.");
      return ((await client.request("POST", `${ROOT}/${enc(owner.id)}/triggers`, { ...body, enabled: options.enable === true, ...(options.enable ? { approval: "enable-reviewed-trigger" } : {}) })) as { trigger: Trigger }).trigger;
    }, value => triggerTable([value])));
  for (const [verb, text] of [["enable", "Enable a trigger after reviewing it"], ["disable", "Pause a trigger"]] as const) {
    const command = triggers.command(`${verb} <id> <trigger-id>`).description(text);
    if (verb === "enable") command.option("--yes", "Confirm that this trigger was reviewed");
    consoleFlags(command).action((id: string, triggerId: string, options: ConsoleFlags & { yes?: boolean }) => withConsole(options, deps, async client => {
      if (verb === "enable") requireYes(options.yes, "Enabling a trigger lets the Sentinel start runs unattended.");
      const owner = await sentinel(client, id);
      const found = resolveId(((await client.request("GET", `${ROOT}/${enc(owner.id)}/triggers`)) as { triggers: Trigger[] }).triggers, triggerId, "Trigger");
      return ((await client.request("PATCH", `${ROOT}/${enc(owner.id)}/triggers/${enc(found.id)}`, { enabled: verb === "enable", expectedVersion: found.version, ...(verb === "enable" ? { approval: "enable-reviewed-trigger" } : {}) })) as { trigger: Trigger }).trigger;
    }, value => triggerTable([value])));
  }
  consoleFlags(triggers.command("check <id> <trigger-id>").description("Poll a pull request trigger now instead of waiting for its next poll"))
    .action((id: string, triggerId: string, options: ConsoleFlags) => withConsole(options, deps, async client => {
      const owner = await sentinel(client, id);
      const found = resolveId(((await client.request("GET", `${ROOT}/${enc(owner.id)}/triggers`)) as { triggers: Trigger[] }).triggers, triggerId, "Trigger");
      return ((await client.request("POST", `${ROOT}/${enc(owner.id)}/triggers/${enc(found.id)}/check`, {})) as { trigger: Trigger }).trigger;
    }, value => triggerTable([value]), { requireHost: "Checking a pull request trigger" }));
  consoleFlags(triggers.command("secret <id> <trigger-id>").description("Create or replace the secret of a webhook or bitbucket-pr trigger; the old one keeps working for 5 minutes. Printed once.").option("--yes", "Confirm; update the calling system afterwards"))
    .action((id: string, triggerId: string, options: ConsoleFlags & { yes?: boolean }) => withConsole(options, deps, async client => {
      requireYes(options.yes, "A new secret means the calling system must be updated with it.");
      const owner = await sentinel(client, id);
      const found = resolveId(((await client.request("GET", `${ROOT}/${enc(owner.id)}/triggers`)) as { triggers: Trigger[] }).triggers, triggerId, "Trigger");
      if (found.kind !== "webhook" && found.kind !== "bitbucket-pr") throw new UsageError("Only webhook and bitbucket-pr triggers have a secret.");
      return (await client.request("POST", `${WEBHOOK_ROOT}/triggers/${enc(found.id)}/secret`, {})) as { secret: string; graceSeconds?: number; webhook: { path: string; url?: string } };
    }, value => [`Secret (shown once, store it now): ${value.secret}`, ...(value.graceSeconds ? [`The previous secret still works for ${value.graceSeconds / 60} minutes.`] : []), `URL: ${value.webhook.url ?? value.webhook.path}`, "Content type: application/json", "Send the secret as X-Gitlab-Token, or sign the body with it (X-Hub-Signature for Bitbucket, X-Hub-Signature-256 or X-0-Signature-256). Use it as the secret of the Bitbucket webhook."].join("\n"), { requireHost: "Creating a webhook secret" }));
  // Server mode only; hidden because most installs poll. The secret is shown once by `secret rotate` and never again.
  const webhook = group.command("webhook", { hidden: true }).description("GitHub webhook for pull request Sentinels (server mode)");
  consoleFlags(webhook.command("status").description("Show whether the webhook is set up and the last deliveries"))
    .action((options: ConsoleFlags) => withConsole(options, deps, async client => ((await client.request("GET", `${WEBHOOK_ROOT}`)) as { webhook: WebhookView }).webhook, view => webhookText(view), { requireHost: "Reading the webhook status" }));
  const webhookSecret = webhook.command("secret").description("Manage the webhook secret");
  consoleFlags(webhookSecret.command("rotate").description("Create the secret, or replace it; the old one keeps working for 5 minutes. Printed once.").option("--yes", "Confirm; update the secret on GitHub afterwards"))
    .action((options: ConsoleFlags & { yes?: boolean }) => withConsole(options, deps, async client => {
      requireYes(options.yes, "Rotating the webhook secret means GitHub must be updated with the new one.");
      const current = ((await client.request("GET", WEBHOOK_ROOT)) as { webhook: WebhookView }).webhook;
      if (!current.serverMode) throw new UsageError("The webhook exists only in server mode (0security --server-mode).");
      return (await client.request("POST", `${WEBHOOK_ROOT}/secret${current.configured ? "/rotate" : ""}`, {})) as { secret: string; graceSeconds?: number; webhook: WebhookView };
    }, value => [`Secret (shown once, store it now): ${value.secret}`, ...(value.graceSeconds ? [`The previous secret still works for ${value.graceSeconds / 60} minutes.`] : []), `Payload URL: ${value.webhook.payloadUrl ?? "set --public-url on the server to derive it"}`, "Content type: application/json", "Events: Pull requests"].join("\n"), { requireHost: "Rotating the webhook secret" }));
  consoleFlags(triggers.command("rm <id> <trigger-id>").description("Delete a trigger").option("--yes", "Confirm deletion"))
    .action((id: string, triggerId: string, options: ConsoleFlags & { yes?: boolean }) => withConsole(options, deps, async client => {
      requireYes(options.yes, "Deleting a trigger cannot be undone.");
      const owner = await sentinel(client, id);
      const found = resolveId(((await client.request("GET", `${ROOT}/${enc(owner.id)}/triggers`)) as { triggers: Trigger[] }).triggers, triggerId, "Trigger");
      await client.request("DELETE", `${ROOT}/${enc(owner.id)}/triggers/${enc(found.id)}`);
      return { ok: true, id: found.id };
    }, result => `Deleted trigger ${result.id}`));
}

function filePath(owner: Sentinel, path: string): string {
  return `${ROOT}/${enc(owner.id)}/files/${path.split("/").map(enc).join("/")}`;
}
