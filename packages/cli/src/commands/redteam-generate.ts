/**
 * `0 redteam generate`: scenarios for testing an agent, from a hosted attack brain when one is configured and allowed, from the open
 * catalog otherwise (the small starter pack only when the catalog has nothing for the manifest). The brain only ever sees the manifest, a list of tool names with a coarse privilege and gate plus the kinds
 * of input the agent reads; `--dry-run` prints exactly that so it can be checked before anything is sent. Payloads get this run's
 * canary here, locally, and the verdict is computed from the agent's recorded calls, never by the server.
 *
 * Remote payloads are hostile by design: run them only against decoy or sandboxed tools, never an agent wired to real credentials,
 * files or services. Text printed here is stripped of control characters, so a server cannot rewrite the terminal.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { Command } from "commander";
import { applyChecked, brainDryRun, CATALOG_BY_ID, materializePayload, materializeSuccess, newCanary, requestScenarios, strategyById, type BrainScenario, type Difficulty } from "@0/engine";
import { UsageError } from "./output.js";
import type { RedteamDeps } from "./redteam.js";

export type GenerateDeps = Pick<RedteamDeps, "out" | "err" | "readText" | "env" | "fetch">;
export interface GenerateCliOptions { manifest?: string; framework?: string; count?: string | number; url?: string; dryRun?: boolean; offline?: boolean; canary?: string; format?: string; generator?: string; area?: string; difficulty?: string; strategy?: string; listGenerators?: boolean }

const defaults: GenerateDeps = {
  out: text => { process.stdout.write(text); },
  err: text => { process.stderr.write(`${text}\n`); },
  readText: path => readFileSync(path, "utf8"),
  env: process.env,
  fetch: (url, init) => fetch(url, init),
};

function parseCount(value: string | number | undefined): number | undefined {
  if (value === undefined) return undefined;
  const count = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(count) || count < 1 || count > 20) throw new UsageError("--count must be a whole number from 1 to 20.");
  return count;
}

/** Builds the request from the manifest file. The file holds `{ tools, sources }`; a full request with `manifest` is accepted too. */
function buildRequest(options: GenerateCliOptions, deps: GenerateDeps): unknown {
  if (!options.manifest?.trim()) throw new UsageError("--manifest is required.");
  let raw: unknown;
  try { raw = JSON.parse(deps.readText(resolve(options.manifest))); } catch { throw new UsageError(`${options.manifest} is not a readable JSON manifest.`); }
  const manifest = typeof raw === "object" && raw !== null && "manifest" in raw ? (raw as { manifest: unknown }).manifest : raw;
  const count = parseCount(options.count);
  return { v: 1, task: "scenarios", manifest, ...(options.framework ? { framework: options.framework } : {}), ...(count ? { count } : {}) };
}

/** Strips C0/C1 controls (keeping newline and tab) from anything printed as text. Defence in depth: the schema already rejects them. */
// eslint-disable-next-line no-control-regex
export const printable = (text: string): string => text.replace(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g, "?");

const materialize = (scenario: BrainScenario, canary: string) => {
  const shape = { goal: scenario.goal, injectionPoint: scenario.injection_point_kind, payload: scenario.payload, success: scenario.success };
  return { ...scenario, payload: materializePayload(shape, canary), success: materializeSuccess(shape, canary) };
};

const DIFFICULTIES = ["basic", "intermediate", "advanced"] as const;
const split = (value: string | undefined): string[] => (value ?? "").split(",").map(item => item.trim()).filter(Boolean);

export async function runGenerate(options: GenerateCliOptions, deps: GenerateDeps = defaults): Promise<number> {
  if (options.listGenerators) { deps.out("The generators are listed by `0 redteam list generators` (filters: --area, --difficulty, --tier, --format json). Name some with --generator <ids> here.\n"); return 0; }
  const format = options.format ?? "text";
  if (format !== "text" && format !== "json") throw new UsageError("--format must be text or json.");
  const generators = split(options.generator);
  const unknown = generators.filter(id => !CATALOG_BY_ID.has(id));
  if (unknown.length) throw new UsageError(`Unknown generator: ${unknown.join(", ")}. Run \`0 redteam list generators\` for the ids.`);
  if (options.difficulty !== undefined && !(DIFFICULTIES as readonly string[]).includes(options.difficulty)) throw new UsageError(`--difficulty must be one of: ${DIFFICULTIES.join(", ")}.`);
  const strategy = options.strategy ? strategyById(options.strategy) : undefined;
  if (options.strategy && !strategy) throw new UsageError(`Unknown strategy: ${options.strategy}. Run \`0 redteam list strategies\` for the ids.`);
  if (strategy && !strategy.apply) throw new UsageError(`Strategy ${strategy.id} has no single-turn delivery (${strategy.turns === "multi" ? "it needs several turns" : "it needs an attacker model"}), so it cannot reshape a printed payload. Use \`0 redteam attack\` for it.`);
  const filter = { ...(generators.length ? { generators } : {}), ...(options.area ? { areas: [options.area] } : {}), ...(options.difficulty ? { difficulties: [options.difficulty as Difficulty] } : {}) };
  const filtered = Object.keys(filter).length > 0;
  const request = buildRequest(options, deps);
  let preview: string;
  try { preview = brainDryRun(request); } catch (error) { throw new UsageError(error instanceof Error ? error.message : String(error)); }
  if (options.dryRun) { deps.out(`${preview}\n`); deps.err("dry run: nothing was sent."); return 0; }
  const canary = options.canary ?? newCanary();
  const result = await requestScenarios(request, { seed: canary, ...(filtered ? { filter } : {}), ...(options.url ? { url: options.url } : {}), ...(options.offline ? { offline: true } : {}) }, deps);
  const scenarios = result.scenarios.map(scenario => {
    const done = materialize(scenario, canary);
    if (!strategy) return done;
    // Display only: the printed payload is reshaped so it can be inspected; the scenario itself is unchanged.
    const checked = applyChecked(strategy, { payload: done.payload, canary, seed: 1 });
    return { ...done, strategy: strategy.id, variants: checked.variants.map(variant => ({ text: variant.text, notes: variant.notes })), droppedVariants: checked.dropped };
  });
  deps.err(`canary: ${canary}`);
  if (result.source === "remote") deps.err("warning: these payloads came from a remote brain and are hostile by design; run them only against decoy or sandboxed tools.");
  if (result.source === "remote" && filtered) deps.err("note: --generator, --area and --difficulty only filter the open catalog; the remote brain got the manifest request as before.");
  if (!scenarios.length) deps.err("No scenarios matched.");
  if (format === "json") {
    deps.out(`${JSON.stringify({ source: result.source, note: result.note, canary, ...(result.watermark ? { watermark: result.watermark } : {}), scenarios }, null, 2)}\n`);
    return 0;
  }
  const lines = [`source: ${result.source}`, printable(result.note), ""];
  for (const scenario of scenarios) {
    lines.push(...[`[${scenario.difficulty}] ${scenario.id}: ${scenario.goal}`, `  inject at: ${scenario.injection_point_kind}`, `  payload: ${scenario.payload}`, `  success: ${scenario.success}`, `  tags: ${scenario.tags.map(tag => tag.id).join(", ")}`].map(printable));
    if ("variants" in scenario) {
      scenario.variants.forEach((variant, i) => lines.push(...[`  strategy ${scenario.strategy} variant ${i + 1} of ${scenario.variants.length} (${variant.notes}): ${variant.text}`].map(printable)));
      for (const drop of scenario.droppedVariants) lines.push(printable(`  strategy ${scenario.strategy} dropped by the linter (${drop.notes}): ${drop.problems.join("; ")}`));
    }
    lines.push("");
  }
  deps.out(`${lines.join("\n")}\n`);
  return 0;
}

export function registerRedteamGenerateCommand(redteam: Command, deps: GenerateDeps = defaults): void {
  redteam.command("generate")
    .description("Make prompt-injection scenarios for an agent from its tool manifest: from a hosted brain if ZERO_BRAIN_URL or --url is set, else from the open catalog of test generators")
    .option("--manifest <file>", "Required unless --list-generators: JSON file listing the agent's tools (name, privilege, gate) and the kinds of input it reads (sources)")
    .option("--framework <name>", "Prefer scenarios mapped to this framework, such as LLM01 or AML.T0051")
    .option("--count <n>", "How many scenarios, 1 to 20")
    .option("--url <url>", "The brain endpoint (default: ZERO_BRAIN_URL); https, or http to localhost. The token comes from ZERO_BRAIN_TOKEN")
    .option("--dry-run", "Print the exact request that would be sent and send nothing")
    .option("--offline", "Never contact a brain; use the open catalog")
    .option("--generator <ids>", "Open catalog only: comma separated generator ids (see `0 redteam list generators`)")
    .option("--area <name>", "Open catalog only: area name or prefix, such as Payment")
    .option("--difficulty <level>", "Open catalog only: basic, intermediate or advanced")
    .option("--strategy <id>", "Also print each payload reshaped by this single-turn strategy, and say which variants the linter dropped (display only)")
    .option("--list-generators", "Point to `0 redteam list generators` and exit")
    .option("--canary <text>", "Put this canary in each payload instead of making one")
    .option("--format <format>", "text or json", "text")
    .action(async (options: GenerateCliOptions) => { process.exitCode = await runGenerate(options, deps); });
}
