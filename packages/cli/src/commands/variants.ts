/**
 * `0 findings variants <finding>` and the automatic variant hunt behind `findings verify` and `findings fix`.
 *
 * A finding carries a structured root cause (bug class, unsafe pattern, missing guard, design origin). A fresh thread
 * searches the folder for the same bug at other sites, seeded from that record; each site it proves becomes a finding
 * with `variantOf` pointing at the seed. After a fix, the recorded variants are checked again and each is marked fixed
 * or left open. The thread never records anything itself: it answers with one json block and this module stores it.
 */
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { Option, type Command } from "commander";
import {
  linesWithin, normalizeAttackCategory, parseRescan, parseVariantReport, variantHuntPrompt, variantRescanPrompt,
  type Finding, type ParsedVariant, type RescanState, type RootCause,
} from "@0/engine/shared";
import { listOsecRunDatabasePaths, osecDB, resolveOsecDbPath } from "@0/engine/storage";
import { consoleTransportOptions, type ConsoleClient, type ConsoleTransportOptions } from "../console-client.js";
import { resolveFindingId, shortFindingId } from "../finding-id.js";
import { connect, DEFAULT_SCAN_MODEL, defaultScanDeps, waitForThread, type ScanDeps } from "./scan.js";
import { finishWithError, UsageError } from "./output.js";
import { asJson, finishedThread } from "./thread-output.js";

export const DEFAULT_VARIANT_BUDGET_USD = 1;
/** Receipt-based launch gate; an in-flight provider request can exceed its estimate. */
export class VariantBudget {
  spent = 0;
  known = true;
  constructor(readonly total: number) {}
  record(cost: number | undefined): void {
    if (cost === undefined || !Number.isFinite(cost) || cost < 0) this.known = false;
    else {
      this.spent += cost;
      if (!Number.isFinite(this.spent)) this.known = false;
    }
  }
  allowance(cap: number): number { return this.known ? Math.max(0, Math.min(cap, this.total - this.spent)) : 0; }
  get stoppedReason(): string { return this.known ? "overall budget exhausted" : "cost receipt unavailable; further paid work stopped"; }
}
const DEFAULT_TIMEOUT_SECONDS = 600;
/** Findings with this status are the ones a rescan leaves alone. */
const DONE_STATUS = "fixed";

/** The finding a hunt starts from. */
export interface VariantParent {
  id: string; dbPath: string; scanId: string; title: string; category: string; severity: string; description: string;
  path?: string; startLine?: number; endLine?: number; rootCause?: RootCause; variantOf?: string;
}

export interface StoredVariant { id: string; title: string; status: string; path?: string; startLine?: number; endLine?: number }

/** Where variants are read and written. The default is the findings database; tests pass an in-memory one. */
export interface VariantStore {
  variantsOf(parent: VariantParent): StoredVariant[];
  saveRootCause(parent: VariantParent, rootCause: RootCause): void;
  /** Store one variant as a finding linked to the parent and return its id. Saving the same site again updates it. */
  saveVariant(parent: VariantParent, variant: ParsedVariant, rootCause: RootCause | undefined): string;
  markFixed(parent: VariantParent, variantId: string): void;
}

export interface VariantDeps extends Pick<ScanDeps, "open" | "err" | "sleep" | "startConsole"> {
  out(text: string): void;
  store: VariantStore;
  loadParent(id: string, dbPath: string | undefined): VariantParent;
  exists(folder: string): boolean;
  now(): number;
}

export interface VariantRunOptions { model?: string; timeout: string; budget: string }

export interface HuntResult {
  threadId?: string; costUsd?: number; tokens?: number; created: string[]; skipped: number; rootCause?: RootCause; rootCauseSource?: "stored" | "derived"; error?: string;
}
export interface RescanItem { id: string; title: string; state: RescanState | "unchecked"; reasoning?: string }
export interface RescanResult { threadId?: string; costUsd?: number; tokens?: number; items: RescanItem[]; error?: string }

interface PromptThread { id: string; reply?: string; error?: string; costUsd?: number; tokens?: number; failed: boolean }

async function runPromptThread(client: ConsoleClient, deps: Pick<ScanDeps, "sleep" | "err">, folder: string, title: string, prompt: string, options: VariantRunOptions): Promise<PromptThread> {
  const created = asJson(asJson(await client.request("POST", "/api/console/sessions", { runtime: { model: options.model ?? DEFAULT_SCAN_MODEL }, title: title.slice(0, 120), costCeilingUsd: Number(options.budget) })).session);
  const id = String(created.id);
  const path = `/api/console/sessions/${encodeURIComponent(id)}`;
  await client.request("PATCH", `${path}/configuration`, { workspacePath: folder });
  await client.request("POST", `${path}/messages`, { text: prompt });
  const { snapshot, timedOut } = await waitForThread(client, deps, id, Date.now() + Number(options.timeout) * 1000);
  const done = finishedThread(snapshot);
  const costUsd = done.usage.costUnavailable !== true && typeof done.usage.costUsd === "number" && Number.isFinite(done.usage.costUsd) && done.usage.costUsd >= 0 ? done.usage.costUsd : undefined;
  const tokens = typeof done.usage.inputTokens === "number" && typeof done.usage.outputTokens === "number" && Number.isFinite(done.usage.inputTokens + done.usage.outputTokens) && done.usage.inputTokens >= 0 && done.usage.outputTokens >= 0 ? done.usage.inputTokens + done.usage.outputTokens : undefined;
  return { id, ...(tokens !== undefined ? { tokens } : {}), ...(done.reply ? { reply: done.reply } : {}), ...(done.error || timedOut ? { error: done.error ?? "the thread timed out" } : {}), ...(costUsd !== undefined ? { costUsd } : {}), failed: done.failed || timedOut };
}

const overlaps = (a: { path?: string; startLine?: number; endLine?: number }, b: { path?: string; startLine?: number; endLine?: number }): boolean =>
  Boolean(a.path && b.path && a.startLine && b.startLine && linesWithin({ path: a.path, startLine: a.startLine, ...(a.endLine ? { endLine: a.endLine } : {}) }, { path: b.path, startLine: b.startLine, ...(b.endLine ? { endLine: b.endLine } : {}) }, 0));

/**
 * Hunt for the same bug elsewhere, seeded from the parent's root cause. A parent with no root cause gets the one the
 * thread derives. A variant that sits on the parent's own lines, or on one already recorded, is not stored again.
 */
export async function huntVariants(client: ConsoleClient, deps: Pick<VariantDeps, "store" | "err" | "sleep">, folder: string, parent: VariantParent, options: VariantRunOptions, extra: { fixCommit?: string } = {}): Promise<HuntResult> {
  const known = deps.store.variantsOf(parent);
  const seedCause = parent.rootCause;
  let thread: PromptThread;
  try {
    thread = await runPromptThread(client, deps, folder, `Variants: ${parent.title}`, variantHuntPrompt(
      { id: parent.id, title: parent.title, category: parent.category, description: parent.description, ...(parent.path ? { path: parent.path } : {}), ...(parent.startLine ? { startLine: parent.startLine } : {}), ...(parent.endLine ? { endLine: parent.endLine } : {}) },
      { ...(seedCause ? { rootCause: seedCause } : {}), ...(extra.fixCommit ? { fixCommit: extra.fixCommit } : {}), known: known.map(v => ({ id: v.id, title: v.title, ...(v.path ? { path: v.path } : {}), ...(v.startLine ? { startLine: v.startLine } : {}) })) },
    ), options);
  } catch (error) {
    return { created: [], skipped: 0, error: error instanceof Error ? error.message.split("\n")[0]! : String(error) };
  }
  const base = { threadId: thread.id, ...(thread.tokens !== undefined ? { tokens: thread.tokens } : {}), ...(thread.costUsd !== undefined ? { costUsd: thread.costUsd } : {}) };
  if (!thread.reply) return { ...base, created: [], skipped: 0, error: thread.error ?? "the thread returned no answer" };
  const report = parseVariantReport(thread.reply);
  const rootCause = seedCause ?? report.rootCause;
  if (!seedCause && report.rootCause) deps.store.saveRootCause(parent, report.rootCause);
  const created: string[] = [];
  let skipped = 0;
  for (const variant of report.variants) {
    if (overlaps(variant, parent) || known.some(k => overlaps(variant, k))) { skipped++; continue; }
    created.push(deps.store.saveVariant(parent, variant, rootCause));
  }
  return { ...base, created, skipped, ...(rootCause ? { rootCause, rootCauseSource: seedCause ? "stored" as const : "derived" as const } : {}), ...(thread.error ? { error: thread.error } : {}) };
}

/** Check the recorded variants again and mark each one that is fixed. A variant the thread does not answer for stays as it was. */
export async function rescanVariants(client: ConsoleClient, deps: Pick<VariantDeps, "store" | "err" | "sleep">, folder: string, parent: VariantParent, options: VariantRunOptions): Promise<RescanResult> {
  const pending = deps.store.variantsOf(parent).filter(v => v.status !== DONE_STATUS);
  if (!pending.length) return { items: [] };
  let thread: PromptThread;
  try {
    thread = await runPromptThread(client, deps, folder, `Rescan variants: ${parent.title}`, variantRescanPrompt(
      { title: parent.title, ...(parent.rootCause ? { rootCause: parent.rootCause } : {}) },
      pending.map(v => ({ id: v.id, title: v.title, ...(v.path ? { path: v.path } : {}), ...(v.startLine ? { startLine: v.startLine } : {}), ...(v.endLine ? { endLine: v.endLine } : {}) })),
    ), options);
  } catch (error) {
    return { items: pending.map(v => ({ id: v.id, title: v.title, state: "unchecked" as const })), error: error instanceof Error ? error.message.split("\n")[0]! : String(error) };
  }
  const base = { threadId: thread.id, ...(thread.tokens !== undefined ? { tokens: thread.tokens } : {}), ...(thread.costUsd !== undefined ? { costUsd: thread.costUsd } : {}) };
  const answers = thread.reply ? parseRescan(thread.reply, pending.map(v => v.id)) : new Map();
  const items = pending.map((v): RescanItem => {
    const answer = answers.get(v.id);
    if (!answer) return { id: v.id, title: v.title, state: "unchecked" };
    if (answer.state === "fixed") deps.store.markFixed(parent, v.id);
    return { id: v.id, title: v.title, state: answer.state, ...(answer.reasoning ? { reasoning: answer.reasoning } : {}) };
  });
  return { ...base, items, ...(!thread.reply ? { error: thread.error ?? "the thread returned no answer" } : {}) };
}

const idFor = (parent: VariantParent, variant: Pick<ParsedVariant, "path" | "startLine">): string =>
  `variant-${createHash("sha256").update(`${parent.id}\n${variant.path}\n${variant.startLine}`).digest("hex").slice(0, 24)}`;

/** The finding a variant is stored as. The first line of the request is the site, so each site has its own fingerprint. */
export function variantFinding(parent: Pick<VariantParent, "id" | "category" | "title">, variant: ParsedVariant, rootCause: RootCause | undefined, id: string, now: number): Finding {
  const site = `${variant.path}:${variant.startLine}`;
  return {
    id, templateId: "variant-hunting", title: variant.title,
    description: `Variant of ${parent.id}: ${parent.title}\n\n${variant.description}${variant.suggestedFix ? `\n\nSuggested fix: ${variant.suggestedFix}` : ""}`,
    severity: variant.severity as Finding["severity"], category: normalizeAttackCategory(parent.category).category, status: "discovered",
    evidence: { request: site, response: variant.evidence, analysis: `Same root cause as ${parent.id}.` },
    reviewAnnotation: { path: variant.path, startLine: variant.startLine, ...(variant.endLine ? { endLine: variant.endLine } : {}) },
    ...(rootCause ? { rootCause } : {}), variantOf: parent.id, tool: "variant-hunting", timestamp: now,
  };
}

function annotationOf(row: { reviewAnnotation?: unknown }): { path?: string; startLine?: number; endLine?: number } {
  let value: unknown = row.reviewAnnotation;
  if (typeof value === "string") { try { value = JSON.parse(value); } catch { return {}; } }
  const a = value as { path?: unknown; startLine?: unknown; endLine?: unknown } | null;
  if (!a || typeof a.path !== "string") return {};
  return { path: a.path, ...(typeof a.startLine === "number" ? { startLine: a.startLine } : {}), ...(typeof a.endLine === "number" ? { endLine: a.endLine } : {}) };
}

export const defaultVariantStore = (now: () => number = Date.now): VariantStore => ({
  variantsOf(parent) {
    const db = new osecDB(parent.dbPath);
    try { return db.listVariantsOf(parent.id).map(row => ({ id: row.id, title: row.title, status: row.status, ...annotationOf(row) })); } finally { db.close(); }
  },
  saveRootCause(parent, rootCause) {
    const db = new osecDB(parent.dbPath);
    try { db.setFindingRootCause(parent.id, rootCause); } finally { db.close(); }
  },
  saveVariant(parent, variant, rootCause) {
    const db = new osecDB(parent.dbPath);
    try {
      const id = idFor(parent, variant);
      db.saveFinding(parent.scanId, variantFinding(parent, variant, rootCause, id, now()));
      return id;
    } finally { db.close(); }
  },
  markFixed(parent, variantId) {
    const db = new osecDB(parent.dbPath);
    try { db.updateFindingStatus(variantId, DONE_STATUS); } finally { db.close(); }
  },
});

function loadParent(id: string, dbPath: string | undefined): VariantParent {
  const paths = dbPath ? [resolveOsecDbPath(dbPath)] : [...new Set([...listOsecRunDatabasePaths(), resolveOsecDbPath()])];
  const rows: Array<{ path: string; row: Record<string, unknown> }> = [];
  for (const path of paths) {
    if (!existsSync(path)) continue;
    const db = new osecDB(path);
    try { for (const row of db.listFindings({ limit: 5000 }) as unknown as Array<Record<string, unknown>>) rows.push({ path, row }); } finally { db.close(); }
  }
  let found: { path: string; row: Record<string, unknown> } | undefined;
  try {
    const row = resolveFindingId(rows.map(entry => ({ ...entry, id: String(entry.row.id) })), id);
    found = row;
  } catch (error) { throw new UsageError(error instanceof Error ? error.message : String(error)); }
  if (!found) throw new UsageError(`Finding '${id}' not found.`);
  return parentFromRow(found.path, found.row);
}

/** A hunt seed from a stored finding row. */
export function parentFromRow(dbPath: string, row: Record<string, unknown>): VariantParent {
  const annotation = annotationOf(row);
  const db = new osecDB(dbPath);
  let rootCause: RootCause | undefined;
  try { rootCause = db.getFindingRootCause(String(row.id)); } finally { db.close(); }
  return {
    id: String(row.id), dbPath, scanId: String(row.scanId), title: String(row.title), category: String(row.category), severity: String(row.severity),
    description: String(row.description ?? ""), ...annotation, ...(rootCause ? { rootCause } : {}), ...(typeof row.variantOf === "string" && row.variantOf ? { variantOf: row.variantOf } : {}),
  };
}

export const defaultVariantDeps: VariantDeps = {
  open: defaultScanDeps.open, err: defaultScanDeps.err, sleep: defaultScanDeps.sleep, startConsole: defaultScanDeps.startConsole,
  out: text => process.stdout.write(`${text}\n`),
  store: defaultVariantStore(),
  loadParent,
  exists: folder => existsSync(folder),
  now: () => Date.now(),
};

export interface VariantsOptions extends ConsoleTransportOptions {
  folder?: string; rescan?: boolean; budget: string; model?: string; timeout: string; format?: string;
}

export interface VariantsReport { finding: string; folder: string; mode: "hunt" | "rescan"; hunt?: HuntResult; rescan?: RescanResult }

export async function runVariants(id: string, options: VariantsOptions, deps: VariantDeps, preset?: { client: ConsoleClient }): Promise<VariantsReport> {
  const budget = Number(options.budget);
  if (!Number.isFinite(budget) || budget <= 0) throw new UsageError("--budget must be a positive number of USD.");
  if (!Number.isFinite(Number(options.timeout)) || Number(options.timeout) <= 0) throw new UsageError("--timeout must be a positive number of seconds.");
  if (options.computer || options.engineUrl) throw new UsageError("0security findings variants reads files on this machine; run it against the local console.");
  const folder = resolve(options.folder ?? process.cwd());
  if (!deps.exists(folder)) throw new UsageError(`The folder ${folder} does not exist. Pass the folder that was scanned with --folder.`);
  const parent = deps.loadParent(id, options.dbPath);
  if (parent.variantOf) throw new UsageError(`Finding ${shortFindingId(parent.id)} is itself a variant of ${shortFindingId(parent.variantOf)}; hunt from that one.`);
  const run: VariantRunOptions = { timeout: options.timeout, budget: options.budget, ...(options.model ? { model: options.model } : {}) };
  let client = preset?.client;
  let stop: (() => void) | undefined;
  if (!client) { const connection = await connect(options, deps); client = connection.client; stop = connection.stop; }
  try {
    if (options.rescan) return { finding: parent.id, folder, mode: "rescan", rescan: await rescanVariants(client, deps, folder, parent, run) };
    return { finding: parent.id, folder, mode: "hunt", hunt: await huntVariants(client, deps, folder, parent, run) };
  } finally { stop?.(); }
}

/** One line per rescanned variant, for `findings variants --rescan` and the fix summary. */
export function rescanSummary(result: RescanResult): { fixed: number; open: number; unchecked: number } {
  const count = (state: RescanItem["state"]) => result.items.filter(item => item.state === state).length;
  return { fixed: count("fixed"), open: count("open"), unchecked: count("unsure") + count("unchecked") };
}

export function renderVariantsReport(report: VariantsReport): string {
  const lines = [`Variants of ${shortFindingId(report.finding)} (${report.mode}) in ${report.folder}`];
  if (report.hunt) {
    const h = report.hunt;
    if (h.error && !h.created.length) lines.push(`Hunt failed: ${h.error}`);
    else lines.push(`Recorded ${h.created.length} variant${h.created.length === 1 ? "" : "s"}${h.skipped ? `, ${h.skipped} already known` : ""}${h.rootCause ? `; root cause ${h.rootCauseSource === "stored" ? "from the finding" : "derived and stored on it"}: ${h.rootCause.bugClass}` : "; no root cause was recorded"}.`);
    for (const id of h.created) lines.push(`  ${shortFindingId(id)}`);
  }
  if (report.rescan) {
    const r = report.rescan;
    if (!r.items.length && !r.error) lines.push("No open variants are recorded for this finding.");
    for (const item of r.items) lines.push(`  ${(item.state === "open" ? "still open" : item.state).padEnd(10)} ${shortFindingId(item.id)} ${item.title.slice(0, 70)}`);
    if (r.error) lines.push(`Rescan problem: ${r.error}`);
  }
  return lines.join("\n");
}

export function registerVariantsCommand(program: Command, deps: VariantDeps = defaultVariantDeps): void {
  consoleTransportOptions(program.command("variants <finding>")
    .description("Experimental: hunt for the same bug at other sites from a finding's root cause, or rescan the recorded variants")
    .option("--folder <dir>", "The folder that was scanned; the thread reads the code there (default: the current directory)")
    .option("--rescan", "Check the variants already recorded for this finding and mark each fixed or still open; hunt for no new ones")
    .option("--budget <usd>", "Spend cap for the thread, in USD", String(DEFAULT_VARIANT_BUDGET_USD))
    .option("--model <model>", `Model for the thread (default: ${DEFAULT_SCAN_MODEL})`)
    .option("--timeout <seconds>", "Maximum seconds to wait for the thread", String(DEFAULT_TIMEOUT_SECONDS))
    .addOption(new Option("--format <format>", "Output: text or json").choices(["text", "json"])))
    .addHelpText("after", "\nEach variant is stored as a finding with a variantOf link to this one; see it in `0security findings show` and `findings list`. `findings verify` and `findings fix` run this for you (turn it off with --no-variants). Nothing is edited.\nExit codes: 0 done, 1 the thread returned no answer, 2 usage error.")
    .action(async (finding: string, options: VariantsOptions) => {
      const json = options.format === "json";
      try {
        const report = await runVariants(finding, options, { ...deps, err: json ? text => process.stderr.write(`${text}\n`) : deps.err });
        deps.out(json ? JSON.stringify(report, null, 2) : renderVariantsReport(report));
        process.exitCode = report.hunt?.error && !report.hunt.created.length ? 1 : report.rescan?.error ? 1 : 0;
      } catch (error) { finishWithError(error, { err: deps.err }, json); }
    });
}
