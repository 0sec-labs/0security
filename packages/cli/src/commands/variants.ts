/**
 * `0 findings variants <finding>` and the automatic variant hunt behind `findings verify` and `findings fix`.
 *
 * A finding carries a structured root cause (bug class, unsafe pattern, missing guard, design origin). A fresh thread
 * searches the folder for the same bug at other sites, seeded from that record; each site it proves becomes a finding
 * with `variantOf` pointing at the seed. After a fix, the recorded variants are checked again and each is marked
 * fixed-pending-merge or left open (it becomes fixed only when the fix pull request is seen merged). The thread never records anything itself: it answers with one json block and this module stores it.
 */
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { Option, type Command } from "commander";
import {
  linesWithin, normalizeAttackCategory, parseRescan, parseRootCauseReply, parseVariantReport, variantHuntPrompt, variantRescanPrompt, variantRootCausePrompt,
  type Finding, type ParsedVariant, type PromptCandidate, type RescanState, type RootCause,
} from "@0/engine/shared";
import { listOsecRunDatabasePaths, osecDB, resolveOsecDbPath } from "@0/engine/storage";
import { consoleTransportOptions, type ConsoleClient, type ConsoleTransportOptions } from "../console-client.js";
import { resolveFindingId, shortFindingId } from "../finding-id.js";
import { settleFromFixPullRequests, VARIANT_FIXED_PENDING_MERGE } from "../finding-variants.js";
import { findingDatabasePaths } from "../finding-focus.js";
import type { StateStore } from "./burndown.js";
import { runGh } from "../host/gh.js";
import { selectHost, type Host } from "../host/index.js";
import { connect, DEFAULT_SCAN_MODEL, scanModelField, defaultScanDeps, waitForThread, type ScanDeps } from "./scan.js";
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
/** Candidates one thread judges. */
export const CANDIDATE_BATCH = 20;
/** Share of a hunt's spend cap given to the root-cause thread when the seed has none. */
const DERIVE_SHARE = 0.2;
/** Findings with this status are the ones a rescan leaves alone (set by a person or a verified fix, never by a rescan). */
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
  /**
   * The variant is fixed in the fix work tree. That is not `fixed`: the branch may never merge. It is recorded as
   * `fixed-pending-merge` and flips to `fixed` only when the fix pull request is observed merged.
   */
  markFixedPendingMerge(parent: VariantParent, variantId: string): void;
}

/** The tree-wide candidate list for a seed, computed in code. Tests pass a stub; the default uses the code index. */
export interface CandidateSource {
  candidates: PromptCandidate[]; total: number; omitted: number; engine: string; strategy: string; notes: string[];
}
export type CandidateFinder = (folder: string, parent: VariantParent, rootCause: RootCause) => Promise<CandidateSource>;

export const defaultCandidateFinder: CandidateFinder = async (folder, parent, rootCause) => {
  const { variantCandidates } = await import("@0/engine/code-index/variant-candidates");
  const list = await variantCandidates(folder, { ...(parent.path ? { path: parent.path } : {}), ...(parent.startLine ? { startLine: parent.startLine } : {}), ...(parent.endLine ? { endLine: parent.endLine } : {}) }, rootCause);
  return { candidates: list.candidates.map(c => ({ id: c.id, file: c.file, line: c.line, ...(c.symbol ? { symbol: c.symbol } : {}), entries: c.entries, entriesOmitted: c.entriesOmitted, why: c.why, ...(c.guardHint ? { guardHint: c.guardHint } : {}) })), total: list.total, omitted: list.omitted, engine: list.engine, strategy: list.strategy, notes: list.notes };
};

export interface VariantDeps extends Pick<ScanDeps, "open" | "err" | "sleep" | "startConsole"> {
  /** Candidate finder; the default reads the code index. */
  candidates?: CandidateFinder;
  out(text: string): void;
  store: VariantStore;
  loadParent(id: string, dbPath: string | undefined): VariantParent;
  exists(folder: string): boolean;
  now(): number;
  /** Flip this finding's `fixed-pending-merge` variants to `fixed` when its fix pull request was merged. Asks the code host. */
  settle?(parent: VariantParent): Promise<{ settled: number; merged: boolean }>;
}

export interface VariantRunOptions { model?: string; timeout: string; budget: string }

export interface HuntResult {
  threadId?: string; costUsd?: number; tokens?: number; created: string[]; skipped: number; /** What the code-computed checklist held and how the thread disposed of it. */ checklist?: ChecklistReport; rootCause?: RootCause; rootCauseSource?: "stored" | "derived"; error?: string;
}
export interface ChecklistReport {
  engine: string; strategy: string; total: number; listed: number; omitted: number;
  /** Threads the checklist was split over. */ batches?: number;
  verdicts: { variant: number; guarded: number; not_reachable: number; unsure: number }; undisposed: string[];
  /** Candidate ids of the variants that were stored. */
  stored: string[]; notes: string[];
}
export interface RescanItem { id: string; title: string; state: RescanState | "unchecked"; reasoning?: string }
export interface RescanResult { threadId?: string; costUsd?: number; tokens?: number; items: RescanItem[]; /** Variants moved from fixed-pending-merge to fixed because the fix pull request was merged. */ settled?: number; error?: string }

interface PromptThread { id: string; reply?: string; error?: string; costUsd?: number; tokens?: number; failed: boolean }

async function runPromptThread(client: ConsoleClient, deps: Pick<ScanDeps, "sleep" | "err">, folder: string, title: string, prompt: string, options: VariantRunOptions): Promise<PromptThread> {
  const created = asJson(asJson(await client.request("POST", "/api/console/sessions", { runtime: { ...scanModelField(options) }, title: title.slice(0, 120), costCeilingUsd: Number(options.budget) })).session);
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
export async function huntVariants(client: ConsoleClient, deps: Pick<VariantDeps, "store" | "err" | "sleep" | "candidates">, folder: string, parent: VariantParent, options: VariantRunOptions, extra: { fixCommit?: string } = {}): Promise<HuntResult> {
  const known = deps.store.variantsOf(parent);
  let seedCause = parent.rootCause;
  let tokens: number | undefined;
  let costUsd: number | undefined;
  const add = (t: PromptThread) => {
    if (t.tokens !== undefined) tokens = (tokens ?? 0) + t.tokens;
    if (t.costUsd !== undefined) costUsd = (costUsd ?? 0) + t.costUsd;
  };
  const totals = () => ({ ...(tokens !== undefined ? { tokens } : {}), ...(costUsd !== undefined ? { costUsd } : {}) });
  const seed = { id: parent.id, title: parent.title, category: parent.category, description: parent.description, ...(parent.path ? { path: parent.path } : {}), ...(parent.startLine ? { startLine: parent.startLine } : {}), ...(parent.endLine ? { endLine: parent.endLine } : {}) };
  const failure = (error: unknown): HuntResult => ({ ...totals(), created: [], skipped: 0, error: error instanceof Error ? error.message.split("\n")[0]! : String(error) });
  try {
    // The candidate search needs a root cause. A seed without one gets a short thread that only reads the seed's site and states it.
    if (!seedCause) {
      // The whole hunt stays inside one allowance: a fifth of it for this thread, the rest is split over the batches below.
      const derive = await runPromptThread(client, deps, folder, `Root cause: ${parent.title}`, variantRootCausePrompt(seed), { ...options, budget: String(Number(options.budget) * DERIVE_SHARE) });
      add(derive);
      seedCause = parseRootCauseReply(derive.reply);
      if (seedCause) deps.store.saveRootCause(parent, seedCause);
    }
  } catch (error) { return failure(error); }
  let source: CandidateSource | undefined;
  if (seedCause) {
    try { source = await (deps.candidates ?? defaultCandidateFinder)(folder, parent, seedCause); } catch (error) { deps.err(`Candidate search failed (${error instanceof Error ? error.message.split("\n")[0] : String(error)}); the thread will search on its own.`); }
    if (source && !source.candidates.length) deps.err(`Candidate search found no sites${source.notes.length ? ` (${source.notes.join("; ")})` : ""}; the thread will search on its own.`);
  }
  const items = source?.candidates ?? [];
  const knownBlock = known.map(v => ({ id: v.id, title: v.title, ...(v.path ? { path: v.path } : {}), ...(v.startLine ? { startLine: v.startLine } : {}) }));
  const promptOptions = { ...(seedCause ? { rootCause: seedCause } : {}), ...(extra.fixCommit ? { fixCommit: extra.fixCommit } : {}), known: knownBlock };
  // A long checklist in one answer is where models drop items or the json block. Judge it in batches, one fresh thread each, in parallel.
  const batches: PromptCandidate[][] = [];
  for (let i = 0; i < items.length; i += CANDIDATE_BATCH) batches.push(items.slice(i, i + CANDIDATE_BATCH));
  if (!batches.length) batches.push([]);
  interface BatchResult { thread?: PromptThread; report?: ReturnType<typeof parseVariantReport>; error?: string }
  const batchOptions: VariantRunOptions = { ...options, budget: String(Number(options.budget) * (parent.rootCause ? 1 : 1 - DERIVE_SHARE) / batches.length) };
  const judge = async (batch: PromptCandidate[], index: number): Promise<BatchResult> => {
    const candidates = batch.length && source ? { candidates: { items: batch, total: index === 0 ? source.total : batch.length, omitted: index === 0 ? source.omitted : 0 } } : {};
    let result: BatchResult = {};
    // One repeat for a batch whose answer holds no verdict at all.
    for (let attempt = 0; attempt < (batch.length ? 2 : 1); attempt++) {
      try {
        const thread = await runPromptThread(client, deps, folder, `Variants${batches.length > 1 ? ` ${index + 1}/${batches.length}` : ""}: ${parent.title}`, variantHuntPrompt(seed, { ...promptOptions, ...candidates }), batchOptions);
        add(thread);
        result = { thread, ...(thread.reply ? { report: parseVariantReport(thread.reply, batch) } : { error: thread.error ?? "the thread returned no answer" }) };
        if (!batch.length || result.report?.dispositions.length || result.report?.variants.length) break;
      } catch (error) { result = { error: error instanceof Error ? error.message.split("\n")[0]! : String(error) }; }
    }
    return result;
  };
  const results = await Promise.all(batches.map((batch, i) => judge(batch, i)));
  const first = results.find(r => r.thread)?.thread;
  const base = { ...(first ? { threadId: first.id } : {}), ...totals() };
  const answered = results.filter(r => r.report);
  if (!answered.length) return { ...base, created: [], skipped: 0, error: results.find(r => r.error)?.error ?? "the thread returned no answer" };
  const reports = answered.map(r => r.report!);
  const rootCause = seedCause ?? reports.find(r => r.rootCause)?.rootCause;
  if (!seedCause && rootCause) deps.store.saveRootCause(parent, rootCause);
  const created: string[] = [];
  const stored: string[] = [];
  const dispositions = reports.flatMap(r => r.dispositions);
  let skipped = 0;
  for (const variant of reports.flatMap(r => r.variants)) {
    if (overlaps(variant, parent) || known.some(k => overlaps(variant, k))) { skipped++; continue; }
    const id = deps.store.saveVariant(parent, variant, rootCause);
    if (created.includes(id)) continue;
    created.push(id);
    if (variant.candidateId) stored.push(variant.candidateId);
  }
  const problem = results.find(r => r.error)?.error ?? results.find(r => r.thread?.error)?.thread?.error;
  const noVerdicts = items.length > 0 && !dispositions.length ? "the answer held no verdict for any checklist candidate" : undefined;
  let checklist: ChecklistReport | undefined;
  if (items.length && source) {
    const verdicts = { variant: 0, guarded: 0, not_reachable: 0, unsure: 0 };
    for (const d of dispositions) verdicts[d.verdict]++;
    const done = new Set(dispositions.map(d => d.id));
    checklist = { engine: source.engine, strategy: source.strategy, total: source.total, listed: items.length, omitted: source.omitted, batches: batches.length, verdicts, undisposed: items.filter(c => !done.has(c.id)).map(c => c.id), stored, notes: source.notes };
  }
  const error = problem ?? noVerdicts;
  return { ...base, created, skipped, ...(checklist ? { checklist } : {}), ...(rootCause ? { rootCause, rootCauseSource: parent.rootCause ? "stored" as const : "derived" as const } : {}), ...(error ? { error } : {}) };
}

/**
 * Check the recorded variants again and report what the thread says. A variant it finds fixed is only marked fixed-pending-merge, never fixed, because
 * nothing but a model's reading of the code backs it. A variant the thread does not answer for is "unchecked".
 */
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
    if (answer.state === "fixed") deps.store.markFixedPendingMerge(parent, v.id);
    return { id: v.id, title: v.title, state: answer.state, ...(answer.reasoning ? { reasoning: answer.reasoning } : {}) };
  });
  return { ...base, items, ...(!thread.reply ? { error: thread.error ?? "the thread returned no answer" } : {}) };
}

const idFor = (parent: VariantParent, variant: Pick<ParsedVariant, "path" | "startLine">): string =>
  `variant-${createHash("sha256").update(`${parent.id}\n${variant.path}\n${variant.startLine}`).digest("hex").slice(0, 24)}`;

/** A variant is an unverified model report: it never enters the findings as critical or high until a verify run confirms it. */
export const VARIANT_MAX_SEVERITY = "medium";
export const VARIANT_CONFIDENCE = 0.4;
const SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"];
export function cappedVariantSeverity(severity: string): Finding["severity"] {
  return (SEVERITY_ORDER.indexOf(severity) > SEVERITY_ORDER.indexOf(VARIANT_MAX_SEVERITY) ? VARIANT_MAX_SEVERITY : severity) as Finding["severity"];
}

/** The finding a variant is stored as. The first line of the request is the site, so each site has its own fingerprint. */
export function variantFinding(parent: Pick<VariantParent, "id" | "category" | "title">, variant: ParsedVariant, rootCause: RootCause | undefined, id: string, now: number): Finding {
  const site = `${variant.path}:${variant.startLine}`;
  const severity = cappedVariantSeverity(variant.severity);
  const capped = severity !== variant.severity;
  return {
    id, templateId: "variant-hunting", title: variant.title,
    description: `Unverified variant of ${parent.id}: ${parent.title}${variant.candidateId ? ` (hunt candidate ${variant.candidateId})` : ""}\n\nA search thread reported this site from the same root cause. Nobody has confirmed it${capped ? `, so its severity is capped at ${severity} (the thread said ${variant.severity})` : ""}. Run \`findings verify\` on it to confirm or reject it.\n\n${variant.description}${variant.suggestedFix ? `\n\nSuggested fix: ${variant.suggestedFix}` : ""}`,
    severity, confidence: VARIANT_CONFIDENCE, category: normalizeAttackCategory(parent.category).category, status: "discovered",
    evidence: { request: site, response: variant.evidence, analysis: `Same root cause as ${parent.id}.${variant.candidateId ? ` Hunt candidate ${variant.candidateId}.` : ""}` },
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
  markFixedPendingMerge(parent, variantId) {
    const db = new osecDB(parent.dbPath);
    try {
      // A merged fix stays fixed: only an open variant moves to pending.
      const current = db.listVariantsOf(parent.id).find(row => row.id === variantId);
      if (current?.status !== DONE_STATUS) db.updateFindingStatus(variantId, VARIANT_FIXED_PENDING_MERGE);
    } finally { db.close(); }
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
  settle: parent => settleMergedFix(parent),
};

/** Reads the fix records the fix command keeps and asks the code host (as `findings export-fixes --check-merged` does) whether the fix merged. */
export async function settleMergedFix(parent: VariantParent, store?: StateStore, host: () => Pick<Host, "pullRequestState"> = () => selectHost({ run: runGh })): Promise<{ settled: number; merged: boolean }> {
  const records = Object.values((store ?? (await import("./burndown.js")).fileStore()).load().findings).filter(record => record.finding === parent.id && record.pullRequestUrl);
  if (!records.length) return { settled: 0, merged: false };
  return settleFromFixPullRequests(parent.id, records, host(), findingDatabasePaths(parent.dbPath));
}

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
    if (options.rescan) {
      // A merged fix pull request settles the variants that were fixed pending merge, before they are checked again.
      let settled = 0;
      try { settled = (await deps.settle?.(parent))?.settled ?? 0; } catch { /* no code host: the variants stay pending */ }
      const rescan = await rescanVariants(client, deps, folder, parent, run);
      return { finding: parent.id, folder, mode: "rescan", rescan: { ...rescan, ...(settled ? { settled } : {}) } };
    }
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
    if (h.checklist) lines.push(`Checklist (${h.checklist.engine}, ${h.checklist.strategy}): ${h.checklist.listed} listed of ${h.checklist.total}; variant ${h.checklist.verdicts.variant}, guarded ${h.checklist.verdicts.guarded}, not reachable ${h.checklist.verdicts.not_reachable}, unsure ${h.checklist.verdicts.unsure}${h.checklist.undisposed.length ? `, ${h.checklist.undisposed.length} not answered` : ""}.`);
    if (h.error && !h.created.length) lines.push(`Hunt failed: ${h.error}`);
    else lines.push(`Recorded ${h.created.length} variant${h.created.length === 1 ? "" : "s"}${h.skipped ? `, ${h.skipped} already known` : ""}${h.rootCause ? `; root cause ${h.rootCauseSource === "stored" ? "from the finding" : "derived and stored on it"}: ${h.rootCause.bugClass}` : "; no root cause was recorded"}.`);
    for (const id of h.created) lines.push(`  ${shortFindingId(id)}`);
  }
  if (report.rescan) {
    const r = report.rescan;
    if (r.settled) lines.push(`The fix pull request was merged: ${r.settled} variant${r.settled === 1 ? "" : "s"} marked fixed.`);
    if (!r.items.length && !r.error) lines.push("No open variants are recorded for this finding.");
    for (const item of r.items) lines.push(`  ${(item.state === "open" ? "still open" : item.state === "fixed" ? "fixed, pending merge" : item.state).padEnd(10)} ${shortFindingId(item.id)} ${item.title.slice(0, 70)}`);
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
    .option("--model <model>", `Model for the thread (default: ${DEFAULT_SCAN_MODEL}; ZERO_MODEL or a pinned provider's default when set)`)
    .option("--timeout <seconds>", "Maximum seconds to wait for the thread", String(DEFAULT_TIMEOUT_SECONDS))
    .addOption(new Option("--format <format>", "Output: text or json").choices(["text", "json"])))
    .addHelpText("after", "\nEach variant is stored as a finding with a variantOf link to this one; see it in `0security findings show` and `findings list`. `findings verify` and `findings fix` run this for you (turn it off with --no-variants). The thread is told not to edit files; that instruction is the only limit.\nExit codes: 0 done, 1 the thread returned no answer, 2 usage error.")
    .action(async (finding: string, options: VariantsOptions) => {
      const json = options.format === "json";
      try {
        const report = await runVariants(finding, options, { ...deps, err: json ? text => process.stderr.write(`${text}\n`) : deps.err });
        deps.out(json ? JSON.stringify(report, null, 2) : renderVariantsReport(report));
        process.exitCode = report.hunt?.error && !report.hunt.created.length ? 1 : report.rescan?.error ? 1 : 0;
      } catch (error) { finishWithError(error, { err: deps.err }, json); }
    });
}
