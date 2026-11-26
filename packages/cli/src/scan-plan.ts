/**
 * `0 scan --plan`: what a scan of a folder would involve, worked out from the inventory alone. No model, no scanner binary
 * and no database is touched. The cost range is a rough estimate from one measurement and is stated as such.
 */
import { isEntryPointKind, planBatches, UNIT_KINDS, type Inventory, type InventoryUnit } from "@0/engine";
import type { ScanTierInfo } from "@0/engine/shared";
import { shouldBatch } from "./scan-batched.js";

/** About $0.28 for 8 batches of one fixture (docs/design/benchmark.md, batched scans on medium-app): $0.035 a batch. */
export const MEASURED_USD_PER_BATCH = 0.035;
/** One thread on the same fixture, the mean of three runs. */
export const MEASURED_USD_PER_THREAD = 0.15;
/** Real cost varied 2 to 3 times with code and model, so the range runs from half to three times the measurement. */
export const LOW_FACTOR = 0.5;
export const HIGH_FACTOR = 3;

export type BudgetVerdict = "likely complete" | "likely partial" | "could go either way";

export interface CostEstimate {
  lowUsd: number;
  highUsd: number;
  verdict: BudgetVerdict;
  basis: string;
}

const money = (usd: number): string => (usd < 0.1 ? usd.toFixed(3) : usd < 10 ? usd.toFixed(2) : usd.toFixed(0));

/** The cost range of `threads` model threads against a budget. Pure. */
export function estimateCost(threads: number, batched: boolean, budgetUsd: number): CostEstimate {
  const unit = batched ? MEASURED_USD_PER_BATCH : MEASURED_USD_PER_THREAD;
  const central = Math.max(0, threads) * unit;
  const lowUsd = central * LOW_FACTOR;
  const highUsd = central * HIGH_FACTOR;
  const verdict: BudgetVerdict = highUsd <= budgetUsd ? "likely complete" : lowUsd > budgetUsd ? "likely partial" : "could go either way";
  const basis = batched
    ? `Based on a measurement of about $${MEASURED_USD_PER_BATCH} per batch on one fixture (40 small files); real cost varies 2-3x with code and model, and larger files cost more. This is not a quote.`
    : `Based on a measurement of about $${MEASURED_USD_PER_THREAD} for one thread on one fixture (40 small files); real cost varies 2-3x with code and model. This is not a quote.`;
  return { lowUsd, highUsd, verdict, basis };
}

export interface ModuleRow { module: string; files: number; entryPoints: number; batches: number }

export interface ScanPlan {
  schemaVersion: 1;
  folder: string;
  sourceFiles: number;
  entryPoints: number;
  otherUnits: number;
  /** Entry-point units by kind (not the `other` groups). */
  byKind: Record<string, number>;
  batchSize: number;
  /** Batches the folder would make at `batchSize`. */
  batchCount: number;
  batchesMode: string;
  /** Whether a scan with these options would run in batches. */
  wouldBatch: boolean;
  /** Whether `--batches auto` would batch this folder. */
  autoWouldBatch: boolean;
  budgetUsd: number;
  estimate: { lowUsd: number; highUsd: number; threads: number; verdict: BudgetVerdict; basis: string };
  notes: string[];
  /** The module map: one row per build module (Maven or Gradle) when the folder has more than one, in the order its batches run. */
  modules?: ModuleRow[];
  ownership?: Array<{ owners: string[]; batches: number }>;
  /** The tier map's decision, when a tier map applies; a skipped or pre-pass-only tier means no model would run. */
  tier?: ScanTierInfo;
}

export interface PlanOptions { shardOf?: (unit: InventoryUnit) => string | undefined; ownersOf?: (unit: InventoryUnit) => readonly string[]; folder: string; batchSize: number; batchesMode: string; budgetUsd: number; tier?: ScanTierInfo }

/** The module map of a plan: files, entry points and batches per module. Empty when the plan was not split by module. */
export function moduleRows(batches: ReadonlyArray<{ module?: string; units: readonly InventoryUnit[] }>): ModuleRow[] {
  const rows = new Map<string, { files: Set<string>; entryPoints: number; batches: number }>();
  for (const batch of batches) {
    const key = batch.module ?? "(no build file)";
    const row = rows.get(key) ?? { files: new Set<string>(), entryPoints: 0, batches: 0 };
    row.batches++;
    for (const unit of batch.units) {
      for (const file of unit.files ?? [unit.path]) row.files.add(file);
      if (isEntryPointKind(unit.kind)) row.entryPoints++;
    }
    rows.set(key, row);
  }
  if (!batches.some(batch => batch.module)) return [];
  return [...rows.entries()].map(([module, row]) => ({ module, files: row.files.size, entryPoints: row.entryPoints, batches: row.batches }));
}

/** The plan of a folder from its inventory. Pure. */
export function planScan(inventory: Inventory, options: PlanOptions): ScanPlan {
  const { summary } = inventory;
  const batchList = planBatches(inventory.units, options.batchSize, { ...(options.shardOf ? { shardOf: options.shardOf } : {}), ...(options.ownersOf ? { ownersOf: options.ownersOf } : {}) });
  const ownership = new Map<string, { owners: string[]; batches: number }>();
  if (options.ownersOf) for (const batch of batchList) {
    const owners = batch.owners ?? [];
    const key = JSON.stringify(owners);
    const row = ownership.get(key) ?? { owners, batches: 0 };
    row.batches++; ownership.set(key, row);
  }
  const batchCount = batchList.length;
  const modules = moduleRows(batchList);
  const autoWouldBatch = inventory.units.length > 0 && shouldBatch(inventory, options.batchSize);
  const wouldBatch = options.batchesMode === "on" ? inventory.units.length > 0 : options.batchesMode === "off" ? false : autoWouldBatch;
  const threads = wouldBatch ? batchCount : inventory.units.length ? 1 : 0;
  const estimate = estimateCost(threads, wouldBatch, options.budgetUsd);
  const byKind: Record<string, number> = {};
  for (const kind of UNIT_KINDS) if (kind !== "other" && summary.byKind[kind]) byKind[kind] = summary.byKind[kind]!;
  const notes: string[] = [];
  if (summary.skipped.walkLimit) notes.push("The folder has more files than the inventory walks; later files are not counted.");
  if (summary.skipped.unitLimit) notes.push("The entry-point limit was reached; the files after it fall into groups of other files.");
  if (summary.skipped.tooLarge.length) notes.push(`${summary.skipped.tooLarge.length} file${summary.skipped.tooLarge.length === 1 ? " is" : "s are"} too large to read and sit in groups of other files.`);
  if (!inventory.units.length) notes.push("No source files were found, so there is nothing to scan.");
  return {
    schemaVersion: 1, folder: options.folder, sourceFiles: summary.sourceFiles, entryPoints: summary.entryPoints, otherUnits: summary.otherUnits, byKind,
    batchSize: options.batchSize, batchCount, batchesMode: options.batchesMode, wouldBatch, autoWouldBatch, budgetUsd: options.budgetUsd,
    estimate: { lowUsd: Number(estimate.lowUsd.toFixed(4)), highUsd: Number(estimate.highUsd.toFixed(4)), threads, verdict: estimate.verdict, basis: estimate.basis },
    notes,
    ...(modules.length > 1 ? { modules } : {}),
    ...(options.ownersOf ? { ownership: [...ownership.values()] } : {}),
    ...(options.tier ? { tier: options.tier } : {}),
  };
}

/** The plan as text. */
export function planText(plan: ScanPlan): string {
  const kinds = Object.entries(plan.byKind).map(([kind, count]) => `${kind} ${count}`).join(", ");
  const budget = `$${Number(plan.budgetUsd.toFixed(4))}`;
  const lines = [
    `Plan for ${plan.folder}`,
    ...(plan.tier ? [`Tier: ${plan.tier.name}${plan.tier.reason ? ` (${plan.tier.reason})` : ""}${plan.tier.skipped ? ". A scan would be skipped: no model, scanner or report of findings." : plan.tier.prepassOnly ? ". A scan would run the pattern scanners only: no model." : ""}`] : []),
    ...(plan.ownership ? [`Ownership groups: ${plan.ownership.map(group => `${group.owners.join(", ") || "unowned"} (${group.batches} batches)`).join("; ")}`] : []),
    "This lists the folder only. No model, scanner or database was used.",
    "",
    `Source files: ${plan.sourceFiles}`,
    `Entry points: ${plan.entryPoints}${kinds ? ` (${kinds})` : ""}`,
    `Other units: ${plan.otherUnits} group${plan.otherUnits === 1 ? "" : "s"} of files no entry-point pattern matched`,
    `Batches: ${plan.batchCount} at --batch-size ${plan.batchSize}`,
    `--batches auto ${plan.autoWouldBatch ? "would batch this folder" : "would run this folder as one thread"}${plan.batchesMode !== "auto" ? `; --batches ${plan.batchesMode} ${plan.wouldBatch ? "batches it" : "keeps one thread"}` : ""}`,
  ];
  if (plan.estimate.threads) {
    lines.push(
      `Estimated cost: $${money(plan.estimate.lowUsd)} to $${money(plan.estimate.highUsd)} for ${plan.estimate.threads} thread${plan.estimate.threads === 1 ? "" : "s"}`,
      `At the ${budget} budget: ${plan.estimate.verdict}`,
      plan.estimate.basis,
    );
  }
  if (plan.modules) {
    lines.push("", `Modules: ${plan.modules.length}. A batch never mixes two modules.`, ...plan.modules.slice(0, 40).map(row => `  ${row.module}: ${row.files} files, ${row.entryPoints} entry points, ${row.batches} batch${row.batches === 1 ? "" : "es"}`));
    if (plan.modules.length > 40) lines.push(`  ... and ${plan.modules.length - 40} more (the JSON plan lists all)`);
    lines.push("");
  }
  for (const note of plan.notes) lines.push(note);
  if (plan.estimate.threads && plan.estimate.verdict !== "likely complete") lines.push("A scan that stops at its budget exits 3 and prints the command that continues it.");
  return lines.join("\n");
}
