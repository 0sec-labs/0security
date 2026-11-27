/**
 * The helper threads a scan thread started with spawn_agent, as the report shows them.
 *
 * The status poll of a scan reads `workers=summary`, which carries one row per helper (task, status, turn and tool
 * counts, tokens). The model wrote the task and result text while it read the repository, so it is clipped, stripped
 * of control characters and reported as data. Token counts are already part of the thread's own usage (the session
 * charges every helper call to it); they are listed here so a reader can see how much of the total was delegated.
 */
import type { ScanChildren, ScanChildThread } from "@0/engine/shared";

export const MAX_CHILD_ITEMS = 50;
const SCOPE_CHARS = 240;
const RESULT_CHARS = 300;

type Row = Record<string, unknown>;
const rec = (value: unknown): Row => (value && typeof value === "object" && !Array.isArray(value) ? value as Row : {});
const count = (value: unknown): number | undefined => (typeof value === "number" && Number.isFinite(value) && value >= 0 ? Math.floor(value) : undefined);
// eslint-disable-next-line no-control-regex
const clip = (text: unknown, max: number): string => String(text ?? "").replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim().slice(0, max);

/** One row per helper of a snapshot, in the order the console lists them. Absent or malformed workers give an empty list. */
export function childrenOf(snapshot: Row): ScanChildThread[] {
  const workers = Array.isArray(snapshot["workers"]) ? snapshot["workers"] as unknown[] : [];
  const rows: ScanChildThread[] = [];
  for (const raw of workers) {
    const worker = rec(raw);
    const id = clip(worker["id"], 80).replace(/[^A-Za-z0-9._:-]/g, "");
    if (!id) continue;
    const telemetry = rec(worker["telemetry"]);
    const usage = rec(telemetry["usage"]);
    const turns = count(telemetry["turns"]) ?? count(worker["turnCount"]) ?? (Array.isArray(worker["transcript"]) ? worker["transcript"].length : undefined);
    const toolCalls = count(worker["toolCallCount"]);
    const inputTokens = count(telemetry["inputTokens"]) ?? count(usage["inputTokens"]);
    const outputTokens = count(telemetry["outputTokens"]) ?? count(usage["outputTokens"]);
    const findings = count(telemetry["findings"]);
    const name = clip(worker["name"], 80);
    const parentId = clip(worker["parentId"], 80).replace(/[^A-Za-z0-9._:-]/g, "");
    const result = clip(worker["error"] ?? worker["summary"], RESULT_CHARS);
    rows.push({
      id, ...(name ? { name } : {}), ...(parentId ? { parentId } : {}), status: clip(worker["status"], 20) || "unknown", scope: clip(worker["task"], SCOPE_CHARS),
      ...(turns !== undefined ? { turns } : {}), ...(toolCalls !== undefined ? { toolCalls } : {}),
      ...(inputTokens !== undefined ? { inputTokens } : {}), ...(outputTokens !== undefined ? { outputTokens } : {}),
      ...(findings !== undefined ? { findings } : {}), ...(result ? { result } : {}),
    });
  }
  return rows;
}

/** Totals over the helpers of every thread of a scan; undefined when no thread started one. A helper seen twice counts once. */
export function summarizeChildren(groups: readonly (readonly ScanChildThread[])[]): ScanChildren | undefined {
  const seen = new Map<string, ScanChildThread>();
  for (const group of groups) for (const child of group) seen.set(child.id, child);
  const all = [...seen.values()];
  if (!all.length) return undefined;
  const byStatus: Record<string, number> = {};
  for (const child of all) byStatus[child.status] = (byStatus[child.status] ?? 0) + 1;
  const withUsage = all.filter(child => child.inputTokens !== undefined || child.outputTokens !== undefined);
  const sum = (pick: (child: ScanChildThread) => number | undefined): number => all.reduce((total, child) => total + (pick(child) ?? 0), 0);
  return {
    count: all.length, byStatus, turns: sum(child => child.turns), toolCalls: sum(child => child.toolCalls), findings: sum(child => child.findings),
    ...(withUsage.length ? { inputTokens: sum(child => child.inputTokens), outputTokens: sum(child => child.outputTokens) } : {}),
    items: all.slice(0, MAX_CHILD_ITEMS), ...(all.length > MAX_CHILD_ITEMS ? { omitted: all.length - MAX_CHILD_ITEMS } : {}),
  };
}

/** The totals without the list, for the coverage block. */
export function childTotals(children: ScanChildren | undefined): Omit<ScanChildren, "items" | "omitted"> | undefined {
  if (!children) return undefined;
  const { items: _items, omitted: _omitted, ...totals } = children;
  return totals;
}
