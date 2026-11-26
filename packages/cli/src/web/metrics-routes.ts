import { readHostObservations, refreshMetricHostReceipts, type MetricHostObservation } from "../metric-host-receipts.js";
import { METRIC_GROUPS, groupMetrics, parseSince, readRunMetrics, renderGroupsCsv, summarizeMetrics, type MetricGroup, type RunMetric } from "../run-metrics.js";

/** Local metrics are workspace-wide: scoped team viewers must not enumerate other agents' runs. */
export function handleMetricsRequest(path: string, method: string, query: URLSearchParams, allowed: boolean, read: () => RunMetric[] = readRunMetrics, observations: () => MetricHostObservation[] = readHostObservations) {
  if (path !== "run-metrics") return undefined;
  if (!allowed) return { status: 403, data: { error: "Only workspace owners can read run metrics." } };
  if (method !== "GET") return { status: 405, data: { error: "Method not allowed" } };
  const by = query.get("by") ?? "sentinel";
  if (!(METRIC_GROUPS as readonly string[]).includes(by)) return { status: 400, data: { error: "Unknown grouping" } };
  const sinceText = query.get("since") ?? "7d";
  const since = parseSince(sinceText, Date.now());
  if (since === undefined) return { status: 400, data: { error: "Invalid since value" } };
  const records = read();
  const receipts = observations();
  const rows = groupMetrics(records, by as MetricGroup, { since }, receipts);
  return { status: 200, data: { by, since: new Date(since).toISOString(), rows, summary: summarizeMetrics(records, { since }, receipts), csv: renderGroupsCsv(by as MetricGroup, rows) } };
}

/** The dashboard server's normal mutation/CSRF gate runs before this owner-only route. */
export async function handleMetricHostRefreshRequest(path: string, method: string, input: unknown, allowed: boolean, deps = { read: readRunMetrics, refresh: refreshMetricHostReceipts }) {
  if (path !== "run-metrics/refresh-host") return undefined;
  if (!allowed) return { status: 403, data: { error: "Only workspace owners can refresh host receipts." } };
  if (method !== "POST") return { status: 405, data: { error: "Method not allowed" } };
  const body = input && typeof input === "object" ? input as Record<string, unknown> : {};
  if (typeof body.checkout !== "string" || body.checkout.length > 4096 || (body.bitbucketUrl !== undefined && typeof body.bitbucketUrl !== "string")) return { status: 400, data: { error: "Provide the local checkout explicitly." } };
  try { return { status: 200, data: await deps.refresh(deps.read(), body.checkout, { ...(typeof body.bitbucketUrl === "string" ? { bitbucketUrl: body.bitbucketUrl } : {}) }) }; }
  catch { return { status: 400, data: { error: "Could not refresh host receipts for that checkout. Check the local origin and host configuration." } }; }
}
