import { metricTotal } from "./run-metrics-model";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useBackendApi } from "@/api";
import { queryKeys } from "@/queries";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/state-panel";

type HostReceipts = { pullRequests: number; merged: number; closed: number; open: number; unknown: number; shareMerged: number | null; ciPassing: number; ciFailing: number; ciPending: number; ciNone: number; ciUnknown: number; lastCheckedAt: string | null; unlinkedFixRuns: number };
type Row = { host?: HostReceipts; unknownCostRuns?: number; unknownTokenRuns?: number; key: string; runs: number; costUsd: number; tokens: number; proposed: number; checksPassed: number; failed: number; costPerProposedFix: number | null; shareVerified: number | null };
type Metrics = { by: string; since: string; rows: Row[]; csv: string; summary: { runs: number } };
export function RunMetricsPage() {
  const { client } = useBackendApi();
  const [checkout, setCheckout] = useState("");
  const [hostPending, setHostPending] = useState(false);
  const [hostNotice, setHostNotice] = useState("");
  const [by, setBy] = useState("sentinel");
  const [since, setSince] = useState("7d");
  const query = useQuery({ queryKey: queryKeys.runMetrics(client.backendId, by, since), queryFn: async (): Promise<Metrics> => {
    const response = await client.request(`/api/console/run-metrics?by=${by}&since=${since}`);
    if (!response.ok) throw new Error(response.status === 403 ? "Only workspace owners can read run metrics." : "Could not load run metrics.");
    return response.json();
  } });
  const refreshHost = async () => {
    setHostPending(true); setHostNotice("");
    try {
      const response = await client.request("/api/console/run-metrics/refresh-host", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ checkout }) });
      if (!response.ok) throw new Error("Could not refresh host receipts. Check the checkout, host configuration and owner access.");
      const result = await response.json() as { checked: number; remaining: number; unavailable: number };
      setHostNotice(`Checked ${result.checked} pull requests; ${result.unavailable} have unavailable receipts; ${result.remaining} remain. Missing receipts stay unknown.`);
      await query.refetch();
    } catch (error) { setHostNotice(error instanceof Error ? error.message : "Host receipts unavailable."); }
    finally { setHostPending(false); }
  };
  const download = (format: "csv" | "json") => {
    if (!query.data) return;
    const url = URL.createObjectURL(new Blob([format === "csv" ? query.data.csv : JSON.stringify(query.data, null, 2)], { type: format === "csv" ? "text/csv" : "application/json" }));
    const link = document.createElement("a"); link.href = url; link.download = `run-metrics.${format}`; link.click(); URL.revokeObjectURL(url);
  };
  return <div className="flex min-w-0 flex-1 flex-col gap-5 overflow-auto p-6">
    <h1 className="text-xl font-medium">Run metrics</h1>
    <p className="text-sm text-muted-foreground-1">Recorded scan, fix, verification and Sentinel runs on this computer. Local checks are separate from code-host CI. Merged share counts unique recorded pull requests per group, using the latest explicit host refresh; it does not measure human approval or fix correctness.</p>
    <div className="flex flex-wrap items-center gap-3">
      <label className="text-sm">Group by <select aria-label="Group metrics by" className="rounded border border-border-1 bg-card p-2" value={by} onChange={event => setBy(event.target.value)}>{["sentinel", "trigger", "week", "model", "command"].map(value => <option key={value} value={value}>{value}</option>)}</select></label>
      <label className="text-sm">Period <select aria-label="Metrics period" className="rounded border border-border-1 bg-card p-2" value={since} onChange={event => setSince(event.target.value)}><option value="7d">Last 7 days</option><option value="4w">Last 4 weeks</option><option value="12w">Last 12 weeks</option></select></label>
      <Button variant="outline" onClick={() => void query.refetch()} disabled={query.isFetching}>Refresh</Button>
      <Button variant="outline" onClick={() => download("csv")} disabled={!query.data}>Export CSV</Button><Button variant="outline" onClick={() => download("json")} disabled={!query.data}>Export JSON</Button>
    </div>
    <div className="flex flex-wrap items-center gap-3">
      <label className="flex items-center gap-2 text-sm">Local checkout on this computer <Input aria-label="Checkout for host receipt refresh" value={checkout} onChange={event => setCheckout(event.target.value)} placeholder="/path/to/checkout" /></label>
      <Button variant="outline" disabled={hostPending || !checkout.trim()} onClick={() => void refreshHost()}>{hostPending ? "Checking host…" : "Refresh host receipts"}</Button>
      <span className="text-xs text-muted-foreground-1">Owner only; up to 20 PRs / 60 seconds. Uses this computer's configured host credentials.</span>
    </div>
    {hostNotice ? <p role="status" className="text-sm text-muted-foreground-1">{hostNotice}</p> : null}
    {query.error ? <ErrorState error={query.error} /> : query.isLoading ? <p role="status">Loading metrics…</p> : !query.data?.rows.length ? <p>No runs recorded in this period.</p> : <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead><tr>{[by, "Runs", "Known cost", "Reported tokens", "Produced findings/fixes", "Local checks passed", "Failed", "Cost/proposed fix", "Merged share", "Code-host CI", "Host last checked"].map(label => <th key={label} className="border-b border-border-1 p-3">{label}</th>)}</tr></thead><tbody>{query.data.rows.map(row => <tr key={row.key}>{[row.key, row.runs, metricTotal(row.costUsd, row.unknownCostRuns, row.runs, true), metricTotal(row.tokens, row.unknownTokenRuns, row.runs), row.proposed, row.checksPassed, row.failed, row.costPerProposedFix === null ? "Unknown" : `$${row.costPerProposedFix.toFixed(4)}`, row.host?.shareMerged == null ? "Unknown" : `${Math.round(row.host.shareMerged * 100)}% (${row.host.merged}/${row.host.pullRequests} PRs)`, row.host?.pullRequests ? `${row.host.ciPassing} passed / ${row.host.ciFailing} failed / ${row.host.ciPending} pending / ${row.host.ciNone} none / ${row.host.ciUnknown} unknown` : "Unknown", row.host?.lastCheckedAt ?? "Not checked"].map((value, index) => <td key={index} className="border-b border-border-1 p-3">{value}</td>)}</tr>)}</tbody></table></div>}
    <p className="text-xs text-muted-foreground-1">Unassigned means the run has no Sentinel or trigger identity. Missing cost and token receipts are excluded from known totals; they are not free runs. Historical runs without recorded PR URLs cannot be associated retrospectively. Counts do not establish detection accuracy.</p>
  </div>;
}
