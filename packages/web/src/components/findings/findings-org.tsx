import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { localControlFetch } from "@/api";
import { queryKeys } from "@/queries";
import { cn } from "@/lib/utils";
import { EmptyState, LoadingState } from "@/components/state-panel";
import { SeverityIcon } from "./finding-icons";
import { normalizeSeverity, SEVERITY_LABELS } from "./findings-model";
import {
  ageLabel, describeHistory, historyPath, overviewPath, repoFilter, severityShares, sortOrgFindings, triageLabel,
  type OrgFinding, type OrgHistoryRow, type OrgOverview,
} from "./findings-org-model";

async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await localControlFetch(path, { signal });
  if (!response.ok) throw new Error("Could not load the org findings.");
  return response.json() as Promise<T>;
}

/** The shared findings server's overview; `available` is false without an enterprise license. */
export function useOrgOverview(repo: string | null = null, enabled = true) {
  return useQuery({ queryKey: queryKeys.findingsOrg(repo), enabled, queryFn: ({ signal }) => getJson<OrgOverview>(overviewPath(repo), signal), staleTime: 15_000, retry: false });
}

const tabClass = "inline-flex h-7 items-center rounded-md px-2 text-xs font-medium whitespace-nowrap text-muted-foreground-1 transition-colors duration-100 outline-none hover:text-foreground focus-visible:outline-ring-inset data-[selected]:bg-secondary data-[selected]:text-foreground";

/** Findings | Org. Shown only when the server has the shared findings server, so the plain page looks as it always did. */
export function FindingsViewTabs({ current }: { current: "findings" | "org" }) {
  const overview = useOrgOverview(null, current === "findings");
  const [params] = useSearchParams();
  const available = current === "org" || (overview.data?.available ?? false);
  if (!available) return null;
  const org = new URLSearchParams(params); org.set("view", "org");
  return (
    <div role="tablist" aria-label="Findings view" className="flex items-center gap-1 px-3 pt-2">
      <Link role="tab" aria-selected={current === "findings"} data-selected={current === "findings" ? "" : undefined} className={tabClass} to="/findings">Findings</Link>
      <Link role="tab" aria-selected={current === "org"} data-selected={current === "org" ? "" : undefined} className={tabClass} to={`/findings?${org.toString()}`}>Org</Link>
    </div>
  );
}

const SEVERITY_BAR: Record<string, string> = {
  critical: "bg-destructive", high: "bg-warning-foreground", medium: "bg-warning-foreground/45", low: "bg-muted-foreground-1", info: "bg-muted-foreground-2",
};

const SEVERITY_FILL: Record<string, string> = {
  critical: "fill-destructive", high: "fill-warning-foreground", medium: "fill-warning-foreground/45", low: "fill-muted-foreground-1", info: "fill-muted-foreground-2",
};

function Tile({ label, value, hint }: { label: string; value: number; hint?: string }) {
  return (
    <div className="min-w-0 rounded-[var(--radius-panel,12px)] border-[0.5px] border-border-1 bg-card px-4 py-3">
      <div className="text-xs text-muted-foreground-1">{label}</div>
      <div className="mt-1 text-2xl/8 font-medium tabular-nums text-foreground">{value}</div>
      {hint ? <div className="text-xs text-muted-foreground-2">{hint}</div> : null}
    </div>
  );
}

function SeverityBar({ bySeverity }: { bySeverity: Record<string, number> }) {
  const shares = severityShares(bySeverity);
  const total = shares.reduce((sum, item) => sum + item.count, 0);
  return (
    <div className="min-w-0 rounded-[var(--radius-panel,12px)] border-[0.5px] border-border-1 bg-card px-4 py-3 sm:col-span-2">
      <div className="text-xs text-muted-foreground-1">By severity</div>
      <svg role="img" aria-label={shares.map(item => `${item.count} ${item.label}`).join(", ")} viewBox="0 0 100 2" preserveAspectRatio="none" className="mt-2 block h-2 w-full overflow-hidden rounded-full bg-secondary">
        {(() => {
          let offset = 0;
          return total === 0 ? null : shares.filter(item => item.count > 0).map(item => {
            const width = (item.count / total) * 100;
            const rect = <rect key={item.severity} x={offset} y="0" width={width} height="2" className={SEVERITY_FILL[item.severity]} />;
            offset += width;
            return rect;
          });
        })()}
      </svg>
      <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground-1">
        {shares.map(item => <li key={item.severity} className="flex items-center gap-1.5"><span aria-hidden="true" className={cn("size-2 rounded-full", SEVERITY_BAR[item.severity])} />{item.label} <span className="tabular-nums text-foreground">{item.count}</span></li>)}
      </ul>
    </div>
  );
}

const th = "px-3 py-2 text-left text-xs font-medium text-muted-foreground-1";
const td = "px-3 py-2 text-sm";

function HistoryPanel({ finding, onClose }: { finding: OrgFinding; onClose: () => void }) {
  const history = useQuery({ queryKey: queryKeys.findingsOrgHistory(finding.fingerprint), queryFn: ({ signal }) => getJson<{ history: OrgHistoryRow[] }>(historyPath(finding.fingerprint), signal), retry: false });
  return (
    <aside aria-label="Finding history" className="min-w-0 rounded-[var(--radius-panel,12px)] border-[0.5px] border-border-1 bg-card p-4" data-testid="org-history">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="break-words text-sm font-medium text-foreground">{finding.title}</h3>
          <p className="mt-0.5 text-xs text-muted-foreground-2">{finding.repo}{finding.source ? ` · ${finding.source}` : ""}</p>
        </div>
        <button type="button" onClick={onClose} className="rounded-md px-1.5 text-xs text-muted-foreground-1 outline-none hover:text-foreground focus-visible:outline-ring-inset">Close</button>
      </div>
      <h4 className="mt-4 text-xs font-medium text-muted-foreground-1">History</h4>
      {history.isPending ? <p className="mt-2 text-sm text-muted-foreground-2">Loading…</p>
        : history.error ? <p className="mt-2 text-sm text-destructive">Could not load the history.</p>
        : history.data!.history.length === 0 ? <p className="mt-2 text-sm text-muted-foreground-2">No history yet.</p>
        : <ol className="mt-2 space-y-3 border-l-[0.5px] border-border-2 pl-4">
          {[...history.data!.history].reverse().map(row => (
            <li key={row.id} className="relative">
              <span aria-hidden="true" className="absolute top-1.5 -left-[21px] size-2 rounded-full bg-muted-foreground-2" />
              <div className="text-sm text-foreground">{describeHistory(row)}</div>
              <div className="text-xs text-muted-foreground-2"><time dateTime={row.ts}>{new Date(row.ts).toLocaleString()}</time>{row.prevState && row.newState && row.prevState !== row.newState ? ` · ${triageLabel(row.prevState)} to ${triageLabel(row.newState)}` : ""}</div>
              {row.reason ? <p className="mt-1 break-words rounded-md bg-secondary px-2 py-1 text-xs text-foreground">Reason: {row.reason}</p> : null}
              {row.expiresAt ? <p className="mt-1 text-xs text-muted-foreground-2">Expires {new Date(row.expiresAt).toLocaleDateString()}</p> : null}
            </li>
          ))}
        </ol>}
      <Link to={`/findings/${encodeURIComponent(finding.fingerprint)}`} className="mt-4 inline-block text-xs text-foreground underline underline-offset-2">Open the finding</Link>
    </aside>
  );
}

/** Findings across repositories: counts by severity, status and repository, the findings themselves, and the history of one. */
export function FindingsOrg() {
  const [params, setParams] = useSearchParams();
  const requested = params.get("repo");
  const overview = useOrgOverview(requested);
  const [openFingerprint, setOpenFingerprint] = useState<string | null>(null);
  const data = overview.data;
  const repos = data?.available ? data.repos : [];
  const repo = repoFilter(requested, repos);
  const chooseRepo = (value: string | null) => setParams(current => { const next = new URLSearchParams(current); if (value) next.set("repo", value); else next.delete("repo"); return next; }, { replace: true });

  let body;
  if (overview.isPending) body = <LoadingState label="Loading org findings" />;
  else if (overview.error || !data) body = <EmptyState variant="fill" title="Could not load the org findings" body="Try again in a moment." />;
  else if (!data.available) body = <EmptyState variant="fill" title="Org findings need an enterprise license" body={data.message} />;
  else if (data.summary.total === 0 && !repo) body = <EmptyState variant="fill" title="No findings have been sent yet" body={<>Send results from a CI job with <code className="font-mono">0security findings upload scan.sarif --to https://your-server</code>.</>} />;
  else {
    const { summary } = data;
    const rows = sortOrgFindings(data.findings);
    const open = rows.find(row => row.fingerprint === openFingerprint) ?? null;
    body = (
      <div className="space-y-5 px-3 pt-3 pb-10">
        <div className="flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-muted-foreground-1">Repository
            <select aria-label="Repository" value={repo ?? ""} onChange={event => chooseRepo(event.target.value || null)} className="h-7 rounded-md border-[0.5px] border-border-1 bg-background px-2 text-xs text-foreground outline-none focus-visible:outline-ring-inset">
              <option value="">All repositories</option>
              {repos.map(name => <option key={name} value={name}>{name}</option>)}
            </select>
          </label>
          <span className="text-xs text-muted-foreground-2">{summary.total} finding{summary.total === 1 ? "" : "s"}{repo ? ` in ${repo}` : ` in ${summary.byRepo.length} ${summary.byRepo.length === 1 ? "repository" : "repositories"}`}</span>
        </div>
        <div className="grid gap-3 sm:grid-cols-4" data-testid="org-tiles">
          <Tile label="Open" value={summary.open} hint="Not suppressed" />
          <Tile label="Suppressed" value={summary.byStatus.suppressed ?? 0} />
          <SeverityBar bySeverity={summary.bySeverity} />
        </div>

        <section aria-labelledby="org-repos">
          <h2 id="org-repos" className="px-3 pb-1 text-xs font-medium text-muted-foreground-1">Repositories</h2>
          <div className="overflow-x-auto rounded-[var(--radius-panel,12px)] border-[0.5px] border-border-1">
            <table className="w-full min-w-[32rem] border-collapse">
              <thead><tr className="border-b-[0.5px] border-border-1"><th className={th}>Repository</th><th className={cn(th, "text-right")}>Open</th>{(["critical", "high", "medium", "low"] as const).map(level => <th key={level} className={cn(th, "text-right")}>{SEVERITY_LABELS[level]}</th>)}</tr></thead>
              <tbody>
                {summary.byRepo.map(item => (
                  <tr key={item.repo} className="border-b-[0.5px] border-border-1 last:border-b-0">
                    <td className={td}><button type="button" onClick={() => chooseRepo(item.repo)} className="font-mono text-[13px] text-foreground outline-none hover:underline focus-visible:outline-ring-inset">{item.repo}</button></td>
                    <td className={cn(td, "text-right tabular-nums")}>{item.open}</td>
                    {(["critical", "high", "medium", "low"] as const).map(level => <td key={level} className={cn(td, "text-right tabular-nums", (item.bySeverity[level] ?? 0) === 0 && "text-muted-foreground-2")}>{item.bySeverity[level] ?? 0}</td>)}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <div className={cn("grid gap-4", open && "lg:grid-cols-[minmax(0,1fr)_22rem]")}>
          <section aria-labelledby="org-findings" className="min-w-0">
            <h2 id="org-findings" className="px-3 pb-1 text-xs font-medium text-muted-foreground-1">Findings{data.truncated ? " (first 500)" : ""}</h2>
            <div className="overflow-x-auto rounded-[var(--radius-panel,12px)] border-[0.5px] border-border-1">
              <table className="w-full min-w-[40rem] border-collapse" data-testid="org-findings">
                <thead><tr className="border-b-[0.5px] border-border-1"><th className={th}>Finding</th><th className={th}>Repository</th><th className={th}>Source</th><th className={th}>Status</th><th className={th}>Last seen</th></tr></thead>
                <tbody>
                  {rows.map(row => (
                    <tr key={row.fingerprint} data-selected={row.fingerprint === openFingerprint ? "" : undefined} className="border-b-[0.5px] border-border-1 last:border-b-0 data-[selected]:bg-secondary">
                      <td className={cn(td, "max-w-[22rem]")}>
                        <button type="button" onClick={() => setOpenFingerprint(row.fingerprint === openFingerprint ? null : row.fingerprint)} aria-expanded={row.fingerprint === openFingerprint} className="flex w-full min-w-0 items-center gap-2 text-left outline-none hover:underline focus-visible:outline-ring-inset">
                          <SeverityIcon severity={normalizeSeverity(row.severity)} /><span className="min-w-0 truncate">{row.title}</span>
                        </button>
                      </td>
                      <td className={cn(td, "font-mono text-[13px] text-muted-foreground-1")}>{row.repo}</td>
                      <td className={cn(td, "text-muted-foreground-1")}>{row.source ?? "—"}</td>
                      <td className={td}>{triageLabel(row.triageStatus)}</td>
                      <td className={cn(td, "whitespace-nowrap text-muted-foreground-1")}>{ageLabel(row.lastSeen)}</td>
                    </tr>
                  ))}
                  {rows.length === 0 ? <tr><td className={cn(td, "text-muted-foreground-2")} colSpan={5}>No findings in this repository.</td></tr> : null}
                </tbody>
              </table>
            </div>
          </section>
          {open ? <HistoryPanel key={open.fingerprint} finding={open} onClose={() => setOpenFingerprint(null)} /> : null}
        </div>

        <section aria-labelledby="org-suppressions">
          <h2 id="org-suppressions" className="px-3 pb-1 text-xs font-medium text-muted-foreground-1">Suppressions</h2>
          {summary.suppressions.length === 0 ? <p className="px-3 text-sm text-muted-foreground-2">Nothing is suppressed.</p> : (
            <ul className="divide-y-[0.5px] divide-border-1 rounded-[var(--radius-panel,12px)] border-[0.5px] border-border-1">
              {summary.suppressions.map(item => (
                <li key={item.fingerprint} className="px-3 py-2">
                  <div className="flex items-center gap-2 text-sm"><SeverityIcon severity={normalizeSeverity(item.severity)} /><span className="min-w-0 truncate">{item.title}</span><span className="shrink-0 font-mono text-xs text-muted-foreground-2">{item.repo}</span></div>
                  <p className="mt-0.5 break-words text-xs text-muted-foreground-1">{item.reason ? `Reason: ${item.reason}` : "No reason recorded."}{item.expiresAt ? ` Expires ${new Date(item.expiresAt).toLocaleDateString()}.` : ""}</p>
                </li>
              ))}
            </ul>
          )}
        </section>
        {data.canWrite ? null : <p className="px-3 text-xs text-muted-foreground-2">Your enterprise license has expired. This data stays readable and exportable. New uploads and suppression history resume when you renew.</p>}
      </div>
    );
  }
  return (
    <div className="flex min-h-0 min-w-0 flex-1 flex-col" data-testid="findings-org">
      <FindingsViewTabs current="org" />
      <div className="min-h-0 flex-1 overflow-y-auto">{body}</div>
    </div>
  );
}
