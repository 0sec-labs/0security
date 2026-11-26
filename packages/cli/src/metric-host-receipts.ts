import { execFile } from "node:child_process";
import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, renameSync, statSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { promisify } from "node:util";
import { homeStateDir } from "@0/engine/shared";
import { assertEgressAllowed } from "@0/engine";
import { selectFixHost } from "./host/fix-host.js";
import type { Host } from "./host/index.js";
import type { RunMetric } from "./run-metrics.js";
import { metricPullRequest, metricRepositoryFromOrigin } from "./metric-pr.js";

const exec = promisify(execFile);
const MAX_BYTES = 1024 * 1024;
export interface MetricHostObservation {
  version: 1; checkedAt: string; pullRequestUrl: string; repositoryId: string;
  state: "open" | "merged" | "closed" | "unknown";
  ci: "passing" | "failing" | "pending" | "none" | "unknown";
}
export function sanitizeHostObservation(raw: unknown): MetricHostObservation | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const r = raw as Record<string, unknown>; const identity = metricPullRequest(r.pullRequestUrl);
  if (!identity || typeof r.checkedAt !== "string" || !Number.isFinite(Date.parse(r.checkedAt))) return undefined;
  return { version: 1, ...identity, checkedAt: new Date(r.checkedAt).toISOString(), state: ["open", "merged", "closed"].includes(String(r.state)) ? r.state as MetricHostObservation["state"] : "unknown", ci: ["passing", "failing", "pending", "none"].includes(String(r.ci)) ? r.ci as MetricHostObservation["ci"] : "unknown" };
}
const ledgerPath = (home?: string) => join(homeStateDir(home), "metrics-host-observations.ndjson");
export function appendHostObservation(record: MetricHostObservation, home?: string): void {
  const clean = sanitizeHostObservation(record); if (!clean) throw new Error("Invalid host observation.");
  const path = ledgerPath(home); mkdirSync(join(path, ".."), { recursive: true, mode: 0o700 });
  if (existsSync(path) && statSync(path).size >= MAX_BYTES) renameSync(path, `${path}.1`);
  appendFileSync(path, `${JSON.stringify(clean)}\n`, { mode: 0o600 }); chmodSync(path, 0o600);
}
export function readHostObservations(home?: string): MetricHostObservation[] {
  const path = ledgerPath(home); const rows: MetricHostObservation[] = [];
  for (const file of [`${path}.1`, path]) {
    let text: string; try { text = readFileSync(file, "utf8"); } catch { continue; }
    for (const line of text.split("\n")) { try { const row = sanitizeHostObservation(JSON.parse(line)); if (row) rows.push(row); } catch { /* torn line */ } }
  }
  return rows;
}
export interface HostReceiptSummary {
  pullRequests: number; merged: number; closed: number; open: number; unknown: number; shareMerged: number | null;
  ciPassing: number; ciFailing: number; ciPending: number; ciNone: number; ciUnknown: number;
  lastCheckedAt: string | null; unlinkedFixRuns: number;
}
/** A repeated update counts once per PR in each selected workflow. Unknown observations never become rejections. */
export function summarizeHostReceipts(records: RunMetric[], observations: MetricHostObservation[]): HostReceiptSummary {
  const fixes = records.filter(row => row.command === "fix");
  const urls = new Set(fixes.flatMap(row => row.pullRequestUrl ? [row.pullRequestUrl] : []));
  const latest = new Map<string, MetricHostObservation>();
  for (const row of observations) if (!latest.has(row.pullRequestUrl) || row.checkedAt >= latest.get(row.pullRequestUrl)!.checkedAt) latest.set(row.pullRequestUrl, row);
  const out: HostReceiptSummary = { pullRequests: urls.size, merged: 0, closed: 0, open: 0, unknown: 0, shareMerged: null, ciPassing: 0, ciFailing: 0, ciPending: 0, ciNone: 0, ciUnknown: 0, lastCheckedAt: null, unlinkedFixRuns: fixes.filter(row => !row.pullRequestUrl && (row.findingsProposed ?? 0) > 0).length };
  for (const url of urls) {
    const row = latest.get(url); out[row?.state ?? "unknown"]++;
    const key = ({ passing: "ciPassing", failing: "ciFailing", pending: "ciPending", none: "ciNone", unknown: "ciUnknown" } as const)[row?.ci ?? "unknown"]; out[key]++;
    if (row && (!out.lastCheckedAt || row.checkedAt > out.lastCheckedAt)) out.lastCheckedAt = row.checkedAt;
  }
  out.shareMerged = urls.size > 0 && out.unknown === 0 ? out.merged / urls.size : null;
  return out;
}
export interface RefreshHostDeps {
  origin(checkout: string): Promise<string>;
  host(checkout: string, signal: AbortSignal, bitbucketUrl?: string): Promise<Pick<Host, "pullRequestState" | "pullRequestChecks">>;
  append(record: MetricHostObservation): void;
  now(): number;
  observations?(): MetricHostObservation[];
}
const gitEnv = { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_OPTIONAL_LOCKS: "0" };
const git = async (checkout: string, args: string[]) => (await exec("git", ["-C", checkout, "-c", "core.fsmonitor=false", ...args], { timeout: 5_000, maxBuffer: 200_000, encoding: "utf8", env: gitEnv })).stdout;
const defaults: RefreshHostDeps = {
  origin: checkout => git(checkout, ["remote", "get-url", "origin"]),
  host: (checkout, signal, bitbucketUrl) => selectFixHost({ bitbucketUrl, git: args => git(checkout, args), run: async args => {
    assertEgressAllowed("Code-host metrics refresh (gh)");
    return (await exec("gh", args, { cwd: checkout, timeout: 5_000, maxBuffer: 200_000, encoding: "utf8", env: gitEnv, signal })).stdout;
  }, fetch: (url, init) => fetch(url, { ...init, signal: init?.signal ? AbortSignal.any([signal, init.signal]) : signal }) }),
  append: record => appendHostObservation(record), observations: () => readHostObservations(), now: Date.now,
};
/** Explicit read-only refresh. No checkout paths enter returned data or either metrics ledger. */
export async function refreshMetricHostReceipts(records: RunMetric[], checkout: string, options: { bitbucketUrl?: string } = {}, deps: RefreshHostDeps = defaults): Promise<{ checked: number; remaining: number; unavailable: number }> {
  const signal = AbortSignal.timeout(60_000); const deadline = deps.now() + 60_000;
  if (!isAbsolute(checkout)) throw new Error("Provide an absolute local checkout with --repo.");
  const repositoryId = metricRepositoryFromOrigin((await deps.origin(checkout)).trim(), options.bitbucketUrl ?? process.env.BITBUCKET_URL);
  if (!repositoryId) throw new Error("Cannot identify the checkout's supported code-host origin.");
  const urls = [...new Set(records.filter(row => row.command === "fix" && row.repositoryId === repositoryId).flatMap(row => row.pullRequestUrl ? [row.pullRequestUrl] : []))];
  const lastChecked = new Map<string, string>();
  for (const row of deps.observations?.() ?? []) if ((lastChecked.get(row.pullRequestUrl) ?? "") < row.checkedAt) lastChecked.set(row.pullRequestUrl, row.checkedAt);
  // Repeated bounded refreshes advance through unobserved/oldest observations instead of starving later PRs.
  urls.sort((a, b) => (lastChecked.get(a) ?? "").localeCompare(lastChecked.get(b) ?? "") || a.localeCompare(b));
  const selected = urls.slice(0, 20);
  const bounded = async <T>(work: Promise<T>): Promise<T> => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try { return await Promise.race([work, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("Host refresh deadline reached")), Math.max(1, deadline - deps.now())); timer.unref?.(); })]); }
    finally { clearTimeout(timer); }
  };
  let host: Pick<Host, "pullRequestState" | "pullRequestChecks"> | undefined; try { host = await bounded(deps.host(checkout, signal, options.bitbucketUrl)); } catch { /* No credentials or unavailable: write unknown observations. */ }
  let unavailable = 0;
  for (const url of selected) {
    let state: MetricHostObservation["state"] = "unknown"; let ci: MetricHostObservation["ci"] = "unknown";
    if (host && !signal.aborted && deps.now() < deadline) {
      try {
        const results = await bounded(Promise.allSettled([host.pullRequestState(url), host.pullRequestChecks?.(url)]));
        if (results[0].status === "fulfilled") state = results[0].value.state;
        if (results[1].status === "fulfilled" && results[1].value) ci = results[1].value.status;
      } catch { /* Deadline: never infer rejection or acceptance. */ }
    }
    if (state === "unknown" || ci === "unknown") unavailable++;
    deps.append({ version: 1, checkedAt: new Date(deps.now()).toISOString(), pullRequestUrl: url, repositoryId, state, ci });
  }
  return { checked: selected.length, remaining: Math.max(0, urls.length - selected.length), unavailable };
}
