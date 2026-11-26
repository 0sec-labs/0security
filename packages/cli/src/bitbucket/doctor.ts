/**
 * `0security sentinels bitbucket doctor`: one command that says whether a Bitbucket Sentinel will work before it fails
 * in the middle of a review. Every check ends as PASS, FAIL or SKIP. A FAIL names the setting or scope to fix.
 *
 * What it sends: reads of the repository, its pull requests and its newest commit; a throw-away Code Insights report named
 * `0-doctor-<random>` that it deletes again (skipped with `readOnly`); and, only when a pull request is named, one marker
 * comment that it deletes again. The token goes only in the Authorization header of the client. Git never sees it.
 */
import { randomBytes } from "node:crypto";
import { statSync } from "node:fs";
import { resolve } from "node:path";
import { enterpriseMode } from "@0/engine";
import { BitbucketClient, BitbucketError, type Http, type Platform } from "./client.js";
import type { CodeInsightsPayload } from "../code-insights.js";
import { defaultExec, type Exec } from "./runner.js";
import { PLATFORMS, splitRepo, type PlatformName } from "./service.js";

export type CheckStatus = "PASS" | "FAIL" | "SKIP";
export interface Check {
  id: string;
  title: string;
  status: CheckStatus;
  detail: string;
  /** What to change, when the check failed. */
  next?: string;
}
export interface DoctorReport { ok: boolean; platform: PlatformName; repo: string; checks: Check[]; next: string }

export interface ModelStatus { configured: boolean; valid: boolean; label?: string | undefined; error?: string | undefined }
export interface DoctorOptions {
  platform: PlatformName;
  repo: string;
  url?: string | undefined;
  checkout?: string | undefined;
  pr?: number | undefined;
  readOnly?: boolean;
  listen?: string | undefined;
  allowInsecureHttp?: boolean;
}
export interface DoctorDeps {
  env?: NodeJS.ProcessEnv;
  http?: Http;
  exec?: Exec;
  /** Reports whether a model provider is configured. Must not call a paid API. */
  modelStatus?: () => Promise<ModelStatus>;
  /** Random suffix source, for tests. */
  suffix?: () => string;
}

const SECRET_VARIABLES = ["BITBUCKET_TOKEN", "BITBUCKET_WEBHOOK_SECRET"];

/** Scope names as Atlassian documents them, by product. Worded as "a token that can ..." so a wrong guess costs little. */
const SCOPES = {
  "bitbucket-cloud": { read: "read pull requests (scope pull requests: read, and repositories: read)", insights: "write Code Insights reports (scope repositories: write)", comment: "write pull request comments (scope pull requests: write)" },
  "bitbucket-dc": { read: "read the repository (Repository read permission)", insights: "write Code Insights reports (Repository write permission)", comment: "comment on pull requests (Repository read permission on the target repository)" },
} as const;

function reasonFor(error: unknown, scope: string): { detail: string; next: string } {
  const message = (error instanceof Error ? error.message : String(error)).split("\n")[0]!.slice(0, 200);
  // The Code Insights sender reports a refusal as plain text rather than a BitbucketError.
  const status = error instanceof BitbucketError ? error.status : Number(/^Bitbucket answered (\d{3}) /.exec(message)?.[1]) || undefined;
  if (status === 401) return { detail: "HTTP 401: Bitbucket does not accept this token (wrong or expired).", next: "Create a new token and set BITBUCKET_TOKEN." };
  if (status === 403) return { detail: `HTTP 403: the token is valid but is not allowed to do this.`, next: `Give the token the permission to ${scope}.` };
  if (status === 404) return { detail: "HTTP 404: this token cannot see that repository, pull request or commit.", next: "Check --repo spelling, and that the token's workspace/project and repository access include it." };
  if (status === 429) return { detail: "HTTP 429: Bitbucket is rate limiting this token.", next: "Wait a minute and run the check again." };
  if (status !== undefined && status >= 500) return { detail: `HTTP ${status}: Bitbucket had a server error.`, next: "Try again; if it persists, check the Bitbucket status page or your server logs." };
  if (status !== undefined) return { detail: `HTTP ${status}: ${message}`, next: `Look at the HTTP ${status} answer above and the token's permissions.` };
  return { detail: message, next: "Check the network path to Bitbucket (--url, proxy, certificates) and the --url value." };
}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

/** `owner/repo` that a git remote URL points at, for https, ssh:// and scp-like remotes on both products. */
export function remoteRepo(remote: string): string | undefined {
  const value = remote.trim();
  let path: string;
  const scp = /^[^/:@\s]+@[^/:\s]+:(?!\/\/)(.+)$/.exec(value);
  if (scp) path = scp[1]!;
  else { try { path = new URL(value).pathname; } catch { return undefined; } }
  const parts = decodeURIComponent(path).replace(/\.git$/i, "").split("/").filter(Boolean);
  return parts.length >= 2 ? `${parts[parts.length - 2]}/${parts[parts.length - 1]}`.toLowerCase() : undefined;
}

export async function runDoctor(options: DoctorOptions, deps: DoctorDeps = {}): Promise<DoctorReport> {
  const env = deps.env ?? process.env;
  const platform: Platform = PLATFORMS[options.platform];
  const scopes = SCOPES[platform];
  const checks: Check[] = [];
  const add = (id: string, title: string, status: CheckStatus, detail: string, next?: string) => { checks.push({ id, title, status, detail, ...(next ? { next } : {}) }); };
  const parts = splitRepo(options.repo);
  if (!parts) throw new Error(`Name the repository as ${platform === "bitbucket-cloud" ? "workspace/repo" : "PROJECT/repo"}.`);
  const { owner, repo } = parts;

  // 1. Token present.
  const token = (env["BITBUCKET_TOKEN"] ?? "").trim();
  if (token) add("token", "BITBUCKET_TOKEN is set", "PASS", `set, ${token.length} chars`);
  else add("token", "BITBUCKET_TOKEN is set", "FAIL", "not set", "Set BITBUCKET_TOKEN to a token that can read pull requests, write comments and write Code Insights.");

  // 9. Restricted egress.
  const restricted = enterpriseMode(env);
  const approved = (env["ZERO_BITBUCKET_URL"] ?? "").trim();
  let blocked = false;
  if (restricted && !approved) {
    blocked = true;
    add("enterprise", "ZERO_ENTERPRISE does not block Bitbucket", "FAIL", "ZERO_ENTERPRISE is set, so every Bitbucket request is refused", "Unset ZERO_ENTERPRISE, or set ZERO_BITBUCKET_URL to the approved Bitbucket server base URL.");
  } else if (restricted) add("enterprise", "ZERO_ENTERPRISE does not block Bitbucket", "PASS", `ZERO_ENTERPRISE is set; requests are allowed only inside ${approved}`);
  else add("enterprise", "ZERO_ENTERPRISE does not block Bitbucket", "PASS", "not set");

  // Server address and client.
  const baseUrl = options.url || env["BITBUCKET_URL"] || undefined;
  let client: BitbucketClient | undefined;
  if (platform === "bitbucket-dc" && !baseUrl) add("server", "Server address is usable", "FAIL", "Data Center needs the server's base URL", "Pass --url https://your-bitbucket-host (or set BITBUCKET_URL).");
  else {
    try {
      client = new BitbucketClient({ platform, token: token || "unset", ...(baseUrl ? { baseUrl } : {}), allowInsecureHttp: options.allowInsecureHttp === true, ...(deps.http ? { http: deps.http } : {}) });
      add("server", "Server address is usable", "PASS", platform === "bitbucket-cloud" ? "Bitbucket Cloud (api.bitbucket.org)" : new URL(baseUrl!).origin);
    } catch (error) { add("server", "Server address is usable", "FAIL", (error as Error).message, "Fix --url (https:// URL with no credentials, query or fragment)."); }
  }

  const online = !!token && !!client && !blocked;
  const skipOffline = (id: string, title: string) => add(id, title, "SKIP", !token ? "needs BITBUCKET_TOKEN" : blocked ? "Bitbucket requests are refused" : "needs a usable server address");

  // 2. Token accepted.
  let reachable = false;
  if (!online) skipOffline("repo", "Token accepted and repository visible");
  else {
    try { const name = await client!.checkRepository(owner, repo); reachable = true; add("repo", "Token accepted and repository visible", "PASS", `HTTP 200, ${name}`); }
    catch (error) { const why = reasonFor(error, scopes.read); add("repo", "Token accepted and repository visible", "FAIL", why.detail, why.next); }
  }
  const afterRepo = (id: string, title: string, run: () => Promise<void>) => reachable ? run() : Promise.resolve(add(id, title, "SKIP", online ? "needs the repository check to pass" : !token ? "needs BITBUCKET_TOKEN" : blocked ? "Bitbucket requests are refused" : "needs a usable server address"));

  // 3. List pull requests.
  await afterRepo("pulls", "Can list pull requests", async () => {
    try { await client!.probePullRequests(owner, repo); add("pulls", "Can list pull requests", "PASS", "HTTP 200"); }
    catch (error) { const why = reasonFor(error, scopes.read); add("pulls", "Can list pull requests", "FAIL", why.detail, why.next); }
  });

  // 4. Code Insights write, then delete.
  await afterRepo("insights", "Can write Code Insights reports", async () => {
    if (options.readOnly) return add("insights", "Can write Code Insights reports", "SKIP", "--read-only was passed; nothing was written");
    let commit: string | undefined;
    try { commit = await client!.latestCommit(owner, repo); }
    catch (error) { const why = reasonFor(error, scopes.read); return add("insights", "Can write Code Insights reports", "FAIL", `could not read the latest commit: ${why.detail}`, why.next); }
    if (!commit) return add("insights", "Can write Code Insights reports", "SKIP", "the repository has no commit to attach a report to");
    const reportId = `0-doctor-${(deps.suffix ?? (() => randomBytes(4).toString("hex")))()}`;
    const cloud = platform === "bitbucket-cloud";
    const payload: CodeInsightsPayload = {
      platform, reportId, batches: [], total: 0, emitted: 0, dropped: 0,
      report: { title: "0 setup check (safe to delete)", details: "Created and deleted by `0security sentinels bitbucket doctor`.", reporter: "0", data: [], result: cloud ? "PASSED" : "PASS", ...(cloud ? { report_type: "SECURITY" } : {}) },
    };
    let written = false;
    let failure: { detail: string; next: string } | undefined;
    try { await client!.publishInsights(payload, { owner, repo, commit }); written = true; }
    catch (error) { failure = reasonFor(error, scopes.insights); }
    let leftover = "";
    try { await client!.deleteInsightsReport({ owner, repo, commit, reportId }); }
    catch (error) { if (!(error instanceof BitbucketError && error.status === 404)) leftover = ` The test report ${reportId} could not be deleted (${reasonFor(error, scopes.insights).detail}); delete it from commit ${commit.slice(0, 12)}.`; }
    if (written) add("insights", "Can write Code Insights reports", "PASS", `created and deleted ${reportId} on ${commit.slice(0, 12)}.${leftover}`);
    else add("insights", "Can write Code Insights reports", "FAIL", `${failure!.detail}${leftover}`, failure!.next);
  });

  // 5. Comment round trip, only when a pull request is named.
  await afterRepo("comment", "Can post and delete a pull request comment", async () => {
    if (options.pr === undefined) return add("comment", "Can post and delete a pull request comment", "SKIP", "pass --pr <id> to test it; nothing was posted");
    const target = { owner, repo, id: options.pr };
    const marker = `0-doctor-${(deps.suffix ?? (() => randomBytes(4).toString("hex")))()}`;
    let posted = false;
    let failure: { detail: string; next: string } | undefined;
    try { await client!.addComment(target, `${marker}: setup check from \`0security sentinels bitbucket doctor\`; this comment is deleted right away.`); posted = true; }
    catch (error) { failure = reasonFor(error, scopes.comment); }
    let cleaned = "";
    try {
      const found = await client!.findComments(target, marker);
      if (posted && !found.length) cleaned = ` The comment was posted but could not be found again to delete; look for ${marker} on pull request ${options.pr}.`;
      for (const comment of found) await client!.deleteComment(target, comment);
    } catch (error) { cleaned = ` The marker comment ${marker} may remain on pull request ${options.pr}: ${reasonFor(error, scopes.comment).detail}`; }
    if (posted && !cleaned) add("comment", "Can post and delete a pull request comment", "PASS", `posted and deleted ${marker} on pull request ${options.pr}`);
    else if (posted) add("comment", "Can post and delete a pull request comment", "FAIL", cleaned.trim(), "Give the token permission to delete its own comments, or remove the marker comment by hand.");
    else add("comment", "Can post and delete a pull request comment", "FAIL", `${failure!.detail}${cleaned}`, failure!.next);
  });

  // 6. Checkout.
  if (!options.checkout) add("checkout", "Local clone matches the repository", "SKIP", "pass --checkout <folder> to check the clone");
  else {
    const dir = resolve(options.checkout);
    const exec = deps.exec ?? defaultExec;
    const clean = Object.fromEntries(Object.entries(env).filter(([name]) => !SECRET_VARIABLES.includes(name)));
    const git = (args: string[], timeoutMs: number) => exec("git", ["-C", dir, ...args], { env: { ...clean, GIT_TERMINAL_PROMPT: "0" }, timeoutMs });
    let isDir = false;
    try { isDir = statSync(dir).isDirectory(); } catch { isDir = false; }
    if (!isDir) add("checkout", "Local clone matches the repository", "FAIL", `${dir} is not a folder`, "Pass --checkout <folder> with a clone of the repository.");
    else {
      try {
        const inside = await git(["rev-parse", "--is-inside-work-tree"], 15_000);
        if (inside.code !== 0 || inside.stdout.trim() !== "true") throw new Error("not a git repository");
        const origin = await git(["remote", "get-url", "origin"], 15_000);
        if (origin.code !== 0) { add("checkout", "Local clone matches the repository", "FAIL", "the clone has no remote named origin", `Run: git -C ${dir} remote add origin <clone URL of ${options.repo}>`); }
        else {
          const found = remoteRepo(origin.stdout);
          const want = `${owner}/${repo}`.toLowerCase();
          if (found !== want) add("checkout", "Local clone matches the repository", "FAIL", `origin points at ${found ?? "an address this check cannot read"}, not ${options.repo}`, `Point origin at ${options.repo}, or pass the clone of that repository.`);
          else if (restricted) add("checkout", "Local clone matches the repository", "PASS", "origin matches; git ls-remote skipped under ZERO_ENTERPRISE (the review checks the transport itself)");
          else {
            const remote = await git(["ls-remote", "--exit-code", "origin", "HEAD"], 30_000);
            if (remote.code === 0) add("checkout", "Local clone matches the repository", "PASS", "origin matches and git ls-remote origin works with your own git credentials");
            else add("checkout", "Local clone matches the repository", "FAIL", `origin matches, but git ls-remote origin failed (exit ${remote.code})`, "Fix your git credentials for origin (SSH key, credential helper); run `git ls-remote origin` in the clone to see git's own message.");
          }
        }
      } catch (error) { add("checkout", "Local clone matches the repository", "FAIL", `${(error as Error).message.split("\n")[0]!.slice(0, 160)}`, `Make ${dir} a git clone of ${options.repo}.`); }
    }
  }

  // 7. Model.
  try {
    const model = await (deps.modelStatus ?? defaultModelStatus)();
    if (model.valid) add("model", "A model provider is configured", "PASS", `${model.label ?? "provider"} (credentials present; no model call made)`);
    else if (model.configured) add("model", "A model provider is configured", "FAIL", `${model.label ?? "provider"}: ${model.error ?? "configuration is not usable"}`.slice(0, 250), "Fix the provider settings, or run `0security models connect`.");
    else add("model", "A model provider is configured", "FAIL", "no model key found", "Set a model key such as OPENAI_API_KEY or ANTHROPIC_API_KEY, or run `0security models connect`.");
  } catch (error) { add("model", "A model provider is configured", "FAIL", (error as Error).message.split("\n")[0]!.slice(0, 200), "Run `0security models connect`."); }

  // 8. Webhook secret and listen address.
  const secret = (env["BITBUCKET_WEBHOOK_SECRET"] ?? "").trim();
  if (secret) {
    if (secret.length >= 16) add("webhook-secret", "Webhook secret is long enough", "PASS", `set, ${secret.length} chars`);
    else add("webhook-secret", "Webhook secret is long enough", "FAIL", `set, only ${secret.length} chars`, "Use a BITBUCKET_WEBHOOK_SECRET of at least 16 characters.");
  } else if (options.listen) add("webhook-secret", "Webhook secret is long enough", "FAIL", "not set, but --listen needs it", "Set BITBUCKET_WEBHOOK_SECRET to a secret of at least 16 characters.");
  else add("webhook-secret", "Webhook secret is long enough", "SKIP", "BITBUCKET_WEBHOOK_SECRET is not set (only needed for watch --listen)");
  if (!options.listen) add("listen", "Listen address is safe", "SKIP", "--listen was not given");
  else {
    const match = /^(.*):(\d{1,5})$/.exec(options.listen);
    if (!match || !match[1] || Number(match[2]) < 1 || Number(match[2]) > 65535) add("listen", "Listen address is safe", "FAIL", `"${options.listen}" is not host:port`, "Use --listen 127.0.0.1:7777.");
    else if (LOOPBACK.has(match[1].toLowerCase())) add("listen", "Listen address is safe", "PASS", `${match[1]} is this machine only; put a TLS proxy in front and point the webhook at it`);
    else add("listen", "Listen address is safe", "PASS", `${match[1]} accepts other machines. Note: the listener speaks plain HTTP, so put a TLS proxy in front, or bind 127.0.0.1`);
  }

  const failed = checks.filter(check => check.status === "FAIL");
  const next = failed.length ? `${failed[0]!.next ?? failed[0]!.detail}${failed.length > 1 ? ` (${failed.length - 1} more failing check${failed.length === 2 ? "" : "s"} above)` : ""}`
    : `Everything required passed. Start it with: 0security sentinels bitbucket watch --platform ${options.platform} --repo ${options.repo}${options.checkout ? ` --checkout ${options.checkout}` : " --checkout <folder>"}${options.url ? ` --url ${options.url}` : ""}`;
  return { ok: failed.length === 0, platform: options.platform, repo: options.repo, checks, next };
}

async function defaultModelStatus(): Promise<ModelStatus> {
  const { getRuntimeAvailability } = await import("../utils.js");
  const { hasApiKey, apiRuntime, availableRuntimes } = await getRuntimeAvailability();
  if (hasApiKey) return { configured: true, valid: true, label: apiRuntime.providerLabel };
  if (!apiRuntime.configured && availableRuntimes.length) return { configured: true, valid: true, label: `local runtime ${availableRuntimes.join(", ")}` };
  return { configured: apiRuntime.configured, valid: false, label: apiRuntime.providerLabel, error: apiRuntime.error };
}

export function renderDoctor(report: DoctorReport): string {
  const width = Math.max(...report.checks.map(check => check.title.length));
  const lines = report.checks.map(check => `${check.status.padEnd(4)}  ${check.title.padEnd(width)}  ${check.detail}`);
  return `${lines.join("\n")}\n\nNext step: ${report.next}`;
}
