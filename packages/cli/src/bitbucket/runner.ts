import { metricIdentityEnv, type MetricIdentity } from "../run-metrics.js";
/**
 * Scans a pull request from a local clone the operator names. The pull request's commit is fetched into a temporary git
 * worktree, so the operator's own checkout is never changed, and `0security scan --diff` runs there. Nothing from the pull
 * request is read as configuration: only the operator's flags decide how the scan runs.
 *
 * The scan reads code written by the pull request's author. It runs with the environment of this process minus the
 * Bitbucket token and the webhook secret, so run it on a machine that holds nothing else you cannot lose.
 */
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, rmdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { UNTRUSTED_GIT_BASE_CONFIG, assertEgressAllowed, enterpriseMode, untrustedGitActionConfig } from "@0/engine";
import { isSafeGitRef } from "@0/engine/shared";
import { assertBitbucketDestination, type PullRequest } from "./client.js";
import type { ReviewRunner, ScanResult } from "./review.js";

const run = promisify(execFile);
const SECRET_VARIABLES = ["BITBUCKET_TOKEN", "BITBUCKET_WEBHOOK_SECRET"];
const SHA = /^[0-9a-f]{40}$/;

export type Exec = (file: string, args: string[], options: { cwd?: string; env: NodeJS.ProcessEnv; timeoutMs: number }) => Promise<{ stdout: string; code: number }>;

export const defaultExec: Exec = async (file, args, options) => {
  try {
    const { stdout } = await run(file, args, { ...(options.cwd ? { cwd: options.cwd } : {}), env: options.env, timeout: options.timeoutMs, maxBuffer: 16 * 1024 * 1024 });
    return { stdout, code: 0 };
  } catch (error) {
    const failure = error as { code?: unknown; stdout?: unknown; killed?: boolean; message?: string };
    if (typeof failure.code === "number") return { stdout: typeof failure.stdout === "string" ? failure.stdout : "", code: failure.code };
    throw new Error(`${file} could not run: ${(failure.message ?? String(error)).split("\n")[0]}`);
  }
};

export interface RunnerOptions {
  metricIdentity?: MetricIdentity;
  /** A local clone of the repository; `origin` must be the Bitbucket repository. */
  checkout: string;
  /** Command that starts 0, for example `["0security"]`. Default: this program. */
  scanCommand?: string[];
  /** Spend limit for one scan, in USD. */
  budget?: string;
  model?: string;
  providerId?: string; reasoning?: string;
  exec?: Exec;
  /** Environment variables to hide from the scan in addition to the default Bitbucket ones, for example the variable a trigger names for its token. */
  secretVariables?: string[];
  /** Time limit for the scan, default 30 minutes. */
  scanTimeoutMs?: number;
}

/** Refs that hold a pull request's head, by product. */
export function headRefspec(pr: PullRequest): string {
  if (pr.platform === "bitbucket-dc") return `+refs/pull-requests/${pr.id}/from:refs/0/pr/${pr.id}`;
  return `+refs/heads/${pr.headBranch}:refs/0/pr/${pr.id}`;
}

export function gitScanRunner(options: RunnerOptions): ReviewRunner {
  const exec = options.exec ?? defaultExec;
  const command = options.scanCommand ?? [process.execPath, process.argv[1] ?? "0security"];
  /** The environment as it is when a scan starts, without the secrets. */
  const hidden = [...SECRET_VARIABLES, ...(options.secretVariables ?? [])];
  const cleanEnv = () => Object.fromEntries(Object.entries(process.env).filter(([name]) => !hidden.includes(name)));
  const git = async (args: string[], timeoutMs = 120_000) => {
    const result = await exec("git", ["-C", options.checkout, ...untrustedGitActionConfig(options.checkout), ...args], { env: cleanEnv(), timeoutMs });
    if (result.code !== 0) throw new Error(`git ${args[0]} failed (exit ${result.code}).`);
    return result.stdout;
  };

  return {
    async scan(pr: PullRequest): Promise<ScanResult> {
      if (!isSafeGitRef(pr.baseBranch, { maxLength: 200 }) || !isSafeGitRef(pr.headBranch, { maxLength: 200 })) throw new Error("The pull request's branch name is not one 0 will pass to git.");
      if (enterpriseMode()) {
        // get-url expands insteadOf, but fetch would expand it again. Reject rewrites rather than trusting a
        // second expansion, helper transport, remote helper or a checkout-controlled alternate destination.
        const rewrites = await exec("git", ["-C", options.checkout, ...UNTRUSTED_GIT_BASE_CONFIG, "config", "--get-regexp", "^url\\..*\\.(insteadof|pushinsteadof)$"], { env: cleanEnv(), timeoutMs: 10_000 });
        if (rewrites.code !== 1 || rewrites.stdout.trim()) throw new Error("Restricted-egress Bitbucket refuses git URL rewrites; use the approved HTTPS origin directly.");
        const remote = (await git(["remote", "get-url", "origin"])).trim();
        assertBitbucketDestination(remote);
        const url = new URL(remote);
        const base = new URL(process.env["ZERO_BITBUCKET_URL"]!);
        const prefix = base.pathname.replace(/\/+$/, "");
        const expected = pr.platform === "bitbucket-dc" ? `${prefix}/scm/${pr.owner}/${pr.repo}` : `${prefix}/${pr.owner}/${pr.repo}`;
        if (url.pathname.replace(/\.git$/, "").toLowerCase() !== expected.toLowerCase()) throw new Error("The git origin does not match the Bitbucket pull request repository.");
      } else assertEgressAllowed("Bitbucket (git remote)");
      await git([...(enterpriseMode() ? ["-c", "http.followRedirects=false", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "protocol.http.allow=always"] : []), "fetch", "--no-tags", "origin", `+refs/heads/${pr.baseBranch}:refs/remotes/origin/${pr.baseBranch}`, headRefspec(pr)], 300_000);
      const sha = (await git(["rev-parse", "--verify", `refs/0/pr/${pr.id}^{commit}`])).trim();
      if (!SHA.test(sha)) throw new Error("git did not return a commit.");
      if (!sha.startsWith(pr.headSha)) {
        await git(["update-ref", "-d", `refs/0/pr/${pr.id}`]);
        throw new Error("The fetched commit no longer matches the reviewed Bitbucket head; retry the review.");
      }
      const parent = mkdtempSync(join(tmpdir(), "0-bitbucket-"));
      const tree = join(parent, "tree");
      const out = join(parent, "scan.json");
      try {
        await git(["worktree", "add", "--detach", tree, sha]);
        const args = [...command.slice(1), "scan", tree, "--diff", `origin/${pr.baseBranch}`, "--format", "json", "-o", out, "--budget", options.budget ?? "2", ...(options.model ? ["--model", options.model] : []), ...(options.providerId ? ["--provider", options.providerId] : []), ...(options.reasoning ? ["--reasoning", options.reasoning] : [])];
        const scan = await exec(command[0]!, args, { env: { ...cleanEnv(), ...metricIdentityEnv(options.metricIdentity ?? {}) }, timeoutMs: options.scanTimeoutMs ?? 30 * 60_000 });
        if (scan.code !== 0 && scan.code !== 1 && scan.code !== 3) throw new Error(`The scan failed (exit ${scan.code}).`);
        let json: string;
        try { json = readFileSync(out, "utf8"); } catch { throw new Error("The scan wrote no report."); }
        return { sha, json, exitCode: scan.code };
      } finally {
        await git(["worktree", "remove", "--force", tree]).catch(() => undefined);
        await git(["update-ref", "-d", `refs/0/pr/${pr.id}`]).catch(() => undefined);
        try { rmdirSync(parent); } catch { /* The scan left files behind; the system temp folder cleans them. */ }
      }
    },
  };
}

export function fileState(path: string, io: { read(path: string): string | undefined; write(path: string, text: string): void }): { get(key: string): string | undefined; set(key: string, sha: string): void } {
  let data: Record<string, string> = {};
  try { const raw = io.read(path); if (raw) { const parsed: unknown = JSON.parse(raw); if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) data = Object.fromEntries(Object.entries(parsed).filter((entry): entry is [string, string] => typeof entry[1] === "string")); } } catch { data = {}; }
  return { get: key => data[key], set(key, sha) { data[key] = sha; io.write(path, JSON.stringify(data, null, 1)); } };
}
