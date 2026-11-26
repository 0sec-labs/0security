import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { Command } from "commander";
import { reviewPullRequest } from "../bitbucket/review.js";
import { fileState } from "../bitbucket/runner.js";
import { PLATFORMS, createReviewer, splitRepo, type PlatformName } from "../bitbucket/service.js";
import { createWebhookServer, pollOnce, ReviewQueue } from "../bitbucket/watch.js";
import { finishWithError, UsageError } from "./output.js";

interface CommonOptions {
  platform?: string; repo?: string; checkout?: string; url?: string; allowInsecureHttp?: boolean; budget?: string; model?: string;
  maxFiles?: string; maxInline?: string; reportId?: string; state?: string; comments?: boolean; insights?: boolean;
}
interface ReviewFlags extends CommonOptions { pr?: string }
interface WatchFlags extends CommonOptions { interval?: string; listen?: string; once?: boolean; maxReviews?: string }

const REPORT_ID = /^[A-Za-z0-9._-]{1,100}$/;

function positive(name: string, value: string | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  const number = Number(value);
  if (!Number.isInteger(number) || number < 1) throw new UsageError(`${name} must be a whole number of at least 1.`);
  return number;
}

function setup(options: CommonOptions) {
  const name = options.platform ?? "";
  if (!Object.hasOwn(PLATFORMS, name)) throw new UsageError("--platform must be cloud or dc.");
  const platform = PLATFORMS[name as PlatformName];
  if (!splitRepo(options.repo ?? "")) throw new UsageError(`Name the repository with --repo ${platform === "bitbucket-cloud" ? "workspace/repo" : "PROJECT/repo"}.`);
  if (!options.checkout) throw new UsageError("Name a local clone of the repository with --checkout <folder>.");
  const token = (process.env["BITBUCKET_TOKEN"] ?? "").trim();
  if (!token) throw new UsageError("Set BITBUCKET_TOKEN to a token that can read pull requests, write comments and write Code Insights.");
  const url = options.url || process.env["BITBUCKET_URL"] || undefined;
  const reportId = options.reportId ?? "0-security";
  if (!REPORT_ID.test(reportId)) throw new UsageError("--report-id may hold letters, digits, dots, dashes and underscores (at most 100).");
  const reviewer = createReviewer({
    platform: name as PlatformName, repo: options.repo!, checkout: options.checkout, token, baseUrl: url, allowInsecureHttp: options.allowInsecureHttp === true,
    budget: String(options.budget ?? "2"), model: options.model, maxFiles: positive("--max-files", options.maxFiles, 50), maxInline: positive("--max-inline", options.maxInline, 10),
    reportId, comments: options.comments !== false, insights: options.insights !== false,
  });
  const statePath = resolve(options.state ?? join(homedir(), ".0", "bitbucket-review.json"));
  const state = fileState(statePath, {
    read: path => { try { return readFileSync(path, "utf8"); } catch { return undefined; } },
    write: (path, text) => { mkdirSync(dirname(path), { recursive: true }); const temp = `${path}.${process.pid}.tmp`; writeFileSync(temp, text, { mode: 0o600 }); renameSync(temp, path); },
  });
  return { platform, owner: reviewer.owner, repo: reviewer.repo, client: reviewer.client, runner: reviewer.runner, state, review: reviewer.review };
}

const log = (line: string) => process.stderr.write(`${line}\n`);

/** `0 sentinels bitbucket review` and `watch`: review Bitbucket pull requests from your own machine, no hosted service. */
export function registerSentinelsBitbucketCommands(group: Command): void {
  const bitbucket = group.command("bitbucket").description("Review Bitbucket pull requests from this machine (Cloud and Data Center)");
  const common = (command: Command): Command => command
    .requiredOption("--platform <platform>", "cloud or dc (Data Center)")
    .requiredOption("--repo <repo>", "workspace/repo on Cloud, PROJECT/repo on Data Center")
    .requiredOption("--checkout <folder>", "A local clone of the repository; its origin must be the Bitbucket repository")
    .option("--url <url>", "Data Center base URL (default: BITBUCKET_URL)")
    .option("--allow-insecure-http", "Send the token to an http:// URL that is not on this machine (default: refuse)")
    .option("--budget <usd>", "Spend limit for one pull request scan", "2")
    .option("--model <model>", "Model for the scan thread")
    .option("--max-files <n>", "Skip a pull request that changes more files than this", "50")
    .option("--max-inline <n>", "Most inline comments per pull request", "10")
    .option("--report-id <id>", "Code Insights report id", "0-security")
    .option("--state <file>", "File that remembers which commit of each pull request was reviewed (default: ~/.0/bitbucket-review.json)")
    .option("--no-comments", "Publish the Code Insights report only; post no comments")
    .option("--no-insights", "Post comments only; publish no Code Insights report");

  common(bitbucket.command("review").description("Review one pull request now").requiredOption("--pr <number>", "Pull request number"))
    .action(async (options: ReviewFlags) => {
      try {
        const { owner, repo, client, runner, state, review } = setup(options);
        const pr = await client.getPullRequest(owner, repo, positive("--pr", options.pr, 0));
        if (!pr) throw new UsageError("Bitbucket returned a pull request this command cannot read.");
        const outcome = await reviewPullRequest(pr, { client, runner, state }, review);
        process.stdout.write(`${JSON.stringify(outcome)}\n`);
      } catch (error) { finishWithError(error, { err: log }, false); }
    });

  common(bitbucket.command("watch").description("Review pull requests as they open or change: poll, a signed webhook, or both"))
    .option("--interval <seconds>", "Poll every this many seconds (at least 30)", "120")
    .option("--listen <host:port>", "Also accept webhooks here; set BITBUCKET_WEBHOOK_SECRET to the webhook's secret")
    .option("--once", "Poll once, finish the reviews, and exit")
    .option("--max-reviews <n>", "Most pull requests one poll queues", "5")
    .action(async (options: WatchFlags) => {
      try {
        const { platform, owner, repo, client, runner, state, review } = setup(options);
        const interval = positive("--interval", options.interval, 120);
        if (interval < 30) throw new UsageError("--interval must be at least 30 seconds.");
        const limit = positive("--max-reviews", options.maxReviews, 5);
        const queue = new ReviewQueue({ review: pr => reviewPullRequest(pr, { client, runner, state }, review), log });
        const poll = async () => { try { const queued = await pollOnce(client, { owner, repo }, queue, state, limit); log(`poll: ${queued} pull request(s) queued`); } catch (error) { log(`poll failed: ${(error instanceof Error ? error.message : String(error)).slice(0, 300)}`); } };
        if (options.once) { await poll(); await queue.idle(); return; }
        if (options.listen) {
          const secret = (process.env["BITBUCKET_WEBHOOK_SECRET"] ?? "").trim();
          if (secret.length < 16) throw new UsageError("Set BITBUCKET_WEBHOOK_SECRET to the webhook's secret (at least 16 characters).");
          const match = /^(.*):(\d{1,5})$/.exec(options.listen);
          if (!match) throw new UsageError("--listen must look like 127.0.0.1:7777.");
          const host = match[1]!;
          const server = createWebhookServer({ platform, secret, repo: { owner, repo }, queue, log });
          await new Promise<void>((done, fail) => { server.once("error", fail); server.listen(Number(match[2]), host, done); });
          log(`listening for webhooks on ${host}:${match[2]}`);
        }
        await poll();
        setInterval(() => { void poll(); }, interval * 1000);
        await new Promise<void>(() => undefined);
      } catch (error) { finishWithError(error, { err: log }, false); }
    });
}
