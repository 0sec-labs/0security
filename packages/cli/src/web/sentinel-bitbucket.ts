/**
 * The `bitbucket-pr` Sentinel trigger. It reviews Bitbucket pull requests with the same code `0security sentinels bitbucket review`
 * uses (scan the changed files, publish Code Insights, keep one summary comment and a few inline comments), and writes each
 * result as one activation on the Sentinel. It does not start a model turn of its own: the scan has its own spend limit.
 *
 * A pull request reaches it two ways: a poll of the open pull requests, or a signed webhook delivery that names one pull request.
 * Both go through `runBitbucketTrigger`, so draft, fork, size and replay rules are the same.
 * The token is read from the environment variable the trigger names. It is never stored and never logged.
 */
import { assertEgressAllowed } from "@0/engine";
import type { SentinelStore } from "@0/engine/storage";
import type { Sentinel, SentinelActivation, SentinelBitbucketPrConfig, SentinelTrigger } from "@0/engine/shared";
import type { PullRequest } from "../bitbucket/client.js";
import { reviewPullRequest, type ReviewOutcome } from "../bitbucket/review.js";
import { createReviewer, type Reviewer, type ReviewerSettings } from "../bitbucket/service.js";
import { describeOutcome } from "../bitbucket/watch.js";
import { oneLine } from "./pr-review.js";

/** Reviews one poll starts. The rest wait for the next poll. */
export const MAX_BITBUCKET_REVIEWS_PER_POLL = 3;
/** The trigger cursor keeps 200 entries; a poll with more open pull requests could not be remembered. */
const MAX_POLLED = 190;

export interface DeliveredPullRequest { pr: PullRequest; event: "opened" | "updated" }

export interface BitbucketRunDeps {
  store: SentinelStore;
  sentinel: Sentinel;
  trigger: SentinelTrigger;
  automationId: string;
  via: "poll" | "check" | "webhook";
  now: () => number;
  isEnabled: () => boolean;
  env?: NodeJS.ProcessEnv;
  /** Test seam; the default builds the real client and scan runner. */
  reviewer?: (settings: ReviewerSettings) => Reviewer;
}
export interface BitbucketRunResult { cursor?: Record<string, string>; lastStatus: string; lastError?: string }

const message = (error: unknown) => (error instanceof Error ? error.message : String(error)).split("\n")[0]!.slice(0, 400);
const isoAt = (ms: number) => new Date(ms).toISOString();
const sameCommit = (a: string, b: string) => a.slice(0, 12) === b.slice(0, 12);

export function reviewerSettings(config: SentinelBitbucketPrConfig, token: string): ReviewerSettings {
  return {
    platform: config.platform, repo: config.repo, checkout: config.checkout, token, baseUrl: config.baseUrl, allowInsecureHttp: config.allowInsecureHttp,
    budget: String(config.budgetUsd), model: config.model, maxFiles: config.maxFiles, maxInline: config.maxInline, reportId: config.reportId,
    comments: config.comments, insights: config.insights, secretVariables: [config.tokenEnv],
  };
}

export async function runBitbucketTrigger(deps: BitbucketRunDeps, delivered?: DeliveredPullRequest): Promise<BitbucketRunResult> {
  const config = deps.trigger.bitbucket;
  if (!config) return { lastStatus: "blocked", lastError: "The trigger has no Bitbucket settings." };
  const token = ((deps.env ?? process.env)[config.tokenEnv] ?? "").trim();
  if (!token) return { lastStatus: "blocked", lastError: `Set ${config.tokenEnv} on the machine that runs 0 to a token that can read pull requests, write comments and write Code Insights.` };
  let reviewer: Reviewer;
  try {
    assertEgressAllowed("Bitbucket");
    reviewer = (deps.reviewer ?? createReviewer)(reviewerSettings(config, token));
  } catch (error) { return { lastStatus: "blocked", lastError: message(error) }; }

  const { store, sentinel, trigger } = deps;
  const seen: Record<string, string> = {};
  // A webhook that arrives before the first poll must not start a cursor: the first poll would then review every open pull request instead of recording them.
  const remember = !delivered || trigger.cursor !== undefined;
  let candidates: DeliveredPullRequest[] = [];
  if (delivered) {
    candidates = [delivered];
    for (const [key, value] of Object.entries(trigger.cursor ?? {})) seen[key] = value;
  } else {
    let open: PullRequest[];
    try {
      open = await reviewer.client.listOpenPullRequests(reviewer.owner, reviewer.repo);
      if (open.length > MAX_POLLED) throw new Error(`More than ${MAX_POLLED} open pull requests.`);
    } catch (error) { return { lastStatus: "blocked", lastError: `Bitbucket could not be read: ${message(error)}` }; }
    const openKeys = new Set(open.map(pr => String(pr.id)));
    for (const [key, value] of Object.entries(trigger.cursor ?? {})) if (openKeys.has(key)) seen[key] = value;
    if (!trigger.cursor) {
      // The first poll only records what is already open; it never reviews old pull requests. A draft or fork is left out so it is reviewed once it qualifies.
      for (const pr of open) if (!pr.draft && !pr.fork) seen[String(pr.id)] = pr.headSha;
      return { cursor: seen, lastStatus: "baseline" };
    }
    for (const pr of open) {
      const was = seen[String(pr.id)];
      if (was && sameCommit(was, pr.headSha)) continue;
      candidates.push({ pr, event: was ? "updated" : "opened" });
    }
  }

  const state = {
    get: (key: string) => seen[key.slice(key.lastIndexOf("#") + 1)],
    set: (key: string, sha: string) => { seen[key.slice(key.lastIndexOf("#") + 1)] = sha; },
  };
  let lastStatus = "idle"; let lastError: string | undefined; let reviews = 0;
  for (const { pr, event } of candidates) {
    if (!deps.isEnabled()) break;
    const id = String(pr.id);
    const handled = () => { if (remember) seen[id] = pr.headSha; };
    if (!config.events.includes(event)) { handled(); continue; }
    const key = `bitbucket:${trigger.id}:${pr.id}:${pr.headSha}`;
    const skip = !pr.open ? "closed" : pr.draft ? "draft" : pr.fork ? "fork" : undefined;
    const record = (status: SentinelActivation["status"], extra: { error?: string; note?: string }, idempotencyKey: string) => {
      const info: Record<string, string | number> = { repo: config.repo, pr: pr.id, headSha: pr.headSha, base: pr.baseBranch.slice(0, 200), head: pr.headBranch.slice(0, 200), title: oneLine(pr.title, 300), event };
      return store.createActivation({
        sentinelId: sentinel.id, sentinelVersion: sentinel.version, status, skills: [...sentinel.skills], automationId: deps.automationId,
        trigger: { kind: "bitbucket-pr", automationId: deps.automationId, triggerId: trigger.id, event: info },
        ...(extra.error ? { error: extra.error } : {}), ...(extra.note ? { note: extra.note } : {}), startedAt: isoAt(deps.now()), ...(status !== "running" ? { finishedAt: isoAt(deps.now()) } : {}),
      }, { via: deps.via, idempotencyKey });
    };
    if (skip) {
      // Recorded once per head commit. A draft or fork is not remembered in the cursor, so it is reviewed when it becomes ready.
      if (skip !== "closed" && !store.getTurnByKey(sentinel.id, `${key}:${skip}`)) record("skipped", { error: `Skipped: ${skip} pull request.` }, `${key}:${skip}`);
      continue;
    }
    if (store.getTurnByKey(sentinel.id, key)) { handled(); continue; }
    // A spend limit that is reached refuses the review. It is recorded once per pull request commit and tried again after the limit resets.
    const refusal = store.budgetRefusal(sentinel.id, trigger.id, deps.now());
    if (refusal) {
      if (!store.getTurnByKey(sentinel.id, `${key}:budget`)) record("skipped", { error: refusal }, `${key}:budget`);
      lastStatus = "budget"; lastError = refusal;
      break;
    }
    if (reviews >= MAX_BITBUCKET_REVIEWS_PER_POLL) break;
    reviews += 1;
    const started = record("running", {}, key);
    const runSettings = reviewerSettings(config, token);
    runSettings.metricIdentity = { sentinelId: sentinel.id, triggerId: trigger.id, activationId: started.id };
    runSettings.budget = String(Math.min(config.budgetUsd, sentinel.runBudgetUsd ?? Infinity, trigger.runBudgetUsd ?? Infinity));
    const runModel = trigger.runModel ?? (config.model ? undefined : sentinel.model);
    if (runModel) {
      runSettings.model = runModel.model; runSettings.providerId = runModel.providerId;
      if (runModel.reasoning) runSettings.reasoning = runModel.reasoning;
    }
    const runReviewer = (deps.reviewer ?? createReviewer)(runSettings);
    let outcome: ReviewOutcome;
    try {
      outcome = await reviewPullRequest(pr, { client: reviewer.client, runner: runReviewer.runner, state }, reviewer.review);
    } catch (error) {
      // A failed review is not retried until the pull request changes: a retry on every poll would spend the budget again each time.
      lastStatus = "error"; lastError = `Pull request ${pr.id}: ${message(error)}`;
      store.updateActivation(started.id, { status: "failed", error: lastError, finishedAt: isoAt(deps.now()) });
      handled();
      continue;
    }
    handled();
    if (outcome.status === "skipped") { store.updateActivation(started.id, { status: "skipped", finishedAt: isoAt(deps.now()) }); continue; }
    store.updateActivation(started.id, { status: "completed", note: oneLine(describeOutcome(outcome), 400), ...(outcome.status === "reviewed" && outcome.costUsd !== undefined ? { costUsd: outcome.costUsd } : {}), finishedAt: isoAt(deps.now()) });
    if (lastStatus !== "error") lastStatus = "reviewed";
  }
  return { ...(remember ? { cursor: seen } : {}), lastStatus, ...(lastError ? { lastError } : {}) };
}
