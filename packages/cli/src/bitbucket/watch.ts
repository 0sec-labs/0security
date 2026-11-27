/**
 * Ways a review starts: a poll of the open pull requests, a signed webhook, or both. Reviews run one at a time, and a
 * pull request already waiting is not queued twice.
 */
import { createServer, type Server } from "node:http";
import { BodyError, WindowCounter, readBodyCapped } from "../web/github-webhook.js";
import type { BitbucketClient, Platform, PullRequest } from "./client.js";
import { parseDelivery, verifySignature } from "./events.js";
import { prKey, type ReviewOutcome, type ReviewState } from "./review.js";

export const MAX_WEBHOOK_BODY = 1024 * 1024;
/**
 * The body is read before the signature can be checked, so anyone who reaches the listener can make it buffer. These bound
 * that: at most MAX_WEBHOOK_CONNECTIONS sockets, each body capped and read within readBodyCapped's 10 second deadline, slow
 * headers cut at 10 seconds, and 30 requests a minute from one address. Bitbucket sends small JSON bodies quickly.
 */
export const MAX_WEBHOOK_CONNECTIONS = 32;
const SOURCE_LIMIT_PER_MINUTE = 30;
const MAX_SOURCES = 5_000;

/**
 * Where the state remembers the head commit whose review failed. A failed review is not retried until the pull request
 * changes: a retry on every poll would spend the budget again each time. It is kept apart from the reviewed commit, so
 * `review --pr` can still run that commit again by hand.
 */
export const failedKey = (pr: Pick<PullRequest, "platform" | "owner" | "repo" | "id">): string => `failed:${prKey(pr)}`;
const sameCommit = (a: string | undefined, b: string): boolean => a !== undefined && a.slice(0, 12) === b.slice(0, 12);

export interface QueueDeps {
  review(pr: PullRequest): Promise<ReviewOutcome>;
  /** Records the head commit of a review that failed, so that commit is not reviewed again. */
  state: ReviewState;
  log(line: string): void;
}

/** One review at a time. A pull request that is already queued is replaced by its newer state, not added again. */
export class ReviewQueue {
  readonly #waiting = new Map<string, PullRequest>();
  #running: Promise<void> | undefined;
  #current: string | undefined;
  constructor(readonly deps: QueueDeps) {}

  add(pr: PullRequest): void {
    const key = prKey(pr);
    this.#waiting.set(key, pr);
    this.#running ??= this.#drain();
  }
  /** Resolves when everything queued so far has finished. */
  async idle(): Promise<void> { while (this.#running) await this.#running; }
  get pending(): number { return this.#waiting.size + (this.#current ? 1 : 0); }

  async #drain(): Promise<void> {
    // Yield once first: a drain that only skips never awaits, and would clear #running before add() stores this promise.
    await Promise.resolve();
    try {
      while (this.#waiting.size) {
        const [key, pr] = this.#waiting.entries().next().value as [string, PullRequest];
        this.#waiting.delete(key);
        this.#current = key;
        if (sameCommit(this.deps.state.get(failedKey(pr)), pr.headSha)) {
          this.deps.log(`${key}: skipped (the review of ${pr.headSha.slice(0, 7)} failed; not retried until the pull request changes)`);
        } else {
          try {
            const outcome = await this.deps.review(pr);
            this.deps.log(`${key}: ${describeOutcome(outcome)}`);
          } catch (error) {
            try { this.deps.state.set(failedKey(pr), pr.headSha); } catch { /* The state file could not be written; a later poll tries this commit again. */ }
            this.deps.log(`${key}: review failed: ${(error instanceof Error ? error.message : String(error)).split("\n")[0]!.slice(0, 300)}; not retried until the pull request changes (fix the cause, then push a commit or run review --pr ${pr.id})`);
          }
        }
        this.#current = undefined;
      }
    } finally { this.#running = undefined; }
  }
}

export function describeOutcome(outcome: ReviewOutcome): string {
  if (outcome.status === "skipped") return `skipped (${outcome.reason})`;
  if (outcome.status === "too-large") return `skipped, ${outcome.files} files is too many`;
  return `reviewed ${outcome.sha.slice(0, 7)}, ${outcome.total} finding(s)${outcome.partial ? ", partial" : ""}${outcome.warnings.length ? `, ${outcome.warnings.length} warning(s): ${outcome.warnings.join(" | ")}` : ""}`;
}

/** Queue the open pull requests whose head commit changed since the last review, or the last failed one. Returns how many were queued. */
export async function pollOnce(client: BitbucketClient, repo: { owner: string; repo: string }, queue: ReviewQueue, state: { get(key: string): string | undefined }, limit = 5): Promise<number> {
  let queued = 0;
  for (const pr of await client.listOpenPullRequests(repo.owner, repo.repo)) {
    if (queued >= limit) break;
    if (pr.draft || pr.fork) continue;
    if (sameCommit(state.get(prKey(pr)), pr.headSha) || sameCommit(state.get(failedKey(pr)), pr.headSha)) continue;
    queue.add(pr);
    queued++;
  }
  return queued;
}

export interface WebhookOptions {
  platform: Platform;
  secret: string;
  /** The one repository this server reviews. Deliveries for another repository are ignored. */
  repo: { owner: string; repo: string };
  queue: ReviewQueue;
  log(line: string): void;
}

/** An HTTP server for webhook deliveries: POST only, signed, small, and for the named repository. */
export function createWebhookServer(options: WebhookOptions): Server {
  const sources = new Map<string, WindowCounter>();
  const sourceAllowed = (client: string, t: number): boolean => {
    if (sources.size >= MAX_SOURCES) for (const [key, counter] of sources) if (counter.idle(t)) sources.delete(key);
    if (sources.size >= MAX_SOURCES) sources.clear();
    let counter = sources.get(client);
    if (!counter) { counter = new WindowCounter(SOURCE_LIMIT_PER_MINUTE, 60_000); sources.set(client, counter); }
    return counter.take(t);
  };
  const server = createServer({ headersTimeout: 10_000, requestTimeout: 15_000, connectionsCheckingInterval: 1_000 }, (request, response) => {
    const reply = (status: number, body: string, close = false) => { response.writeHead(status, { "Content-Type": "text/plain", ...(close ? { Connection: "close" } : {}) }); response.end(body); };
    request.on("error", () => { /* A dropped connection needs no answer. */ });
    if (request.method !== "POST") return reply(405, "Use POST.");
    if (!sourceAllowed(request.socket.remoteAddress ?? "", Date.now())) { response.setHeader("Retry-After", "60"); return reply(429, "Too many requests.", true); }
    const declared = Number(request.headers["content-length"] ?? 0);
    if (declared > MAX_WEBHOOK_BODY) return reply(413, "Too large.");
    readBodyCapped(request, MAX_WEBHOOK_BODY).then(body => {
      if (!verifySignature(options.secret, body, header(request.headers["x-hub-signature"]))) { options.log("webhook: signature did not match"); return reply(401, "Bad signature."); }
      const eventKey = header(request.headers["x-event-key"]) ?? "";
      let payload: unknown;
      try { payload = JSON.parse(body.toString("utf8")); } catch { return reply(400, "Not JSON."); }
      const parsed = parseDelivery(options.platform, eventKey, payload);
      if (!parsed.ok) { options.log(`webhook: ignored ${eventKey.slice(0, 40)} (${parsed.reason})`); return reply(202, "Ignored."); }
      const { pr } = parsed;
      if (pr.owner.toLowerCase() !== options.repo.owner.toLowerCase() || pr.repo.toLowerCase() !== options.repo.repo.toLowerCase()) { options.log("webhook: ignored a delivery for another repository"); return reply(202, "Ignored."); }
      options.queue.add(pr);
      reply(202, "Queued.");
    }, (error: unknown) => {
      if (!(error instanceof BodyError)) { request.destroy(); return; }
      const tooLarge = error.reason === "too_large";
      reply(tooLarge ? 413 : 408, tooLarge ? "Too large." : "Too slow.", true);
      response.once("finish", () => request.destroy());
    });
  });
  server.maxConnections = MAX_WEBHOOK_CONNECTIONS;
  return server;
}

const header = (value: string | string[] | undefined): string | undefined => (Array.isArray(value) ? value[0] : value);
