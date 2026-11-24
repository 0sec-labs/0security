/**
 * Ways a review starts: a poll of the open pull requests, a signed webhook, or both. Reviews run one at a time, and a
 * pull request already waiting is not queued twice.
 */
import { createServer, type Server } from "node:http";
import type { BitbucketClient, Platform, PullRequest } from "./client.js";
import { parseDelivery, verifySignature } from "./events.js";
import { prKey, type ReviewOutcome } from "./review.js";

export const MAX_WEBHOOK_BODY = 1024 * 1024;

export interface QueueDeps {
  review(pr: PullRequest): Promise<ReviewOutcome>;
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
    try {
      while (this.#waiting.size) {
        const [key, pr] = this.#waiting.entries().next().value as [string, PullRequest];
        this.#waiting.delete(key);
        this.#current = key;
        try {
          const outcome = await this.deps.review(pr);
          this.deps.log(`${key}: ${describe(outcome)}`);
        } catch (error) {
          this.deps.log(`${key}: review failed: ${(error instanceof Error ? error.message : String(error)).split("\n")[0]!.slice(0, 300)}`);
        }
        this.#current = undefined;
      }
    } finally { this.#running = undefined; }
  }
}

function describe(outcome: ReviewOutcome): string {
  if (outcome.status === "skipped") return `skipped (${outcome.reason})`;
  if (outcome.status === "too-large") return `skipped, ${outcome.files} files is too many`;
  return `reviewed ${outcome.sha.slice(0, 7)}, ${outcome.total} finding(s)${outcome.partial ? ", partial" : ""}${outcome.warnings.length ? `, ${outcome.warnings.length} warning(s): ${outcome.warnings.join(" | ")}` : ""}`;
}

/** Queue the open pull requests whose head commit changed since the last review. Returns how many were queued. */
export async function pollOnce(client: BitbucketClient, repo: { owner: string; repo: string }, queue: ReviewQueue, state: { get(key: string): string | undefined }, limit = 5): Promise<number> {
  let queued = 0;
  for (const pr of await client.listOpenPullRequests(repo.owner, repo.repo)) {
    if (queued >= limit) break;
    if (pr.draft || pr.fork) continue;
    const seen = state.get(prKey(pr));
    if (seen && seen.slice(0, 12) === pr.headSha.slice(0, 12)) continue;
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
  return createServer((request, response) => {
    const reply = (status: number, body: string) => { response.writeHead(status, { "Content-Type": "text/plain" }); response.end(body); };
    if (request.method !== "POST") return reply(405, "Use POST.");
    const declared = Number(request.headers["content-length"] ?? 0);
    if (declared > MAX_WEBHOOK_BODY) return reply(413, "Too large.");
    const chunks: Buffer[] = [];
    let size = 0;
    let rejected = false;
    request.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_WEBHOOK_BODY) { if (!rejected) { rejected = true; reply(413, "Too large."); request.destroy(); } return; }
      chunks.push(chunk);
    });
    request.on("end", () => {
      if (rejected) return;
      const body = Buffer.concat(chunks);
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
    });
    request.on("error", () => { /* A dropped connection needs no answer. */ });
  });
}

const header = (value: string | string[] | undefined): string | undefined => (Array.isArray(value) ? value[0] : value);
