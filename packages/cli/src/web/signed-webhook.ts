// Signed webhook trigger: another system (a CI service, GitLab, Bitbucket, a script) starts one Sentinel trigger.
//
// URL: POST /api/webhooks/trigger/<trigger id>. Every trigger has its own secret, shown once when it is created or rotated.
// The caller proves it holds the secret with ONE of these, each as the vendor documents it:
//   X-Hub-Signature-256: sha256=<hex>   HMAC-SHA256 of the raw body. GitHub.
//     https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
//   X-Hub-Signature: sha256=<hex>       Same HMAC. Bitbucket Cloud and Bitbucket Data Center.
//     https://support.atlassian.com/bitbucket-cloud/docs/manage-webhooks/
//   X-Gitlab-Token: <secret>            The secret itself, sent as plain text. GitLab.
//     https://docs.gitlab.com/user/project/integrations/webhooks/
//   X-0-Signature-256: sha256=<hex> with X-0-Timestamp: <unix seconds>
//     HMAC-SHA256 of "<timestamp>.<raw body>". For your own scripts. Rejected outside a five minute window.
// Checks, cheapest first and always before the body is parsed: method, rate limit, secret exists, content type,
// Content-Length cap, streamed body cap and deadline, signature (constant-time), global limit, replay (delivery id,
// or a digest of the body), JSON. The payload never chooses a trigger or authorises anything: it is reduced to a few
// short neutralised strings that the run sees as untrusted data.
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { audit } from "./audit.js";
import { json } from "./dashboard-http.js";
import { BodyError, DeliveryDedupe, WebhookSecretStore, WindowCounter, readBodyCapped, verifySignature } from "./github-webhook.js";
import { cleanField } from "./sentinel-github-events.js";

export const SIGNED_WEBHOOK_PREFIX = "/api/webhooks/trigger/";
export const SIGNED_WEBHOOK_MAX_BODY_BYTES = 256 * 1024;
export const SIGNED_WEBHOOK_REPLAY_WINDOW_SECONDS = 300;
const TRIGGER_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SIGNATURE_SHAPE = /^sha256=[0-9a-f]{64}$/;
const DELIVERY_SHAPE = /^[0-9A-Za-z._-]{8,80}$/;
const SOURCE_LIMIT_PER_MINUTE = 30;
const GLOBAL_LIMIT_PER_MINUTE = 300;
const MAX_SOURCES = 5_000;

/** The trigger id when `pathname` is exactly the signed webhook path of one trigger. */
export function signedWebhookTriggerId(pathname: string): string | undefined {
  if (!pathname.startsWith(SIGNED_WEBHOOK_PREFIX)) return undefined;
  const id = pathname.slice(SIGNED_WEBHOOK_PREFIX.length);
  return TRIGGER_ID.test(id) ? id : undefined;
}

/** One secret file per trigger, in the same 0600 format and with the same rotation grace as the GitHub webhook secret. */
export class SignedWebhookSecrets {
  readonly #stores = new Map<string, WebhookSecretStore>();
  constructor(private readonly stateDir: string, private readonly now: () => number = Date.now) {}
  #store(triggerId: string): WebhookSecretStore {
    if (!TRIGGER_ID.test(triggerId)) throw new Error("Bad trigger id.");
    let store = this.#stores.get(triggerId);
    if (!store) { store = new WebhookSecretStore(this.stateDir, this.now, `signed-webhook-${triggerId}.json`); this.#stores.set(triggerId, store); }
    return store;
  }
  configured(triggerId: string): boolean { return TRIGGER_ID.test(triggerId) && this.#store(triggerId).configured; }
  active(triggerId: string): string[] { return TRIGGER_ID.test(triggerId) ? this.#store(triggerId).active() : []; }
  /** A new secret, returned once. The previous one keeps working for the grace window. */
  rotate(triggerId: string): string { return this.#store(triggerId).rotate(); }
  status(triggerId: string): { configured: boolean; createdAt?: string; graceUntil?: string } { return this.#store(triggerId).status(); }
}

const constantTimeEqual = (a: string, b: string): boolean => timingSafeEqual(createHash("sha256").update(a).digest(), createHash("sha256").update(b).digest());

type Headers = IncomingMessage["headers"];
const header = (headers: Headers, name: string): string | undefined => { const value = headers[name]; return typeof value === "string" ? value : undefined; };

export type SignatureCheck = { ok: true; scheme: "github" | "bitbucket" | "gitlab" | "own" } | { ok: false; reason: string };

const hmacHeader = (value: string, raw: Buffer, secrets: readonly string[], scheme: "github" | "bitbucket"): SignatureCheck =>
  verifySignature(raw, value, secrets) ? { ok: true, scheme } : { ok: false, reason: SIGNATURE_SHAPE.test(value) ? "invalid_signature" : "signature_missing_or_malformed" };

/**
 * Checks the first scheme the request carries. Every candidate secret is evaluated (current and, during rotation, the previous one).
 * `nowMs` is only used for the X-0 timestamp window.
 */
export function verifyDelivery(headers: Headers, raw: Buffer, secrets: readonly string[], nowMs: number): SignatureCheck {
  const own = header(headers, "x-0-signature-256");
  if (own !== undefined) {
    const stamp = header(headers, "x-0-timestamp");
    if (stamp === undefined || !/^\d{9,12}$/.test(stamp)) return { ok: false, reason: "timestamp_missing_or_malformed" };
    if (Math.abs(nowMs / 1000 - Number(stamp)) > SIGNED_WEBHOOK_REPLAY_WINDOW_SECONDS) return { ok: false, reason: "timestamp_outside_window" };
    if (!SIGNATURE_SHAPE.test(own)) return { ok: false, reason: "signature_missing_or_malformed" };
    return verifySignature(Buffer.concat([Buffer.from(`${stamp}.`), raw]), own, secrets) ? { ok: true, scheme: "own" } : { ok: false, reason: "invalid_signature" };
  }
  const github = header(headers, "x-hub-signature-256");
  if (github !== undefined) return hmacHeader(github, raw, secrets, "github");
  const bitbucket = header(headers, "x-hub-signature");
  if (bitbucket !== undefined) return hmacHeader(bitbucket, raw, secrets, "bitbucket");
  const gitlab = header(headers, "x-gitlab-token");
  if (gitlab !== undefined) {
    let ok = false;
    for (const secret of secrets) if (constantTimeEqual(gitlab, secret)) ok = true;
    return ok ? { ok: true, scheme: "gitlab" } : { ok: false, reason: "invalid_signature" };
  }
  return { ok: false, reason: "signature_missing_or_malformed" };
}

/** Delivery id the sender gave us, else a digest of the exact bytes (a replayed body is a replayed delivery). */
export function deliveryKey(headers: Headers, raw: Buffer): string {
  for (const name of ["x-0-delivery", "x-github-delivery", "x-request-uuid", "x-gitlab-event-uuid", "x-gitlab-webhook-uuid"]) {
    const value = header(headers, name);
    if (value !== undefined && DELIVERY_SHAPE.test(value)) return `id-${value}`;
  }
  return `body-${createHash("sha256").update(raw).digest("hex")}`;
}

/** What the run sees: a few short strings. Unknown fields are dropped. */
export function webhookFields(headers: Headers, payload: unknown, scheme: string): Record<string, string | number> {
  const body = payload && typeof payload === "object" && !Array.isArray(payload) ? payload as Record<string, unknown> : {};
  const fields: Record<string, string | number> = { event: "webhook called", sender: scheme };
  const sourceEvent = cleanField(header(headers, "x-github-event") ?? header(headers, "x-gitlab-event") ?? header(headers, "x-event-key"), 60);
  if (sourceEvent) fields["sourceEvent"] = sourceEvent;
  const message = cleanField(body["message"], 500);
  if (message) fields["message"] = message;
  const ref = cleanField(body["ref"], 200);
  if (ref && /^[A-Za-z0-9._/-]+$/.test(ref)) fields["ref"] = ref;
  const url = cleanField(body["url"], 300);
  if (/^https:\/\/[A-Za-z0-9.-]+(?:[/?#][A-Za-z0-9_./?#=&%:+-]*)?$/.test(url)) fields["url"] = url;
  return fields;
}

export interface SignedWebhookDispatcher {
  /** Starts the trigger. Resolves false when it is missing, off, not a webhook trigger or busy. */
  deliver(triggerId: string, input: { key: string; fields: Record<string, string | number> }): Promise<boolean>;
}
export interface SignedWebhookOptions {
  secrets: SignedWebhookSecrets;
  dispatcher: () => SignedWebhookDispatcher | undefined;
  now?: () => number;
  sourceLimitPerMinute?: number;
  globalLimitPerMinute?: number;
  maxBodyBytes?: number;
}

const reply = (res: ServerResponse, status: number, body: Record<string, unknown> = {}): void => { json(res, status, body); };

export class SignedWebhookReceiver {
  private readonly now: () => number;
  private readonly dedupe: DeliveryDedupe;
  private readonly sources = new Map<string, WindowCounter>();
  private readonly global: WindowCounter;
  private readonly sourceLimit: number;
  private readonly maxBody: number;
  private readonly pending = new Set<Promise<void>>();
  constructor(private readonly options: SignedWebhookOptions) {
    this.now = options.now ?? Date.now;
    this.dedupe = new DeliveryDedupe(this.now);
    this.sourceLimit = options.sourceLimitPerMinute ?? SOURCE_LIMIT_PER_MINUTE;
    this.global = new WindowCounter(options.globalLimitPerMinute ?? GLOBAL_LIMIT_PER_MINUTE, 60_000);
    this.maxBody = options.maxBodyBytes ?? SIGNED_WEBHOOK_MAX_BODY_BYTES;
  }
  get secrets(): SignedWebhookSecrets { return this.options.secrets; }
  /** Resolves when deliveries started so far have been handed to the trigger (tests and shutdown). */
  async settled(): Promise<void> { while (this.pending.size) await Promise.allSettled([...this.pending]); }

  private record(outcome: "received" | "ignored" | "rejected", client: string, triggerId: string | undefined, reason?: string): void {
    audit({ actor: "signed-webhook", action: `webhook.signed.${outcome}`, subject: triggerId ?? "unknown", outcome: outcome === "rejected" ? "denied" : "ok", detail: { ...(reason ? { reason } : {}), client } });
  }
  private reject(res: ServerResponse, status: number, client: string, triggerId: string | undefined, reason: string): void {
    this.record("rejected", client, triggerId, reason);
    reply(res, status);
  }
  private sourceAllowed(client: string, t: number): boolean {
    if (this.sources.size >= MAX_SOURCES) for (const [key, counter] of this.sources) if (counter.idle(t)) this.sources.delete(key);
    if (this.sources.size >= MAX_SOURCES) this.sources.clear();
    let counter = this.sources.get(client);
    if (!counter) { counter = new WindowCounter(this.sourceLimit, 60_000); this.sources.set(client, counter); }
    return counter.take(t);
  }

  async handle(req: IncomingMessage, res: ServerResponse, client: string, triggerId: string): Promise<void> {
    if (req.method !== "POST") { res.setHeader("Allow", "POST"); reply(res, 405, { error: "Use POST." }); return; }
    const t = this.now();
    if (!this.sourceAllowed(client, t)) { this.record("rejected", client, undefined, "rate_limited_source"); res.setHeader("Retry-After", "60"); reply(res, 429); return; }
    // An unknown trigger and a trigger without a secret answer the same, so ids cannot be probed.
    if (!this.options.secrets.configured(triggerId)) { reply(res, 404, { error: "Not found." }); return; }
    const type = String(req.headers["content-type"] ?? "").split(";")[0]!.trim().toLowerCase();
    if (type !== "application/json") { this.reject(res, 415, client, triggerId, "content_type"); return; }
    const lengthHeader = req.headers["content-length"];
    if (lengthHeader !== undefined) {
      const length = /^\d{1,12}$/.test(lengthHeader) ? Number(lengthHeader) : NaN;
      if (!Number.isFinite(length)) { this.reject(res, 400, client, triggerId, "content_length"); return; }
      if (length > this.maxBody) { this.tooLarge(req, res, client, triggerId); return; }
    }
    let raw: Buffer;
    try { raw = await readBodyCapped(req, this.maxBody); }
    catch (error) {
      if (error instanceof BodyError) { if (error.reason === "too_large") this.tooLarge(req, res, client, triggerId); else this.reject(res, 408, client, triggerId, "body_timeout"); return; }
      this.reject(res, 400, client, triggerId, "body_read"); return;
    }
    const checked = verifyDelivery(req.headers, raw, this.options.secrets.active(triggerId), this.now());
    if (!checked.ok) { this.reject(res, 401, client, triggerId, checked.reason); return; }
    if (!this.global.take(this.now())) { this.record("rejected", client, triggerId, "rate_limited_global"); res.setHeader("Retry-After", "60"); reply(res, 429); return; }
    const key = deliveryKey(req.headers, raw);
    const claim = `${triggerId}:${key}`;
    if (!this.dedupe.claim(claim)) { this.record("ignored", client, triggerId, "duplicate_delivery"); reply(res, 202, { ok: true }); return; }
    let payload: unknown = {};
    if (raw.length) { try { payload = JSON.parse(raw.toString("utf8")); } catch { this.dedupe.release(claim); this.reject(res, 400, client, triggerId, "malformed_json"); return; } }
    const dispatcher = this.options.dispatcher();
    if (!dispatcher) { this.dedupe.release(claim); this.record("ignored", client, triggerId, "not_available"); reply(res, 503, { error: "Not available." }); return; }
    this.record("received", client, triggerId, checked.scheme);
    reply(res, 202, { ok: true });
    const fields = webhookFields(req.headers, payload, checked.scheme);
    const work = (async () => {
      try { if (!await dispatcher.deliver(triggerId, { key, fields })) this.dedupe.release(claim); }
      catch { this.dedupe.release(claim); }
    })().finally(() => { this.pending.delete(work); });
    this.pending.add(work);
  }

  private tooLarge(req: IncomingMessage, res: ServerResponse, client: string, triggerId: string): void {
    this.record("rejected", client, triggerId, "body_too_large");
    res.setHeader("Connection", "close");
    reply(res, 413);
    res.once("finish", () => req.destroy());
  }
}

/** The X-0-Signature-256 value for a body, for scripts and tests. */
export const signOwn = (secret: string, timestampSeconds: number, body: string | Buffer): string =>
  `sha256=${createHmac("sha256", secret).update(`${timestampSeconds}.`).update(body).digest("hex")}`;
