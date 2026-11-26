import type { MetricSink } from "../run-metrics.js";
import { z } from "zod";
import { recordAccessUpgrade } from "../state/access-upgrade.js";
import { listSessions } from "../state/session-store.js";
import { audit } from "./audit.js";
import { SecurityWorkflowStore, SentinelStore, SentinelStoreError } from "@0/engine/storage";
import { budgetCapSchema, utcDayStart, utcMonthStart, SENTINEL_FILE_FOLDERS, SENTINEL_PRESETS, SENTINEL_STATUSES, describeSentinelSchedule, getSentinelPreset, sentinelNeedsReview, type Sentinel, type SentinelActivation, type SentinelAttention, type SentinelTrigger } from "@0/engine/shared";
import type { GithubEvent } from "./sentinel-github-events.js";
import { SentinelRunError, SentinelRunner, type SentinelActor, type SentinelGhClient, type SentinelMissionRuntime } from "./sentinel-runner.js";

const PREFIX = "/api/console/";
const idSchema = z.string().trim().min(1).max(160).regex(/^[A-Za-z0-9_.:-]+$/);

export type { SentinelActor, SentinelMissionRuntime, SentinelGhClient } from "./sentinel-runner.js";
class SentinelRequestError extends Error {
  constructor(message: string, readonly status: number = 409) { super(message); }
}
function parse<T>(schema: z.ZodType<T>, input: unknown): T {
  const result = schema.safeParse(input);
  if (!result.success) throw new SentinelRequestError(result.error.issues.map(issue => `${issue.path.join(".") || "request"}: ${issue.message}`).join("; "), 400);
  return result.data;
}
const bodyOf = (input: unknown): Record<string, unknown> => input && typeof input === "object" && !Array.isArray(input) ? input as Record<string, unknown> : {};
/** The Monday (UTC) of the week an ISO time falls in, as a date. */
const weekStartOf = (at: string): string => { const d = new Date(at); d.setUTCHours(0, 0, 0, 0); d.setUTCDate(d.getUTCDate() - ((d.getUTCDay() + 6) % 7)); return d.toISOString().slice(0, 10); };
const message = (error: unknown) => (error instanceof Error ? error.message : String(error)).slice(0, 4_000);

export class WebSentinelService {
  readonly #store: SentinelStore;
  readonly #workflows: SecurityWorkflowStore;
  readonly #missions: SentinelMissionRuntime;
  readonly #now: () => number;
  readonly #runner: SentinelRunner;
  /**
   * `scheduler` starts the background tick (schedules, GitHub PR polling, run tracking). Off by default so tests and
   * tools that only need the HTTP surface do not run autonomous work; the dashboard turns it on.
   */
  constructor(options: { metrics?: MetricSink; dbPath?: string; missions: SentinelMissionRuntime; now?: () => number; scheduler?: boolean | { pollIntervalMs?: number }; gh?: SentinelGhClient; executionProfile?: () => "local" | "smolvm"; checkout?: (repo: string) => Promise<string | undefined>; persistentThread?: () => boolean; bitbucket?: ConstructorParameters<typeof SentinelRunner>[0]["bitbucket"] }) {
    this.#store = new SentinelStore(options.dbPath);
    this.#workflows = new SecurityWorkflowStore(options.dbPath);
    this.#missions = options.missions;
    this.#now = options.now ?? Date.now;
    this.#runner = new SentinelRunner({ metrics: options.metrics, store: this.#store, workflows: this.#workflows, missions: options.missions, now: this.#now, ...(options.gh ? { gh: options.gh } : {}), ...(options.executionProfile ? { executionProfile: options.executionProfile } : {}), ...(options.checkout ? { checkout: options.checkout } : {}), ...(options.persistentThread ? { persistentThread: options.persistentThread } : {}), ...(options.bitbucket ? { bitbucket: options.bitbucket } : {}) });
    if (options.scheduler) this.#noteAccessUpgrade();
    if (options.scheduler) this.#runner.start(typeof options.scheduler === "object" ? options.scheduler.pollIntervalMs : undefined);
  }
  /** First start after access collapsed to one mode: record how many Sentinels and threads already existed (one audit entry) and leave one dismissible notice next to the setting. */
  #noteAccessUpgrade(): void {
    try {
      const agents = this.#store.list().length;
      const threads = listSessions().length;
      if (recordAccessUpgrade({ agents, threads }) && agents + threads > 0) audit({ actor: "system", action: "access.upgrade.one-mode", subject: "access", outcome: "ok", detail: { agents, threads, note: "Threads and Sentinels now always have shell access; limits are the budget and the sandbox." } });
    } catch { /* Advisory only. */ }
  }
  /** Webhook acceleration: the triggers a delivery for this repository and base branch may check. */
  webhookTargets(repo: string, baseBranch: string): Array<{ id: string }> { return this.#runner.pullRequestTriggers(repo, baseBranch).map(trigger => ({ id: trigger.id })); }
  /** Signed-webhook source for release and check triggers: the enabled triggers this event belongs to. */
  webhookEventTargets(event: GithubEvent): Array<{ id: string }> { return this.#runner.eventTriggers(event).map(trigger => ({ id: trigger.id })); }
  deliverWebhookEvent(triggerId: string, event: GithubEvent): Promise<boolean> { return this.#runner.deliverEvent(triggerId, event); }
  /** True when this id is a webhook or Bitbucket pull request trigger (the secret endpoint refuses anything else). */
  isWebhookTrigger(triggerId: string): boolean { const kind = this.#store.getTrigger(triggerId)?.kind; return kind === "webhook" || kind === "bitbucket-pr"; }
  /** Signed webhook triggers: starts one trigger for a verified delivery. A Bitbucket pull request trigger gets the event name and the payload to find its pull request. */
  deliverSignedWebhook(triggerId: string, input: { key: string; fields: Record<string, string | number>; eventKey?: string; payload?: unknown }): Promise<boolean> {
    if (this.#store.getTrigger(triggerId)?.kind === "bitbucket-pr") return this.#runner.deliverBitbucket(triggerId, { eventKey: input.eventKey ?? "", payload: input.payload });
    return this.#runner.deliverSigned(triggerId, input);
  }
  /** Webhook acceleration: runs the poller's own check for one trigger now (same draft, fork, comment and head-SHA rules). */
  checkTrigger(triggerId: string): Promise<boolean> { return this.#runner.checkNow(triggerId, "webhook"); }
  /** Drives one scheduler pass; the background timer calls this. Exposed for tests and for an explicit "check now". */
  tick(nowMs?: number): Promise<void> { return this.#runner.tick(nowMs); }
  /** Resolves when the Bitbucket reviews started so far have finished (tests). */
  settled(): Promise<void> { return this.#runner.settled(); }
  async dispose(): Promise<void> { await this.#runner.dispose(); this.#store.close(); this.#workflows.close(); }

  /** Auth (control token / team session) is enforced before this is reached; this layer adds team roles. */
  async handle(pathname: string, method: string, input: unknown, query: URLSearchParams, actor?: SentinelActor): Promise<{ status: number; data: unknown } | null> {
    if (pathname !== PREFIX + "sentinels" && !pathname.startsWith(PREFIX + "sentinels/") && pathname !== PREFIX + "sentinel-presets") return null;
    try {
      return await this.#route(pathname.slice(PREFIX.length), method, input, query, actor);
    } catch (error) {
      const status = error instanceof z.ZodError ? 400 : error instanceof SentinelRequestError ? error.status
        : error instanceof SentinelStoreError ? error.statusCode
        : error && typeof error === "object" && "statusCode" in error && typeof error.statusCode === "number" ? error.statusCode : 500;
      return { status, data: { error: status === 500 ? "Sentinel request failed." : message(error) } };
    }
  }

  #requireWriter(actor?: SentinelActor): void {
    if (actor?.role === "viewer") throw new SentinelRequestError("Viewers cannot change Sentinels.", 403);
  }
  #requireSentinel(id: string): Sentinel {
    const sentinel = this.#store.get(id);
    if (!sentinel) throw new SentinelRequestError("Sentinel not found.", 404);
    return sentinel;
  }
  #attention(sentinel: Sentinel): SentinelAttention {
    const missions = new Set<string>();
    if (sentinel.homeMissionId) missions.add(sentinel.homeMissionId);
    for (const activation of this.#store.listActivations(sentinel.id, 5)) if (activation.status === "running" && activation.missionId) missions.add(activation.missionId);
    let pending = 0;
    for (const id of missions) { try { pending += this.#missions.pendingDecisions(id); } catch { /* A closed mission has nothing pending. */ } }
    const needsReview = sentinelNeedsReview(sentinel);
    const failing = this.#store.listTriggers(sentinel.id).some(trigger => trigger.lastStatus === "failing");
    const reason = (needsReview ? "Model, tools or skills changed since the last review." : failing ? "A trigger was turned off after three failed turns in a row." : undefined);
    return { needsYou: pending > 0 || needsReview || failing, needsReview, pendingDecisions: pending, ...(reason ? { reason } : {}) };
  }
  #view(sentinel: Sentinel) {
    const thread = this.#runner.threadInfo(sentinel);
    return { ...sentinel, attention: this.#attention(sentinel), ...(thread ? { thread } : {}) };
  }
  /** Spend by Sentinel, model and week over the last 12 weeks, with each Sentinel's spend today and this month against its limits. UTC. */
  #usage() {
    const nowMs = this.#now();
    const since = new Date(Date.parse(utcDayStart(nowMs)) - 11 * 7 * 86_400_000 - ((new Date(nowMs).getUTCDay() + 6) % 7) * 86_400_000).toISOString();
    const rows = this.#store.usageSince(since);
    const sentinels = new Map(this.#store.list().map(sentinel => [sentinel.id, sentinel]));
    const total = () => ({ runs: 0, costUsd: 0, refused: 0 });
    const add = (target: ReturnType<typeof total>, row: (typeof rows)[number]) => { if (row.refused) target.refused += 1; else { target.runs += 1; target.costUsd += row.costUsd; } };
    const bySentinel = new Map<string, ReturnType<typeof total> & { dayUsd: number; monthUsd: number }>();
    const byModel = new Map<string, ReturnType<typeof total>>();
    const byWeek = new Map<string, ReturnType<typeof total>>();
    const day = utcDayStart(nowMs); const month = utcMonthStart(nowMs);
    for (const row of rows) {
      const owner = sentinels.get(row.sentinelId);
      const entry = bySentinel.get(row.sentinelId) ?? { ...total(), dayUsd: 0, monthUsd: 0 };
      add(entry, row);
      if (!row.refused && row.at >= month) entry.monthUsd += row.costUsd;
      if (!row.refused && row.at >= day) entry.dayUsd += row.costUsd;
      bySentinel.set(row.sentinelId, entry);
      const model = owner?.model?.model ?? "Default model";
      add(byModel.get(model) ?? byModel.set(model, total()).get(model)!, row);
      const week = weekStartOf(row.at);
      add(byWeek.get(week) ?? byWeek.set(week, total()).get(week)!, row);
    }
    const round = (n: number) => Number(n.toFixed(6));
    return {
      since, generatedAt: new Date(nowMs).toISOString(),
      sentinels: [...bySentinel.entries()].map(([id, entry]) => { const s = sentinels.get(id); return { id, name: s?.name ?? "Deleted Sentinel", model: s?.model?.model ?? null, runs: entry.runs, refused: entry.refused, costUsd: round(entry.costUsd), dayUsd: round(entry.dayUsd), monthUsd: round(entry.monthUsd), dailyBudgetUsd: s?.dailyBudgetUsd ?? null, monthlyBudgetUsd: s?.monthlyBudgetUsd ?? null }; }).sort((a, b) => b.costUsd - a.costUsd || a.name.localeCompare(b.name)),
      models: [...byModel.entries()].map(([model, entry]) => ({ model, runs: entry.runs, refused: entry.refused, costUsd: round(entry.costUsd) })).sort((a, b) => b.costUsd - a.costUsd || a.model.localeCompare(b.model)),
      weeks: [...byWeek.entries()].map(([week, entry]) => ({ week, runs: entry.runs, refused: entry.refused, costUsd: round(entry.costUsd) })).sort((a, b) => b.week.localeCompare(a.week)),
    };
  }
  #automations(id: string) { return this.#workflows.list().filter(workflow => workflow.ownerSentinelId === id); }

  async #route(path: string, method: string, input: unknown, query: URLSearchParams, actor?: SentinelActor): Promise<{ status: number; data: unknown }> {
    if (path === "sentinel-presets") {
      if (method !== "GET") throw new SentinelRequestError("Use GET to list Sentinel presets.", 405);
      return { status: 200, data: { presets: SENTINEL_PRESETS } };
    }
    if (path === "sentinels") {
      if (method === "GET") {
        const status = query.get("status");
        if (status !== null && !(SENTINEL_STATUSES as readonly string[]).includes(status)) throw new SentinelRequestError("Unknown status filter.", 400);
        return { status: 200, data: { sentinels: this.#store.list(status as Sentinel["status"] | undefined ?? undefined).map(sentinel => this.#view(sentinel)) } };
      }
      if (method === "POST") {
        this.#requireWriter(actor);
        const { preset: presetId, ...rest } = bodyOf(input);
        let body: Record<string, unknown> = rest;
        let suggestedAutomations;
        if (presetId !== undefined) {
          const preset = typeof presetId === "string" ? getSentinelPreset(presetId) : undefined;
          if (!preset) throw new SentinelRequestError("Unknown Sentinel preset.", 400);
          body = { ...preset.sentinel, ...rest };
          suggestedAutomations = preset.suggestedAutomations;
        }
        const sentinel = this.#store.create(body, actor?.userId ?? "local");
        return { status: 201, data: { sentinel: this.#view(sentinel), ...(suggestedAutomations ? { suggestedAutomations } : {}) } };
      }
      throw new SentinelRequestError("Use GET or POST for Sentinels.", 405);
    }
    if (path === "sentinels/usage") {
      if (method !== "GET") throw new SentinelRequestError("Use GET to read usage.", 405);
      return { status: 200, data: this.#usage() };
    }
    const match = path.match(/^sentinels\/([^/]+)(?:\/(.*))?$/);
    if (!match) throw new SentinelRequestError("Unknown Sentinel route.", 404);
    const id = parse(idSchema, decodeURIComponent(match[1]!));
    const rest = match[2];
    if (rest === undefined) {
      if (method === "GET") return { status: 200, data: { sentinel: this.#view(this.#requireSentinel(id)) } };
      if (method === "PATCH") { this.#requireWriter(actor); return { status: 200, data: { sentinel: this.#view(this.#store.update(id, input)) } }; }
      if (method === "DELETE") {
        this.#requireWriter(actor);
        const sentinel = this.#requireSentinel(id);
        if (actor?.role === "editor" && sentinel.owner !== actor.userId) throw new SentinelRequestError("Only the owner or a workspace owner can delete this Sentinel.", 403);
        if (!query.has("version")) throw new SentinelRequestError("Deleting requires the reviewed Sentinel version.", 409);
        this.#store.delete(id, parse(z.number().int().positive(), Number(query.get("version"))));
        // Hard delete detaches the automations it owned so no dangling ownerSentinelId survives; triggers went with the record.
        const detached = this.#workflows.clearOwnerSentinel(id);
        return { status: 200, data: { ok: true, detachedAutomations: detached } };
      }
      throw new SentinelRequestError("Use GET, PATCH or DELETE for a Sentinel.", 405);
    }
    if ((rest === "pause" || rest === "resume") && method === "POST") {
      this.#requireWriter(actor);
      const body = parse(z.object({ version: z.number().int().positive().optional(), acknowledge: z.boolean().optional() }).strict(), bodyOf(input));
      if (rest === "pause" && body.acknowledge) throw new SentinelRequestError("Acknowledge applies to resume.", 400);
      return { status: 200, data: { sentinel: this.#view(this.#store.setStatus(id, rest === "pause" ? "paused" : "active", body.version, body.acknowledge === true)) } };
    }
    if (rest === "acknowledge" && method === "POST") {
      this.#requireWriter(actor);
      const { version } = parse(z.object({ version: z.number().int().positive().optional() }).strict(), bodyOf(input));
      return { status: 200, data: { sentinel: this.#view(this.#store.acknowledge(id, version)) } };
    }
    if (rest === "triggers" || rest.startsWith("triggers/")) return await this.#triggers(id, rest === "triggers" ? "" : rest.slice("triggers/".length), method, input, actor);
    if (rest === "thread" && method === "POST") {
      this.#requireWriter(actor);
      this.#requireSentinel(id);
      try {
        const { missionId, created } = await this.#runner.ensureThread(id, actor);
        return { status: created ? 201 : 200, data: { missionId, sentinel: this.#view(this.#requireSentinel(id)) } };
      } catch (error) { if (error instanceof SentinelRunError) throw new SentinelRequestError(error.message, error.statusCode); throw error; }
    }
    if (rest === "run" && method === "POST") { this.#requireWriter(actor); return await this.#run(id, input, actor); }
    if (rest === "activations" && method === "GET") {
      this.#requireSentinel(id);
      const limit = query.has("limit") ? parse(z.number().int().min(1).max(200), Number(query.get("limit"))) : 50;
      return { status: 200, data: { activations: this.#store.listActivations(id, limit) } };
    }
    if (rest === "turns" && method === "GET") {
      this.#requireSentinel(id);
      const limit = query.has("limit") ? parse(z.number().int().min(1).max(200), Number(query.get("limit"))) : 50;
      return { status: 200, data: { turns: this.#store.listTurns(id, limit) } };
    }
    if (rest === "automations" && method === "GET") { this.#requireSentinel(id); return { status: 200, data: { automations: this.#automations(id) } }; }
    if (rest === "files" || rest.startsWith("files/")) return this.#files(id, rest === "files" ? "" : rest.slice("files/".length), method, input, query, actor);
    throw new SentinelRequestError("Unsupported Sentinel action.", 405);
  }

  #triggerView(trigger: SentinelTrigger) {
    const resultsLabel = (mode: string | undefined) => (mode && mode !== "off" ? `, results to GitHub: ${mode === "sarif" ? "code scanning" : mode === "comment" ? "comment" : "code scanning and comment"}` : "");
    const { activeClaim: _claim, ...visible } = trigger;
    const summary = trigger.schedule ? describeSentinelSchedule(trigger.schedule)
      : trigger.release ? `${trigger.release.on === "tag" ? "Tags" : "Releases"} on ${trigger.release.repo}${trigger.release.tagPrefix ? `, starting with ${trigger.release.tagPrefix}` : ""}${trigger.release.report !== "none" ? `, reports as ${trigger.release.report}` : ""}${resultsLabel(trigger.release.results)}`
      : trigger.check ? `${trigger.check.conclusion === "failure" ? "Failed checks" : "Finished checks"} on ${trigger.check.repo}${trigger.check.branch ? ` (${trigger.check.branch})` : ""}${trigger.check.report !== "none" ? `, reports as ${trigger.check.report}` : ""}${resultsLabel(trigger.check.results)}`
      : trigger.github ? `Pull requests on ${trigger.github.repo}${trigger.github.commentOnPr ? ", comments on" : ""}${trigger.github.includeForks ? ", forks included" : ""}${resultsLabel(trigger.github.results)}`
      : trigger.bitbucket ? `Bitbucket ${trigger.bitbucket.platform === "cloud" ? "Cloud" : "Data Center"} pull requests in ${trigger.bitbucket.repo} (${trigger.bitbucket.events.join(" and ")}), reports as ${[trigger.bitbucket.comments ? "comments" : "", trigger.bitbucket.insights ? "Code Insights" : ""].filter(Boolean).join(" and ") || "nothing"}`
      : trigger.webhook ? `Signed calls to /api/webhooks/trigger/${trigger.id} (${trigger.webhook.label})`
      : undefined;
    return { ...visible, ...(summary ? { summary } : {}) };
  }

  /** Triggers start runs of an owned automation. Enabling one needs the same explicit review approval schedules use. */
  async #triggers(id: string, triggerId: string, method: string, input: unknown, actor?: SentinelActor): Promise<{ status: number; data: unknown }> {
    const sentinel = this.#requireSentinel(id);
    if (!triggerId) {
      if (method === "GET") return { status: 200, data: { triggers: this.#store.listTriggers(id).map(trigger => this.#triggerView(trigger)) } };
      if (method !== "POST") throw new SentinelRequestError("Use GET or POST for triggers.", 405);
      this.#requireWriter(actor);
      const { approval, ...fields } = bodyOf(input);
      if (fields.enabled === true && approval !== "enable-reviewed-trigger") throw new SentinelRequestError("Review this trigger before enabling it.", 400);
      if (sentinel.status === "archived") throw new SentinelRequestError("Archived Sentinels cannot have triggers.", 409);
      const automationId = typeof fields.automationId === "string" ? fields.automationId : "";
      const automation = automationId ? this.#workflows.get(automationId) : null;
      if (!automation) throw new SentinelRequestError("Automation not found.", 404);
      if (automation.ownerSentinelId !== id) throw new SentinelRequestError("This automation is not owned by this Sentinel.", 409);
      return { status: 201, data: { trigger: this.#triggerView(this.#store.createTrigger(id, fields, this.#now())) } };
    }
    const checkNow = triggerId.endsWith("/check");
    if (checkNow) triggerId = triggerId.slice(0, -"/check".length);
    const trigger = this.#store.getTrigger(triggerId);
    if (!trigger || trigger.sentinelId !== id) throw new SentinelRequestError("Trigger not found.", 404);
    this.#requireWriter(actor);
    if (method === "PATCH") {
      const { approval, expectedVersion, ...patch } = bodyOf(input);
      const body = parse(z.object({ dailyBudgetUsd: budgetCapSchema.nullable().optional(), monthlyBudgetUsd: budgetCapSchema.nullable().optional(), runBudgetUsd: z.number().optional(), runModel: z.unknown().optional(), enabled: z.boolean().optional(), schedule: z.unknown().optional(), github: z.unknown().optional(), release: z.unknown().optional(), check: z.unknown().optional(), webhook: z.unknown().optional(), bitbucket: z.unknown().optional() }).strict(), patch);
      if (body.enabled === true && approval !== "enable-reviewed-trigger") throw new SentinelRequestError("Review this trigger before enabling it.", 400);
      const version = expectedVersion === undefined ? undefined : parse(z.number().int().positive(), expectedVersion);
      return { status: 200, data: { trigger: this.#triggerView(this.#store.updateTrigger(triggerId, body, version, this.#now())) } };
    }
    if (method === "POST" && checkNow) {
      if (trigger.kind === "schedule" || trigger.kind === "manual" || trigger.kind === "webhook") throw new SentinelRequestError("Only GitHub and Bitbucket triggers can be checked now.", 400);
      if (!await this.#runner.checkNow(triggerId)) throw new SentinelRequestError("Turn the trigger on and wait for any run in progress, then check again.", 409);
      return { status: 202, data: { trigger: this.#triggerView(this.#store.getTrigger(triggerId)!) } };
    }
    if (method === "DELETE") {
      if (!this.#store.deleteTrigger(triggerId)) throw new SentinelRequestError("Trigger is launching a run; try again in a moment.", 409);
      return { status: 200, data: { ok: true } };
    }
    throw new SentinelRequestError("Use PATCH or DELETE for a trigger.", 405);
  }

  #files(id: string, rawPath: string, method: string, input: unknown, query: URLSearchParams, actor?: SentinelActor): { status: number; data: unknown } {
    this.#requireSentinel(id);
    if (!rawPath) {
      if (method !== "GET") throw new SentinelRequestError("Use GET to list files.", 405);
      return { status: 200, data: { files: this.#store.listFiles(id), folders: SENTINEL_FILE_FOLDERS } };
    }
    const path = rawPath.split("/").map(part => { try { return decodeURIComponent(part); } catch { throw new SentinelRequestError("Invalid file path.", 400); } }).join("/");
    if (method === "GET") {
      const file = this.#store.getFile(id, path);
      if (!file) throw new SentinelRequestError("File not found.", 404);
      return { status: 200, data: { file, ...(query.get("revisions") === "1" ? { revisions: this.#store.listFileRevisions(id, path) } : {}) } };
    }
    this.#requireWriter(actor);
    if (method === "PUT") {
      const body = parse(z.object({ content: z.string(), revision: z.number().int().positive().nullable() }).strict(), input);
      const author = actor?.userId ?? "local";
      return { status: body.revision === null ? 201 : 200, data: { file: this.#store.putFile(id, path, body.content, body.revision, "human", author) } };
    }
    if (method === "DELETE") {
      const revision = query.has("revision") ? parse(z.number().int().positive(), Number(query.get("revision"))) : undefined;
      if (revision === undefined) throw new SentinelRequestError("Deleting requires the reviewed file revision.", 409);
      if (!this.#store.deleteFile(id, path, revision)) throw new SentinelRequestError("File not found.", 404);
      return { status: 200, data: { ok: true } };
    }
    throw new SentinelRequestError("Use GET, PUT or DELETE for a file.", 405);
  }

  /**
   * "Run now" / a task from the old composer. With the standing thread on (the default) this is a person's message sent into the
   * Sentinel's one thread; the response keeps an `activation` shape for older clients for one release. With it off it starts a child thread as before.
   */
  async #run(id: string, input: unknown, actor?: SentinelActor): Promise<{ status: number; data: unknown }> {
    const body = parse(z.object({ approval: z.literal("launch-authorized-run"), version: z.number().int().positive(), task: z.string().trim().max(4_000).optional() }).strict(), bodyOf(input));
    const sentinel = this.#requireSentinel(id);
    if (sentinel.version !== body.version) throw new SentinelRequestError("Sentinel changed. Review it again before running.", 409);
    if (this.#runner.persistentThread) {
      try {
        const { missionId, queued } = await this.#runner.sendToThread(id, { ...(body.task ? { text: body.task } : {}), ...(actor ? { actor } : {}) });
        return { status: 202, data: { missionId, queued, activation: { id: missionId, sentinelId: id, status: queued ? "queued" : "running", missionId, trigger: { kind: "manual" } }, sentinel: this.#view(this.#requireSentinel(id)) } };
      } catch (error) { if (error instanceof SentinelRunError) throw new SentinelRequestError(error.message, error.statusCode); throw error; }
    }
    let activation: SentinelActivation;
    try { activation = await this.#runner.launch(id, { trigger: { kind: "manual" }, ...(body.task ? { task: body.task } : {}), ...(actor ? { actor } : {}), autonomous: false }); }
    catch (error) { if (error instanceof SentinelRunError) throw new SentinelRequestError(error.message, error.statusCode); throw error; }
    return { status: 202, data: { activation, sentinel: this.#view(this.#requireSentinel(id)) } };
  }
}
