/**
 * Asks a hosted attack brain for scenarios, and falls back to the open starter pack whenever it cannot or must not. The fallback is
 * always announced in `note`: a run that quietly used a different source than the operator expects would be misleading. Only the
 * schema-checked manifest shape leaves the machine; the verdict is computed locally from the agent's recorded calls.
 */
import { enterpriseMode } from "../../policy/enterprise.js";
import { catalogScenarios } from "../catalog/scenarios.js";
import { TEMPLATES_BY_ID } from "../catalog/entries/index.js";
import { selectGenerators } from "../catalog/select.js";
import type { Difficulty } from "../catalog/types.js";
import { newCanary } from "../scenario.js";
import { validateRequest, validateResponse, type BrainScenario, type ScenarioRequest } from "./schema.js";
import { starterFor } from "./starter-pack.js";

export const BRAIN_URL_ENV = "ZERO_BRAIN_URL";
export const BRAIN_TOKEN_ENV = "ZERO_BRAIN_TOKEN";
const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_BYTES = 256 * 1024;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** Filters apply to the open catalog fallback only; a remote brain gets the schema-checked request and nothing else. */
export interface CatalogFilter { generators?: string[]; areas?: string[]; difficulties?: Difficulty[] }
export interface BrainOptions { url?: string; offline?: boolean; timeoutMs?: number; maxBytes?: number; filter?: CatalogFilter; /** Only seeds which catalog generators are sampled. */ seed?: string }
export interface BrainDeps { env: NodeJS.ProcessEnv; fetch(url: string, init: RequestInit): Promise<Response> }
export interface BrainResult { source: "remote" | "open-catalog" | "starter-pack"; scenarios: BrainScenario[]; note: string; watermark?: string }

const truthy = (value: string | undefined): boolean => { const v = value?.trim().toLowerCase(); return v !== undefined && v !== "" && v !== "0" && v !== "false" && v !== "no"; };

/** The exact JSON a request would send. Validates first, so a dry run also proves the manifest is acceptable. */
export function dryRun(request: unknown): string {
  const checked = validateRequest(request);
  if (!checked.ok) throw new Error(`Invalid request: ${checked.error}`);
  return JSON.stringify(checked.value, null, 2);
}

/** https only, or plain http to this machine so tests need no certificate. No credentials, query or fragment in the URL. */
export function brainUrl(raw: string): URL {
  let url: URL;
  try { url = new URL(raw); } catch { throw new Error("The brain URL is not a URL."); }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && LOOPBACK.has(url.hostname))) throw new Error("The brain URL must be https (http is allowed only for localhost).");
  if (url.username || url.password) throw new Error("The brain URL must not contain a user name or password; use ZERO_BRAIN_TOKEN.");
  if (url.search || url.hash) throw new Error("The brain URL must not contain a query or fragment.");
  return url;
}

async function readCapped(response: Response, maxBytes: number): Promise<string> {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) throw new Error(`the response is larger than ${maxBytes} bytes`);
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = []; let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) { await reader.cancel().catch(() => undefined); throw new Error(`the response is larger than ${maxBytes} bytes`); }
    chunks.push(value);
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}

async function fromRemote(request: ScenarioRequest, url: URL, token: string | undefined, options: BrainOptions, deps: BrainDeps): Promise<BrainResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  try {
    const response = await deps.fetch(url.toString(), {
      method: "POST", redirect: "manual", signal: controller.signal, body: JSON.stringify(request),
      headers: { "content-type": "application/json", accept: "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    });
    if (response.status >= 300 && response.status < 400) throw new Error("the server answered with a redirect, which is refused");
    if (!response.ok) throw new Error(`the server answered HTTP ${response.status}`);
    const body = await readCapped(response, options.maxBytes ?? DEFAULT_MAX_BYTES);
    let parsed: unknown;
    try { parsed = JSON.parse(body); } catch { throw new Error("the response is not JSON"); }
    const checked = validateResponse(parsed);
    if (!checked.ok) throw new Error(`the response broke the contract: ${checked.error}`);
    const { scenarios, watermark } = checked.value;
    if (scenarios.length === 0) throw new Error("the brain returned no scenarios");
    const trimmed = request.count ? scenarios.slice(0, request.count) : scenarios;
    return { source: "remote", scenarios: trimmed, note: `Scenarios came from the brain at ${url.host}.`, ...(watermark ? { watermark } : {}) };
  } finally { clearTimeout(timer); }
}

const DEFAULT_COUNT = 10;

/** The open catalog scenarios for this manifest, honouring the filters; empty when nothing fits. */
function fromCatalog(request: ScenarioRequest, options: BrainOptions): BrainScenario[] {
  const count = request.count ?? DEFAULT_COUNT;
  const seed = options.seed ?? newCanary();
  const filter = options.filter;
  if (!filter || (!filter.generators?.length && !filter.areas?.length && !filter.difficulties?.length)) return catalogScenarios(request.manifest, seed, count);
  const ids = filter.generators?.length ? new Set(filter.generators) : undefined;
  return selectGenerators(request.manifest, { tiers: ["open", "both"], seed, ...(filter.areas?.length ? { areas: filter.areas } : {}), ...(filter.difficulties?.length ? { difficulties: filter.difficulties } : {}) })
    .filter(spec => !ids || ids.has(spec.id)).slice(0, count).flatMap(spec => {
      const template = TEMPLATES_BY_ID.get(spec.id);
      return template ? [{ id: spec.id, goal: template.goal, injection_point_kind: template.injectionPointKind, payload: template.payload, success: template.success, tags: spec.tags.map(tag => ({ ...tag })), difficulty: spec.difficulty }] : [];
    });
}

/** Remote scenarios when allowed and working, the open catalog otherwise, with the reason. Throws only for an invalid request. */
export async function requestScenarios(input: unknown, options: BrainOptions, deps: BrainDeps): Promise<BrainResult> {
  const checked = validateRequest(input);
  if (!checked.ok) throw new Error(`Invalid request: ${checked.error}`);
  const request = checked.value;
  const starter = (reason: string): BrainResult => {
    const filtered = Boolean(options.filter?.generators?.length || options.filter?.areas?.length || options.filter?.difficulties?.length);
    const scenarios = fromCatalog(request, options);
    if (scenarios.length) return { source: "open-catalog", scenarios, note: `${reason} Used the open catalog instead.` };
    // An empty answer to a filter is the truthful answer; only an unfiltered miss falls back to the small starter pack.
    if (filtered) return { source: "open-catalog", scenarios: [], note: `${reason} The open catalog has no scenario that matches the filters and this manifest.` };
    return { source: "starter-pack", scenarios: starterFor(request), note: `${reason} The open catalog had nothing for this manifest, so used the open starter pack instead.` };
  };
  const raw = options.url ?? deps.env[BRAIN_URL_ENV]?.trim();
  if (options.offline || truthy(deps.env["ZERO_OFFLINE"])) return starter("Offline mode is on, so nothing was sent.");
  if (enterpriseMode(deps.env)) return starter("ZERO_ENTERPRISE blocks the hosted brain, so nothing was sent.");
  if (!raw) return starter(`No brain URL is set (--url or ${BRAIN_URL_ENV}), so nothing was sent.`);
  const token = deps.env[BRAIN_TOKEN_ENV]?.trim() || undefined;
  // An error must never carry the token, whatever the server or the network put in its message.
  const scrub = (message: string) => (token ? message.split(token).join("[token]") : message).slice(0, 300);
  let url: URL;
  try { url = brainUrl(raw); } catch (error) { return starter(`${scrub(error instanceof Error ? error.message : String(error))}`); }
  try { return await fromRemote(request, url, token, options, deps); }
  catch (error) { return starter(`The brain at ${url.host} could not be used (${scrub(error instanceof Error ? error.message : String(error))}).`); }
}
