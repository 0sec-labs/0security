/**
 * Asks a hosted attack brain for scenarios, and falls back to the open starter pack whenever it cannot or must not. The fallback is
 * always announced in `note`: a run that quietly used a different source than the operator expects would be misleading. Only the
 * schema-checked manifest shape leaves the machine; the verdict is computed locally from the agent's recorded calls.
 */
import { enterpriseMode } from "../../policy/enterprise.js";
import { validateRequest, validateResponse, type BrainScenario, type ScenarioRequest } from "./schema.js";
import { starterFor } from "./starter-pack.js";

export const BRAIN_URL_ENV = "ZERO_BRAIN_URL";
export const BRAIN_TOKEN_ENV = "ZERO_BRAIN_TOKEN";
const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_BYTES = 256 * 1024;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

export interface BrainOptions { url?: string; offline?: boolean; timeoutMs?: number; maxBytes?: number }
export interface BrainDeps { env: NodeJS.ProcessEnv; fetch(url: string, init: RequestInit): Promise<Response> }
export interface BrainResult { source: "remote" | "starter-pack"; scenarios: BrainScenario[]; note: string; watermark?: string }

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

/** Remote scenarios when allowed and working, the starter pack otherwise, with the reason. Throws only for an invalid request. */
export async function requestScenarios(input: unknown, options: BrainOptions, deps: BrainDeps): Promise<BrainResult> {
  const checked = validateRequest(input);
  if (!checked.ok) throw new Error(`Invalid request: ${checked.error}`);
  const request = checked.value;
  const starter = (reason: string): BrainResult => ({ source: "starter-pack", scenarios: starterFor(request), note: `${reason} Used the open starter pack instead.` });
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
