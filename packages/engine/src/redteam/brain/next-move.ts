/**
 * Client for the `next-move` task: asks a server for the next message of a multi-turn attacker. Same rules as the scenario client in
 * client.ts: https or loopback only, no redirects, a size cap, the token from ZERO_BRAIN_TOKEN, and silence when offline or in
 * enterprise mode. The server's answer is validated strictly; anything else falls back to a local strategy, with a stated note.
 */
import { enterpriseMode } from "../../policy/enterprise.js";
import { BRAIN_TOKEN_ENV, BRAIN_URL_ENV, brainUrl, type BrainDeps } from "./client.js";
import type { NextMoveRequest, NextMoveResponse } from "./next-move-types.js";

export const MAX_MOVE_MESSAGE = 4000;
export const MAX_MOVE_RATIONALE = 500;
export const MAX_HISTORY_ENTRIES = 40;
export const MAX_HISTORY_TEXT = 2000;
export const MAX_CALL_ARG = 200;
const MAX_CALLS = 40;
const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_BYTES = 64 * 1024;

export interface NextMoveOptions { url?: string; offline?: boolean; timeoutMs?: number; maxBytes?: number }
export type NextMoveResult =
  | { source: "remote"; response: NextMoveResponse; note: string }
  /** The caller must use a local strategy; `note` says why. */
  | { source: "local"; note: string };

export interface NextMoveInput {
  objective: NextMoveRequest["objective"];
  turn: number;
  maxTurns: number;
  history: { role: "attacker" | "agent"; text: string }[];
  calls: { tool: string; privilege: string; args: Record<string, unknown> }[];
}

const clip = (text: string, max: number): string => (text.length > max ? text.slice(0, max) : text);
const asText = (value: unknown): string => (typeof value === "string" ? value : (JSON.stringify(value) ?? ""));

/**
 * The most a request may weigh. The service reads anonymous requests only up to 64 KiB, so the client keeps well inside that:
 * a long conversation sends its newest entries and drops the oldest, instead of being refused.
 */
export const MAX_REQUEST_BYTES = 60_000;
const byteLength = (value: unknown): number => new TextEncoder().encode(JSON.stringify(value)).length;

/** Builds the exact request: the newest 40 history entries with texts clipped to 2000 characters, call arguments clipped to 200, and the oldest entries dropped until the request fits MAX_REQUEST_BYTES (the newest is always kept, clipped if it alone is too big). */
export function buildNextMoveRequest(input: NextMoveInput): NextMoveRequest {
  const request: NextMoveRequest = {
    v: 1, task: "next-move", objective: input.objective, turn: input.turn, maxTurns: input.maxTurns,
    history: input.history.slice(-MAX_HISTORY_ENTRIES).map(entry => ({ role: entry.role, text: clip(entry.text, MAX_HISTORY_TEXT) })),
    calls: input.calls.slice(-MAX_CALLS).map(call => ({
      tool: call.tool, privilege: call.privilege,
      args: Object.fromEntries(Object.entries(call.args).map(([key, value]) => [key, clip(asText(value), MAX_CALL_ARG)])),
    })),
  };
  while (request.history.length > 1 && byteLength(request) > MAX_REQUEST_BYTES) request.history.shift();
  const last = request.history[request.history.length - 1];
  if (last && byteLength(request) > MAX_REQUEST_BYTES) last.text = clip(last.text, 500);
  return request;
}

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029]/;
const KEYS = new Set(["v", "task", "message", "rationale", "done"]);

export function validateNextMoveResponse(value: unknown): { ok: true; value: NextMoveResponse } | { ok: false; error: string } {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return { ok: false, error: "the response is not an object" };
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) if (!KEYS.has(key)) return { ok: false, error: `unknown field ${clip(key, 40)}` };
  if (record["v"] !== 1) return { ok: false, error: "v must be 1" };
  if (record["task"] !== "next-move") return { ok: false, error: "task must be next-move" };
  const { message, rationale, done } = record;
  if (typeof message !== "string" || message.trim() === "") return { ok: false, error: "message must be a non-empty string" };
  if (message.length > MAX_MOVE_MESSAGE) return { ok: false, error: `message is longer than ${MAX_MOVE_MESSAGE} characters` };
  if (CONTROL.test(message)) return { ok: false, error: "message has a control character other than newline or tab" };
  if (rationale !== undefined) {
    if (typeof rationale !== "string") return { ok: false, error: "rationale must be a string" };
    if (rationale.length > MAX_MOVE_RATIONALE) return { ok: false, error: `rationale is longer than ${MAX_MOVE_RATIONALE} characters` };
    if (CONTROL.test(rationale)) return { ok: false, error: "rationale has a control character other than newline or tab" };
  }
  if (done !== undefined && typeof done !== "boolean") return { ok: false, error: "done must be a boolean" };
  return { ok: true, value: { v: 1, task: "next-move", message, ...(rationale !== undefined ? { rationale: rationale as string } : {}), ...(done !== undefined ? { done: done as boolean } : {}) } };
}

const truthy = (value: string | undefined): boolean => { const v = value?.trim().toLowerCase(); return v !== undefined && v !== "" && v !== "0" && v !== "false" && v !== "no"; };

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

/** The server's next move when allowed and working, otherwise `source: "local"` with the reason. Never throws and never sends when offline or in enterprise mode. */
export async function requestNextMove(request: NextMoveRequest, options: NextMoveOptions, deps: BrainDeps): Promise<NextMoveResult> {
  const local = (reason: string): NextMoveResult => ({ source: "local", note: `${reason} Used the local attacker strategy instead.` });
  if (options.offline || truthy(deps.env["ZERO_OFFLINE"])) return local("Offline mode is on, so nothing was sent.");
  if (enterpriseMode(deps.env)) return local("ZERO_ENTERPRISE blocks the hosted brain, so nothing was sent.");
  const raw = options.url ?? deps.env[BRAIN_URL_ENV]?.trim();
  if (!raw) return local(`No brain URL is set (--url or ${BRAIN_URL_ENV}), so nothing was sent.`);
  const token = deps.env[BRAIN_TOKEN_ENV]?.trim() || undefined;
  // An error must never carry the token, whatever the server or the network put in its message.
  const scrub = (message: string) => (token ? message.split(token).join("[token]") : message).slice(0, 300);
  let url: URL;
  try { url = brainUrl(raw); } catch (error) { return local(scrub(error instanceof Error ? error.message : String(error))); }
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
    const checked = validateNextMoveResponse(parsed);
    if (!checked.ok) throw new Error(`the response broke the contract: ${checked.error}`);
    return { source: "remote", response: checked.value, note: `The next move came from the brain at ${url.host}.` };
  } catch (error) {
    return local(`The brain at ${url.host} could not be used (${scrub(error instanceof Error ? error.message : String(error))}).`);
  } finally { clearTimeout(timer); }
}
