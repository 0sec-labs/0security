/**
 * The public contract between the open client and a hosted attack brain, version 1. It is deliberately narrow: a request carries
 * only the SHAPE of an agent (tool names with a coarse privilege and gate, kinds of input sources), never source code, paths,
 * prompts or secrets, so there is nothing sensitive to leak. Validation is strict and hand-written: an unknown field anywhere is
 * an error, because an open field is where data gets smuggled out. The same validators check the request before it is sent and
 * the response before it is trusted, so a hostile or broken server cannot feed the client arbitrary structure. Text fields may not
 * hold control characters (other than newline and tab) or ANSI escapes.
 *
 * Payloads from a remote brain are hostile by design: run them only against decoy or sandboxed tools, never against an agent wired to
 * real credentials, files or services.
 */
import { CANARY_PLACEHOLDER } from "../scenario.js";

export const PRIVILEGES = ["read-local", "write-local", "network-out", "exec", "credentialed", "none"] as const;
export const GATES = ["none", "allowlist", "approval", "sandbox"] as const;
export const SOURCE_KINDS = ["user-message", "web", "email", "document", "tool-result", "memory", "repository", "other"] as const;
export const DIFFICULTIES = ["basic", "intermediate", "advanced"] as const;
export type BrainPrivilege = (typeof PRIVILEGES)[number];
export type BrainGate = (typeof GATES)[number];
export type SourceKind = (typeof SOURCE_KINDS)[number];

export const LIMITS = { tools: 64, sources: 16, count: 20, framework: 64, scenarios: 50, id: 64, goal: 300, payload: 2000, success: 500, tags: 8, tagField: 64, watermark: 256 } as const;

export interface BrainManifest { tools: { name: string; privilege: BrainPrivilege; gate: BrainGate }[]; sources: { kind: SourceKind }[] }
export interface ScenarioRequest { v: 1; task: "scenarios"; manifest: BrainManifest; framework?: string; count?: number }
export interface BrainScenario { id: string; goal: string; injection_point_kind: SourceKind; payload: string; success: string; tags: { framework: string; id: string }[]; difficulty: (typeof DIFFICULTIES)[number] }
export interface ScenarioResponse { v: 1; task: "scenarios"; scenarios: BrainScenario[]; watermark?: string }

export type Checked<T> = { ok: true; value: T } | { ok: false; error: string };

const TOOL_NAME = /^[A-Za-z0-9_.:-]{1,64}$/;
const FRAMEWORK = /^[A-Za-z0-9 _.:()-]{1,64}$/;
const SCENARIO_ID = /^[A-Za-z0-9_.:-]{1,64}$/;

/** C0 and C1 controls other than newline and tab, which includes ESC, so a server cannot rewrite what the terminal shows. */
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/;

class Invalid extends Error {}
const fail = (message: string): never => { throw new Invalid(message); };
const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

/** An object with exactly the allowed keys: an extra key is rejected rather than ignored. */
function exact(value: unknown, where: string, allowed: readonly string[]): Record<string, unknown> {
  if (!isObject(value)) return fail(`${where} must be an object`);
  for (const key of Object.keys(value)) if (!allowed.includes(key)) fail(`${where} has an unknown field '${key.slice(0, 40)}'`);
  return value;
}
function oneOf<T extends string>(value: unknown, where: string, allowed: readonly T[]): T {
  if (typeof value !== "string" || !(allowed as readonly string[]).includes(value)) return fail(`${where} must be one of: ${allowed.join(", ")}`);
  return value as T;
}
function text(value: unknown, where: string, max: number, pattern?: RegExp): string {
  if (typeof value !== "string" || value.length === 0) return fail(`${where} must be a non-empty string`);
  if (value.length > max) return fail(`${where} is longer than ${max} characters`);
  if (CONTROL.test(value)) return fail(`${where} contains a control character`);
  if (pattern && !pattern.test(value)) return fail(`${where} has characters that are not allowed`);
  return value;
}
function list(value: unknown, where: string, max: number): unknown[] {
  if (!Array.isArray(value)) return fail(`${where} must be a list`);
  if (value.length > max) return fail(`${where} has more than ${max} entries`);
  return value;
}
function check<T>(read: () => T): Checked<T> {
  try { return { ok: true, value: read() }; } catch (error) { if (error instanceof Invalid) return { ok: false, error: error.message }; throw error; }
}

export function validateRequest(input: unknown): Checked<ScenarioRequest> {
  return check(() => {
    const body = exact(input, "request", ["v", "task", "manifest", "framework", "count"]);
    if (body["v"] !== 1) fail("request.v must be 1");
    if (body["task"] !== "scenarios") fail("request.task must be 'scenarios'");
    const manifest = exact(body["manifest"], "manifest", ["tools", "sources"]);
    const tools = list(manifest["tools"], "manifest.tools", LIMITS.tools).map((raw, index) => {
      const tool = exact(raw, `manifest.tools[${index}]`, ["name", "privilege", "gate"]);
      return { name: text(tool["name"], `manifest.tools[${index}].name`, 64, TOOL_NAME), privilege: oneOf(tool["privilege"], `manifest.tools[${index}].privilege`, PRIVILEGES), gate: oneOf(tool["gate"], `manifest.tools[${index}].gate`, GATES) };
    });
    const sources = list(manifest["sources"], "manifest.sources", LIMITS.sources).map((raw, index) => ({ kind: oneOf(exact(raw, `manifest.sources[${index}]`, ["kind"])["kind"], `manifest.sources[${index}].kind`, SOURCE_KINDS) }));
    const request: ScenarioRequest = { v: 1, task: "scenarios", manifest: { tools, sources } };
    if (body["framework"] !== undefined) request.framework = text(body["framework"], "framework", LIMITS.framework, FRAMEWORK);
    if (body["count"] !== undefined) {
      const count = body["count"];
      if (typeof count !== "number" || !Number.isInteger(count) || count < 1 || count > LIMITS.count) fail(`count must be a whole number from 1 to ${LIMITS.count}`);
      request.count = count as number;
    }
    return request;
  });
}

export function validateResponse(input: unknown): Checked<ScenarioResponse> {
  return check(() => {
    const body = exact(input, "response", ["v", "task", "scenarios", "watermark"]);
    if (body["v"] !== 1) fail("response.v must be 1");
    if (body["task"] !== "scenarios") fail("response.task must be 'scenarios'");
    const scenarios = list(body["scenarios"], "response.scenarios", LIMITS.scenarios).map((raw, index): BrainScenario => {
      const where = `scenarios[${index}]`;
      const item = exact(raw, where, ["id", "goal", "injection_point_kind", "payload", "success", "tags", "difficulty"]);
      const payload = text(item["payload"], `${where}.payload`, LIMITS.payload);
      if (!payload.includes(CANARY_PLACEHOLDER)) fail(`${where}.payload must contain ${CANARY_PLACEHOLDER}`);
      const tags = list(item["tags"], `${where}.tags`, LIMITS.tags).map((tag, tagIndex) => {
        const entry = exact(tag, `${where}.tags[${tagIndex}]`, ["framework", "id"]);
        return { framework: text(entry["framework"], `${where}.tags[${tagIndex}].framework`, LIMITS.tagField), id: text(entry["id"], `${where}.tags[${tagIndex}].id`, LIMITS.tagField) };
      });
      return { id: text(item["id"], `${where}.id`, LIMITS.id, SCENARIO_ID), goal: text(item["goal"], `${where}.goal`, LIMITS.goal), injection_point_kind: oneOf(item["injection_point_kind"], `${where}.injection_point_kind`, SOURCE_KINDS), payload, success: text(item["success"], `${where}.success`, LIMITS.success), tags, difficulty: oneOf(item["difficulty"], `${where}.difficulty`, DIFFICULTIES) };
    });
    const response: ScenarioResponse = { v: 1, task: "scenarios", scenarios };
    if (body["watermark"] !== undefined) response.watermark = text(body["watermark"], "watermark", LIMITS.watermark);
    return response;
  });
}
