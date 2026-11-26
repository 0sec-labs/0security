/**
 * Strict suite validator. An unknown field at any level is an error, because an open field is where data gets smuggled; ids are unique;
 * sizes are bounded; text holds no control characters; URLs in payloads and tasks may name reserved hosts only. JSON always; YAML too,
 * since the engine already depends on the `yaml` package.
 */
import { parse as parseYaml } from "yaml";
import { CANARY_PLACEHOLDER } from "../scenario.js";
import type { ArgCondition, OracleSpec } from "../oracle-types.js";
import { INVISIBLE } from "./text-safety.js";
import type { Suite, SuiteAgent, SuiteCase, SuiteKit, Thresholds } from "./types.js";

/** `warnings` is set only when there is something to say; a warning does not make the suite invalid. */
export type Parsed<T> = { ok: true; value: T; warnings?: string[] } | { ok: false; error: string };

export const SUITE_LIMITS = { source: 200_000, agents: 32, kits: 32, cases: 200, toolsPerKit: 32, env: 32, id: 64, command: 500, cwd: 300, description: 300, task: 4000, payload: 2000, oracleText: 500, regex: 100, oracleNodes: 64, oracleDepth: 6, repeats: 20, maxRuns: 10_000, matrix: 10_000, regexUnbounded: 2 } as const;

const ID = /^[A-Za-z0-9_.:-]{1,64}$/;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const PRIVILEGES = ["source", "read-local", "write-local", "network-out", "exec"] as const;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/;
const RESERVED_HOST = /(^|\.)(invalid|test|example|example\.com|example\.org|example\.net)$/i;

class Invalid extends Error {}
const fail = (message: string): never => { throw new Invalid(message); };
const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

function exact(value: unknown, where: string, allowed: readonly string[]): Record<string, unknown> {
  if (!isObject(value)) return fail(`${where} must be an object`);
  for (const key of Object.keys(value)) if (!allowed.includes(key)) fail(`${where} has an unknown field '${key.slice(0, 40)}'`);
  return value;
}
function text(value: unknown, where: string, max: number, pattern?: RegExp): string {
  if (typeof value !== "string" || value.length === 0) return fail(`${where} must be a non-empty string`);
  if (value.length > max) return fail(`${where} is longer than ${max} characters`);
  if (CONTROL.test(value)) return fail(`${where} contains a control character`);
  if (pattern && !pattern.test(value)) return fail(`${where} has characters that are not allowed`);
  return value;
}
const NOT_RESERVED = (where: string): string => `${where} names a host that is not reserved, or hides one behind credentials or a backslash (use .invalid, .test, .example or example.com/org/net)`;
// A scheme with slashes, or a special scheme where the slashes are optional or backslashes (browsers read http:evil.com and http:\\evil.com as hosts).
const SCHEME_URL = /\b(?:(?:https?|wss?|ftp):[\\/]*|[a-z][a-z0-9+.-]*:\/\/)([^\s/?#"'<>]*)/gi;
const PROTOCOL_RELATIVE = /(?:^|[^\p{L}\p{N}:\\/])([\\/]{2})([^\s/?#"'<>]*)/gu;
// Any dotted name that ends in a letters-only label could be a host, whatever surrounds it.
const DOTTED_NAME = /(?<![\p{L}\p{N}-])(?:[\p{L}\p{N}][\p{L}\p{N}-]*\.)+\p{L}{2,63}(?![\p{L}\p{N}-])/giu;
const IPV4 = /(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?!\d)/;
// Extensions that are not top-level domains, so a file name is not mistaken for a host.
const FILE_EXTENSIONS = new Set(["txt", "json", "yaml", "yml", "log", "csv", "js", "mjs", "cjs", "ts", "tsx", "jsx", "html", "htm", "css", "toml", "ini", "cfg", "conf", "env", "pdf", "png", "jpg", "jpeg", "gif", "svg", "xml", "tmp", "bak", "lock"]);

/** True when the authority (host with an optional port, no userinfo) parses to an ASCII hostname under a reserved name. */
function reservedHost(authority: string): boolean {
  let name: string;
  try { name = new URL(`http://${authority}/`).hostname.toLowerCase(); } catch { return false; }
  name = name.replace(/\.$/, "");
  return /^[a-z0-9.-]+$/.test(name) && RESERVED_HOST.test(name);
}

/** Text that may carry URLs: every host must be reserved, so a suite cannot point an agent at a real target. */
function safeText(value: unknown, where: string, max: number): string {
  const out = text(value, where, max);
  if (INVISIBLE.test(out)) fail(`${where} contains an invisible or bidirectional character`);
  // Compatibility forms (fullwidth dots, slashes and backslashes) fold to the characters a URL parser would see.
  const norm = out.normalize("NFKC").replace(/[\u3002\uFF61]/g, ".");
  const bad = (): never => fail(NOT_RESERVED(where));
  for (const match of norm.matchAll(SCHEME_URL)) {
    if (match[0].includes("\\")) bad();
    const authority = match[1]!.replace(/[).,;!\]}]+$/, "");
    if (authority === "") continue;
    if (authority.includes("@") || !reservedHost(authority)) bad();
  }
  for (const match of norm.matchAll(PROTOCOL_RELATIVE)) {
    const authority = match[2]!.replace(/[).,;!\]}]+$/, "");
    if (match[1]!.includes("\\") || authority.includes("\\")) bad();
    if (authority !== "" && (authority.includes("@") || !reservedHost(authority))) bad();
  }
  for (const match of norm.matchAll(DOTTED_NAME)) {
    const name = match[0];
    if (FILE_EXTENSIONS.has(name.slice(name.lastIndexOf(".") + 1).toLowerCase())) continue;
    if (!reservedHost(name)) bad();
  }
  if (IPV4.test(norm)) bad();
  return out;
}
function list(value: unknown, where: string, max: number, min = 0): unknown[] {
  if (!Array.isArray(value)) return fail(`${where} must be an array`);
  if (value.length > max) return fail(`${where} has more than ${max} entries`);
  if (value.length < min) return fail(`${where} must not be empty`);
  return value;
}
function unit(value: unknown, where: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) return fail(`${where} must be a number from 0 to 1`);
  return value;
}
function int(value: unknown, where: string, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) return fail(`${where} must be an integer from ${min} to ${max}`);
  return value;
}

/**
 * The pattern runs against agent-controlled text, so shapes that can backtrack badly are refused: back-references, a group repeated
 * without bound, a repeated group that itself holds a repeat, and more than a few unbounded repeats. Returns the reason, or undefined.
 */
export function unsafeRegex(src: string): string | undefined {
  const stack: boolean[] = [];
  let prev: "none" | "atom" | "group" | "quant" = "none"; let groupHadRepeat = false; let unbounded = 0;
  for (let i = 0; i < src.length; i++) {
    const ch = src[i]!;
    if (ch === "\\") {
      if (/[1-9k]/.test(src[i + 1] ?? "")) return "back-references are not allowed";
      i++; prev = "atom"; continue;
    }
    if (ch === "[") {
      for (i++; i < src.length && src[i] !== "]"; i++) if (src[i] === "\\") i++;
      prev = "atom"; continue;
    }
    if (ch === "(") {
      stack.push(false); prev = "none";
      if (src[i + 1] === "?") {
        const k = src[i + 2];
        if (k === "<" && (src[i + 3] === "=" || src[i + 3] === "!")) i += 3;
        else if (k === "<") { const close = src.indexOf(">", i); i = close < 0 ? src.length : close; } else i += 2;
      }
      continue;
    }
    if (ch === ")") { groupHadRepeat = stack.pop() ?? false; prev = "group"; continue; }
    let quant: "optional" | "bounded" | "unbounded" | undefined;
    if (ch === "*" || ch === "+") quant = "unbounded";
    else if (ch === "?") quant = prev === "quant" ? undefined : "optional";
    else if (ch === "{") {
      const m = /^\{(\d+)(,(\d*))?\}/.exec(src.slice(i));
      if (m) { quant = m[2] !== undefined && m[3] === "" ? "unbounded" : "bounded"; i += m[0].length - 1; }
    }
    if (ch === "|") { prev = "none"; continue; }
    if (quant === undefined) { prev = ch === "?" ? "quant" : "atom"; continue; }
    if (prev === "group") {
      if (quant === "unbounded") return "a group repeated without bound is not allowed";
      if (quant === "bounded" && groupHadRepeat) return "nested repeats are not allowed";
    }
    if (quant === "unbounded" && ++unbounded > SUITE_LIMITS.regexUnbounded) return `more than ${SUITE_LIMITS.regexUnbounded} unbounded repeats`;
    if (quant !== "optional" && stack.length > 0) stack[stack.length - 1] = true;
    prev = "quant";
  }
  return undefined;
}

function condition(value: unknown, where: string): ArgCondition {
  const raw = exact(value, where, ["arg", "contains", "equals", "notEquals", "gt", "lt", "matches"]);
  const out: ArgCondition = { arg: text(raw.arg, `${where}.arg`, SUITE_LIMITS.id, ID) };
  const given = ["contains", "equals", "notEquals", "gt", "lt", "matches"].filter(key => raw[key] !== undefined);
  if (given.length !== 1) fail(`${where} must have exactly one comparison`);
  for (const key of ["contains", "equals", "notEquals"] as const) if (raw[key] !== undefined) out[key] = text(raw[key], `${where}.${key}`, SUITE_LIMITS.oracleText);
  for (const key of ["gt", "lt"] as const) if (raw[key] !== undefined) {
    if (typeof raw[key] !== "number" || !Number.isFinite(raw[key])) fail(`${where}.${key} must be a finite number`);
    out[key] = raw[key] as number;
  }
  if (raw.matches !== undefined) {
    const source = text(raw.matches, `${where}.matches`, SUITE_LIMITS.regex);
    try { new RegExp(source.split(CANARY_PLACEHOLDER).join("CANARY-0")); } catch { fail(`${where}.matches is not a valid regular expression`); }
    const unsafe = unsafeRegex(source);
    if (unsafe !== undefined) fail(`${where}.matches is not safe to run on agent text: ${unsafe}`);
    out.matches = source;
  }
  return out;
}

function oracle(value: unknown, where: string, depth: number, budget: { nodes: number }): OracleSpec {
  if (depth > SUITE_LIMITS.oracleDepth) fail(`${where} is nested deeper than ${SUITE_LIMITS.oracleDepth}`);
  if (++budget.nodes > SUITE_LIMITS.oracleNodes) fail(`an oracle has more than ${SUITE_LIMITS.oracleNodes} nodes`);
  if (!isObject(value)) return fail(`${where} must be an object`);
  switch (value.kind) {
    case "marker-in-sink": {
      const raw = exact(value, where, ["kind", "privileges", "tools"]);
      const out: OracleSpec & { kind: "marker-in-sink" } = { kind: "marker-in-sink" };
      if (raw.privileges !== undefined) out.privileges = list(raw.privileges, `${where}.privileges`, PRIVILEGES.length, 1).map((p, i) => {
        if (typeof p !== "string" || !(PRIVILEGES as readonly string[]).includes(p)) fail(`${where}.privileges[${i}] must be one of: ${PRIVILEGES.join(", ")}`);
        return p as (typeof PRIVILEGES)[number];
      });
      if (raw.tools !== undefined) out.tools = list(raw.tools, `${where}.tools`, SUITE_LIMITS.toolsPerKit, 1).map((t, i) => text(t, `${where}.tools[${i}]`, SUITE_LIMITS.id, ID));
      return out;
    }
    case "tool-called": {
      const raw = exact(value, where, ["kind", "tool", "where"]);
      return { kind: "tool-called", tool: text(raw.tool, `${where}.tool`, SUITE_LIMITS.id, ID), ...(raw.where !== undefined ? { where: condition(raw.where, `${where}.where`) } : {}) };
    }
    case "tool-not-called": {
      const raw = exact(value, where, ["kind", "tool"]);
      return { kind: "tool-not-called", tool: text(raw.tool, `${where}.tool`, SUITE_LIMITS.id, ID) };
    }
    case "sequence": {
      const raw = exact(value, where, ["kind", "steps"]);
      return { kind: "sequence", steps: list(raw.steps, `${where}.steps`, SUITE_LIMITS.oracleNodes, 1).map((s, i) => oracle(s, `${where}.steps[${i}]`, depth + 1, budget)) };
    }
    case "any":
    case "all": {
      const raw = exact(value, where, ["kind", "of"]);
      return { kind: value.kind, of: list(raw.of, `${where}.of`, SUITE_LIMITS.oracleNodes, 1).map((s, i) => oracle(s, `${where}.of[${i}]`, depth + 1, budget)) };
    }
    default: return fail(`${where}.kind must be one of: marker-in-sink, tool-called, tool-not-called, sequence, any, all`);
  }
}

/** Tools every case can use whatever its kits list. */
export const CORE_TOOLS = ["read_file", "read_email", "fetch_url", "write_file", "send_email", "http_post", "run_command"] as const;

/** Every tool an oracle names, with whether it sits under a tool-not-called. */
function oracleTools(spec: OracleSpec, out: { tool: string; negative: boolean }[] = []): { tool: string; negative: boolean }[] {
  switch (spec.kind) {
    case "marker-in-sink": for (const tool of spec.tools ?? []) out.push({ tool, negative: false }); break;
    case "tool-called": out.push({ tool: spec.tool, negative: false }); break;
    case "tool-not-called": out.push({ tool: spec.tool, negative: true }); break;
    case "sequence": for (const step of spec.steps) oracleTools(step, out); break;
    case "any": case "all": for (const step of spec.of) oracleTools(step, out); break;
  }
  return out;
}

function agent(value: unknown, where: string): SuiteAgent {
  const raw = exact(value, where, ["id", "command", "env", "cwd"]);
  const out: SuiteAgent = { id: text(raw.id, `${where}.id`, SUITE_LIMITS.id, ID), command: text(raw.command, `${where}.command`, SUITE_LIMITS.command) };
  if (raw.env !== undefined) {
    out.env = list(raw.env, `${where}.env`, SUITE_LIMITS.env).map((n, i) => text(n, `${where}.env[${i}]`, 64, ENV_NAME));
    if (new Set(out.env).size !== out.env.length) fail(`${where}.env repeats a name`);
  }
  if (raw.cwd !== undefined) {
    out.cwd = text(raw.cwd, `${where}.cwd`, SUITE_LIMITS.cwd);
    if (out.cwd.split(/[\\/]/).includes("..")) fail(`${where}.cwd must not contain a '..' segment`);
  }
  return out;
}

function kit(value: unknown, where: string): SuiteKit {
  const raw = exact(value, where, ["id", "tools"]);
  const tools = list(raw.tools, `${where}.tools`, SUITE_LIMITS.toolsPerKit, 1).map((t, i) => text(t, `${where}.tools[${i}]`, SUITE_LIMITS.id, ID));
  if (new Set(tools).size !== tools.length) fail(`${where}.tools repeats a name`);
  return { id: text(raw.id, `${where}.id`, SUITE_LIMITS.id, ID), tools };
}

function testCase(value: unknown, where: string): SuiteCase {
  const raw = exact(value, where, ["id", "kind", "description", "kits", "payload", "generatorId", "strategyId", "task", "pairedWith", "oracle"]);
  if (raw.kind !== "security" && raw.kind !== "utility") fail(`${where}.kind must be security or utility`);
  const kind = raw.kind as SuiteCase["kind"];
  const out: SuiteCase = {
    id: text(raw.id, `${where}.id`, SUITE_LIMITS.id, ID), kind, description: text(raw.description, `${where}.description`, SUITE_LIMITS.description),
    kits: list(raw.kits, `${where}.kits`, SUITE_LIMITS.kits, 1).map((k, i) => text(k, `${where}.kits[${i}]`, SUITE_LIMITS.id, ID)),
    oracle: oracle(raw.oracle, `${where}.oracle`, 0, { nodes: 0 }),
  };
  if (new Set(out.kits).size !== out.kits.length) fail(`${where}.kits repeats a kit`);
  if (raw.payload !== undefined && raw.generatorId !== undefined) fail(`${where} must not have both payload and generatorId`);
  if (kind === "security" && raw.payload === undefined && raw.generatorId === undefined) fail(`${where} is a security case and needs a payload or a generatorId`);
  if (raw.payload !== undefined) out.payload = safeText(raw.payload, `${where}.payload`, SUITE_LIMITS.payload);
  if (raw.generatorId !== undefined) out.generatorId = text(raw.generatorId, `${where}.generatorId`, SUITE_LIMITS.id, ID);
  if (raw.strategyId !== undefined) out.strategyId = text(raw.strategyId, `${where}.strategyId`, SUITE_LIMITS.id, ID);
  if (raw.task !== undefined) out.task = safeText(raw.task, `${where}.task`, SUITE_LIMITS.task);
  if (raw.pairedWith !== undefined) out.pairedWith = text(raw.pairedWith, `${where}.pairedWith`, SUITE_LIMITS.id, ID);
  return out;
}

function thresholds(value: unknown): Thresholds {
  const raw = exact(value, "thresholds", ["minSecurityPass", "minUtilityPass", "maxInconclusive"]);
  const out: Thresholds = {};
  for (const key of ["minSecurityPass", "minUtilityPass", "maxInconclusive"] as const) if (raw[key] !== undefined) out[key] = unit(raw[key], `thresholds.${key}`);
  return out;
}

function unique(items: { id: string }[], what: string): void {
  const seen = new Set<string>();
  for (const item of items) { if (seen.has(item.id)) fail(`${what} id '${item.id}' is used twice`); seen.add(item.id); }
}

/** Validates an already-parsed value. */
export function validateSuite(value: unknown): Parsed<Suite> {
  try {
    const raw = exact(value, "suite", ["name", "version", "agents", "kits", "cases", "thresholds", "repeats", "maxRuns", "maxCost"]);
    if (raw.version !== 1) fail("suite.version must be 1");
    const suite: Suite = {
      name: text(raw.name, "suite.name", SUITE_LIMITS.id, ID), version: 1,
      agents: list(raw.agents, "suite.agents", SUITE_LIMITS.agents, 1).map((a, i) => agent(a, `agents[${i}]`)),
      kits: list(raw.kits, "suite.kits", SUITE_LIMITS.kits, 1).map((k, i) => kit(k, `kits[${i}]`)),
      cases: list(raw.cases, "suite.cases", SUITE_LIMITS.cases, 1).map((c, i) => testCase(c, `cases[${i}]`)),
    };
    unique(suite.agents, "agent"); unique(suite.kits, "kit"); unique(suite.cases, "case");
    const kitIds = new Set(suite.kits.map(k => k.id));
    const byId = new Map(suite.cases.map(c => [c.id, c] as const));
    for (const c of suite.cases) {
      for (const k of c.kits) if (!kitIds.has(k)) fail(`case '${c.id}' uses an unknown kit '${k}'`);
      if (c.pairedWith !== undefined) {
        const other = byId.get(c.pairedWith);
        if (other === undefined) fail(`case '${c.id}' is paired with an unknown case '${c.pairedWith}'`);
        else if (other.kind === c.kind) fail(`case '${c.id}' must be paired with a case of the other kind`);
        else if (other.pairedWith !== undefined && other.pairedWith !== c.id) fail(`case '${c.pairedWith}' is already paired with another case`);
      }
    }
    // An oracle can only hit a tool the case exposes; a typo or a missing kit would let a security case pass without ever being able to fail.
    const kitTools = new Map(suite.kits.map(k => [k.id, k.tools] as const));
    const warnings: string[] = [];
    for (const c of suite.cases) {
      const available = new Set<string>([...CORE_TOOLS, ...c.kits.flatMap(k => kitTools.get(k) ?? [])]);
      for (const { tool, negative } of oracleTools(c.oracle)) {
        if (!available.has(tool)) fail(`case '${c.id}' oracle names tool '${tool}' that is in none of its kits (core tools: ${CORE_TOOLS.join(", ")})`);
        if (negative && c.kind === "security") warnings.push(`case '${c.id}' is a security case with a tool-not-called oracle on '${tool}': it hits when the tool is absent, so an agent that does nothing fails it`);
      }
    }
    // Two cases naming the same unpaired partner would make a pair ambiguous.
    const claimed = new Set<string>();
    for (const c of suite.cases) if (c.pairedWith !== undefined && byId.get(c.pairedWith)!.pairedWith === undefined) {
      if (claimed.has(c.pairedWith)) fail(`case '${c.pairedWith}' is paired by more than one case`);
      claimed.add(c.pairedWith);
    }
    if (raw.thresholds !== undefined) suite.thresholds = thresholds(raw.thresholds);
    if (raw.repeats !== undefined) suite.repeats = int(raw.repeats, "suite.repeats", 1, SUITE_LIMITS.repeats);
    if (raw.maxRuns !== undefined) suite.maxRuns = int(raw.maxRuns, "suite.maxRuns", 1, SUITE_LIMITS.maxRuns);
    if (raw.maxCost !== undefined) {
      if (typeof raw.maxCost !== "number" || !Number.isFinite(raw.maxCost) || raw.maxCost <= 0) fail("suite.maxCost must be a positive number");
      suite.maxCost = raw.maxCost as number;
    }
    const runs = suite.agents.length * suite.cases.length * (suite.repeats ?? 1);
    if (runs > SUITE_LIMITS.matrix) fail(`the matrix is ${suite.agents.length} agents x ${suite.cases.length} cases x ${suite.repeats ?? 1} repeats = ${runs} runs, more than the limit of ${SUITE_LIMITS.matrix}`);
    return { ok: true, value: suite, ...(warnings.length ? { warnings } : {}) };
  } catch (error) {
    if (error instanceof Invalid) return { ok: false, error: error.message };
    throw error;
  }
}

/** Finds a duplicate object key in JSON text that JSON.parse already accepted; returns the key, or undefined. */
export function duplicateJsonKey(source: string): string | undefined {
  const frames: ({ keys: Set<string>; expectKey: boolean } | null)[] = [];
  for (let i = 0; i < source.length; i++) {
    const ch = source[i]!;
    if (ch === "{") frames.push({ keys: new Set(), expectKey: true });
    else if (ch === "[") frames.push(null);
    else if (ch === "}" || ch === "]") frames.pop();
    else if (ch === ",") { const top = frames[frames.length - 1]; if (top) top.expectKey = true; }
    else if (ch === '"') {
      let end = i + 1;
      while (end < source.length && source[end] !== '"') end += source[end] === "\\" ? 2 : 1;
      const top = frames[frames.length - 1];
      if (top?.expectKey) {
        const key = JSON.parse(source.slice(i, end + 1)) as string;
        if (top.keys.has(key)) return key;
        top.keys.add(key); top.expectKey = false;
      }
      i = end;
    }
  }
  return undefined;
}

/** Parses suite text: JSON when it starts with a brace, YAML otherwise (anchors capped, duplicate keys rejected). */
export function parseSuite(source: string): Parsed<Suite> {
  if (typeof source !== "string" || source.length > SUITE_LIMITS.source) return { ok: false, error: `the suite text must be a string of at most ${SUITE_LIMITS.source} characters` };
  let value: unknown;
  try {
    if (source.trimStart().startsWith("{")) {
      value = JSON.parse(source);
      const duplicate = duplicateJsonKey(source);
      if (duplicate !== undefined) return { ok: false, error: `the suite JSON repeats the key '${duplicate.slice(0, 40)}'` };
    } else value = parseYaml(source, { maxAliasCount: 10, uniqueKeys: true });
  } catch (error) {
    return { ok: false, error: `the suite is not valid JSON or YAML: ${(error instanceof Error ? error.message : "parse error").slice(0, 200)}` };
  }
  return validateSuite(value);
}
