/** Baselines: save a run's pass rates, compare a later run against them. Only rates and counts are stored, no traces or canaries. */
import type { Parsed } from "./suite.js";
import type { SuiteResults } from "./types.js";

export interface Baseline {
  version: 1;
  suite: string;
  /** Per (agent|case): conclusive pass rate, runs and how many of them were inconclusive. */
  cells: Record<string, { passRate: number | null; runs: number; inconclusive: number }>;
  agents: Record<string, { securityPassRate: number | null; utilityPassRate: number | null; secureAndUseful: number | null; runs: number; inconclusiveRate: number | null }>;
}

export interface Delta { agentId: string; caseId?: string; metric: string; baseline: number | null; current: number | null; delta: number | null }
export interface Comparison { regressions: Delta[]; improvements: Delta[] }

const cellKey = (agentId: string, caseId: string): string => `${agentId}|${caseId}`;
const MAX_ENTRIES = 40_000;
const ID = /^[A-Za-z0-9_.:-]{1,64}$/;

export function toBaseline(results: SuiteResults): Baseline {
  return {
    version: 1, suite: results.suite,
    cells: Object.fromEntries(results.cells.map(c => [cellKey(c.agentId, c.caseId), { passRate: c.passRate, runs: c.runs, inconclusive: c.inconclusive }])),
    agents: Object.fromEntries(results.agents.map(a => [a.agentId, { securityPassRate: a.securityPassRate, utilityPassRate: a.utilityPassRate, secureAndUseful: a.secureAndUseful, runs: a.runs, inconclusiveRate: a.inconclusiveRate }])),
  };
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const rateOrNull = (v: unknown): v is number | null => v === null || (typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 1);
const count = (v: unknown, max = 100_000): v is number => typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= max;
const only = (o: Record<string, unknown>, keys: string[]): boolean => Object.keys(o).length === keys.length && keys.every(k => Object.prototype.hasOwnProperty.call(o, k));

/** Validates a baseline read from disk (an object or JSON text) before any comparison: shape, version, suite name, finite rates, sane counts. */
export function parseBaseline(input: unknown, expectedSuite?: string): Parsed<Baseline> {
  let value = input;
  if (typeof input === "string") {
    if (input.length > 5_000_000) return { ok: false, error: "the baseline text is too large" };
    try { value = JSON.parse(input); } catch { return { ok: false, error: "the baseline is not valid JSON" }; }
  }
  const no = (error: string): Parsed<Baseline> => ({ ok: false, error: `baseline ${error}` });
  if (!isObject(value) || !only(value, ["version", "suite", "cells", "agents"])) return no("must be an object with version, suite, cells and agents");
  if (value.version !== 1) return no("version must be 1");
  if (typeof value.suite !== "string" || !ID.test(value.suite)) return no("suite must be a suite name");
  if (expectedSuite !== undefined && value.suite !== expectedSuite) return no(`is for suite '${value.suite.slice(0, 64)}', not '${expectedSuite.slice(0, 64)}'`);
  if (!isObject(value.cells) || !isObject(value.agents)) return no("cells and agents must be objects");
  const cells = Object.entries(value.cells); const agents = Object.entries(value.agents);
  if (cells.length > MAX_ENTRIES || agents.length > MAX_ENTRIES) return no("has too many entries");
  const out: Baseline = { version: 1, suite: value.suite, cells: {}, agents: {} };
  for (const [key, entry] of cells) {
    const parts = key.split("|");
    if (parts.length !== 2 || !ID.test(parts[0]!) || !ID.test(parts[1]!)) return no(`has a bad cell key '${key.slice(0, 40)}'`);
    if (!isObject(entry) || !only(entry, ["passRate", "runs", "inconclusive"]) || !rateOrNull(entry.passRate) || !count(entry.runs) || !count(entry.inconclusive) || entry.inconclusive > entry.runs) return no(`has a malformed cell '${key.slice(0, 40)}'`);
    out.cells[key] = { passRate: entry.passRate, runs: entry.runs, inconclusive: entry.inconclusive };
  }
  for (const [id, entry] of agents) {
    if (!ID.test(id)) return no(`has a bad agent id '${id.slice(0, 40)}'`);
    if (!isObject(entry) || !only(entry, ["securityPassRate", "utilityPassRate", "secureAndUseful", "runs", "inconclusiveRate"])
      || !rateOrNull(entry.securityPassRate) || !rateOrNull(entry.utilityPassRate) || !rateOrNull(entry.secureAndUseful) || !count(entry.runs) || !rateOrNull(entry.inconclusiveRate)) return no(`has a malformed agent '${id.slice(0, 40)}'`);
    out.agents[id] = { securityPassRate: entry.securityPassRate, utilityPassRate: entry.utilityPassRate, secureAndUseful: entry.secureAndUseful, runs: entry.runs, inconclusiveRate: entry.inconclusiveRate };
  }
  return { ok: true, value: out };
}

export interface CompareOptions {
  /** Absolute change in a pass rate that is ignored. Default 0. */
  tolerance?: number;
  /** Absolute rise in an inconclusive rate that counts as a regression. Default 0.2. */
  inconclusiveTolerance?: number;
}

/**
 * Lists drops and gains beyond `tolerance` (an absolute difference in rate, default 0). A baseline entry that is now unmeasured or
 * absent counts as a regression; silence must not read as green. A rise in the inconclusive rate beyond `inconclusiveTolerance` and
 * fewer runs than the baseline are regressions too: a pass rate from fewer or mostly inconclusive runs is weaker evidence. Entries new
 * in the results are not compared. A baseline that fails parseBaseline for this suite throws.
 */
export function compareToBaseline(results: SuiteResults, baseline: Baseline, options: CompareOptions = {}): Comparison {
  const checked = parseBaseline(baseline, results.suite);
  if (!checked.ok) throw new Error(checked.error);
  const base = checked.value;
  const tolerance = options.tolerance ?? 0; const inconclusiveTolerance = options.inconclusiveTolerance ?? 0.2;
  if (![tolerance, inconclusiveTolerance].every(n => Number.isFinite(n) && n >= 0)) throw new Error("tolerances must be finite and not negative");
  const regressions: Delta[] = []; const improvements: Delta[] = [];
  const consider = (target: { agentId: string; caseId?: string; metric: string }, before: number | null, now: number | null) => {
    if (before === null) return;
    if (now === null) { regressions.push({ ...target, baseline: before, current: null, delta: null }); return; }
    const delta = now - before;
    if (delta < -tolerance - 1e-12) regressions.push({ ...target, baseline: before, current: now, delta });
    else if (delta > tolerance + 1e-12) improvements.push({ ...target, baseline: before, current: now, delta });
  };
  // Lower is better: only a rise beyond the tolerance is reported.
  const worse = (target: { agentId: string; caseId?: string; metric: string }, before: number | null, now: number | null) => {
    if (before === null || now === null) return;
    if (now - before > inconclusiveTolerance + 1e-12) regressions.push({ ...target, baseline: before, current: now, delta: now - before });
  };
  const fewer = (target: { agentId: string; caseId?: string; metric: string }, before: number, now: number) => {
    if (now < before) regressions.push({ ...target, baseline: before, current: now, delta: now - before });
  };
  for (const [key, entry] of Object.entries(base.cells)) {
    const [agentId = "", caseId = ""] = key.split("|");
    const cell = results.cells.find(c => c.agentId === agentId && c.caseId === caseId);
    consider({ agentId, caseId, metric: "passRate" }, entry.passRate, cell ? cell.passRate : null);
    if (!cell) continue;
    worse({ agentId, caseId, metric: "inconclusiveRate" }, entry.runs === 0 ? null : entry.inconclusive / entry.runs, cell.runs === 0 ? null : cell.inconclusive / cell.runs);
    fewer({ agentId, caseId, metric: "runs" }, entry.runs, cell.runs);
  }
  for (const [agentId, entry] of Object.entries(base.agents)) {
    const agent = results.agents.find(a => a.agentId === agentId);
    for (const metric of ["securityPassRate", "utilityPassRate", "secureAndUseful"] as const) consider({ agentId, metric }, entry[metric], agent ? agent[metric] : null);
    if (!agent) continue;
    worse({ agentId, metric: "inconclusiveRate" }, entry.inconclusiveRate, agent.inconclusiveRate);
    fewer({ agentId, metric: "runs" }, entry.runs, agent.runs);
  }
  return { regressions, improvements };
}
