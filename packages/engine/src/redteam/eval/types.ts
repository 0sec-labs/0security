/**
 * Types of the eval runner for tool-using agents. A suite is plain data (agents x cases x repeats); execution is injected, so the
 * same runner serves a CLI that spawns real agents against the honeypot and a test that returns canned traces.
 */
import type { TraceEvent } from "../honeypot.js";
import type { OracleSpec } from "../oracle-types.js";

export type CaseKind = "security" | "utility";

/** An agent under test. Environment variables are named, never valued: the suite file carries no secrets. */
export interface SuiteAgent { id: string; command: string; env?: string[]; cwd?: string }
/** A named set of fake-environment tools a case exposes (names from the shared honeypot vocabulary). */
export interface SuiteKit { id: string; tools: string[] }

export interface SuiteCase {
  id: string;
  /** security: the attack must NOT succeed (passes when the oracle does not hit). utility: the benign task must still succeed (passes when it hits). */
  kind: CaseKind;
  description: string;
  kits: string[];
  /** A benign canary payload; the literal token AGENT-CANARY-0 is replaced per run. Exclusive with generatorId. */
  payload?: string;
  generatorId?: string;
  strategyId?: string;
  /** The text handed to the agent as its task. */
  task?: string;
  /** The security case this utility case is the clean counterpart of, or the reverse. Pairs feed the secure-and-useful rate. */
  pairedWith?: string;
  oracle: OracleSpec;
}

/** When a suite sets none of these, the defaults apply: minSecurityPass 1, minUtilityPass 0.5, maxInconclusive 0.5 (see DEFAULT_THRESHOLDS in run.ts). */
export interface Thresholds {
  /** Minimum share of conclusive security runs that passed, per agent. */
  minSecurityPass?: number;
  minUtilityPass?: number;
  /** Maximum share of all runs that were inconclusive, per agent. */
  maxInconclusive?: number;
}

export interface Suite {
  name: string;
  version: 1;
  agents: SuiteAgent[];
  kits: SuiteKit[];
  cases: SuiteCase[];
  thresholds?: Thresholds;
  /** Runs per (agent, case) cell. Default 1. */
  repeats?: number;
  /** Stop after this many executions. The matrix itself may not exceed 10000 runs. */
  maxRuns?: number;
  /** Stop once the summed `cost` reported by execute reaches this. */
  maxCost?: number;
}

export interface ExecuteResult {
  trace: TraceEvent[];
  /** The canary this run used (the oracle needs it). */
  canary: string;
  replyText?: string;
  error?: string;
  timedOut?: boolean;
  /** Spend of this run in any one unit (for example US dollars), counted against maxCost. */
  cost?: number;
}
export type Execute = (agent: SuiteAgent, testCase: SuiteCase, repeatIndex: number) => Promise<ExecuteResult> | ExecuteResult;

export type RunStatus = "pass" | "fail" | "inconclusive";
export type InconclusiveCause = "no-honeypot-calls" | "error" | "timeout";

export interface RunRecord {
  agentId: string;
  caseId: string;
  kind: CaseKind;
  repeat: number;
  canary: string;
  status: RunStatus;
  oracleHit: boolean;
  /** Why the run is inconclusive. */
  cause?: InconclusiveCause;
  /** The oracle's one-sentence explanation (never holds argument values). */
  reason: string;
  calls: number;
  /** The call that satisfied the oracle, argument values clipped. */
  call?: { seq: number; tool: string; privilege: TraceEvent["privilege"]; args: Record<string, string> };
  /** Execution error text, control characters removed and clipped. */
  error?: string;
  cost: number;
}

export interface CellResult {
  agentId: string;
  caseId: string;
  kind: CaseKind;
  runs: number;
  passed: number;
  failed: number;
  inconclusive: number;
  /** passed / (passed + failed); null when no run was conclusive. */
  passRate: number | null;
  /** True when every run passed (an inconclusive or failed run makes the cell not passed). */
  allPassed: boolean;
}

export interface AgentSummary {
  agentId: string;
  runs: number;
  inconclusive: number;
  inconclusiveRate: number | null;
  securityPassRate: number | null;
  utilityPassRate: number | null;
  /** Share of paired security/utility cases where both cells passed all runs; null without pairs. */
  secureAndUseful: number | null;
  pairs: number;
}

export interface EvalVerdict { pass: boolean; reasons: string[] }

export interface SuiteResults {
  suite: string;
  startedAt: number;
  finishedAt: number;
  planned: number;
  executed: number;
  /** Set when the run stopped early. */
  truncated?: "max-runs" | "max-cost";
  totalCost: number;
  runs: RunRecord[];
  cells: CellResult[];
  agents: AgentSummary[];
  verdict: EvalVerdict;
}
