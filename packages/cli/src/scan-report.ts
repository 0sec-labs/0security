/**
 * The report of a scan: the findings a thread stored, in a versioned shape.
 *
 * A scan is a thread that follows the `scan` skill (docs/design/scan-as-a-thread.md). Findings
 * are stored under the thread's id by the `finding` tool, whoever in the thread recorded them
 * (the thread itself or a helper agent), so the report reads the store and never the transcript.
 */
import { createHash } from "node:crypto";
import { classifyFinding, classifyKnown, labelWithScope, linesWithin, orderByScope, sameFlaw, type Finding, type KnownItem, type ScanCoverage, type ScanFileCoverage, type ScanKnownSummary, type ScanReport, type ScanTierInfo } from "@0/engine/shared";
import { labelBusinessContext, type BusinessContext } from "./business-context.js";
import { compareFindingsByBusinessContext } from "@0/engine/shared";
import { tagCustomFindings } from "./scan-rules.js";
import type { ScopeDeclaration } from "./scan-steering.js";

export const SCAN_REPORT_SCHEMA_VERSION = 1;

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type ScanSeverity = typeof SEVERITIES[number];
const rank = (severity: string): number => { const index = (SEVERITIES as readonly string[]).indexOf(severity); return index < 0 ? SEVERITIES.length : index; };

export interface ScanOutcome {
  /** A label that is the same on every machine: a git URL without credentials, or the folder's name. Never an absolute path. */
  target: string;
  /** Explicit operator declarations, used for work ordering only. */
  businessContext?: BusinessContext;
  /** The repository its per-repository rules were matched against. */
  businessRepository?: string;
  /** Where the scanned code was on this machine (the folder, and its real path); finding paths are made relative to it. */
  roots?: readonly string[];
  threadId: string;
  startedAt: string;
  completedAt: string;
  budgetUsd: number;
  costUsd?: number;
  /** Sum of actual reported input/output usage for this invocation, absent if any thread lacks usage. */
  tokens?: number;
  /** The thread stopped at its cost ceiling; the findings are partial. */
  budgetExhausted: boolean;
  /** The scan hit --timeout and was cancelled; the findings are partial. */
  timedOut?: boolean;
  /** --allow-partial: a scan that stopped early exits by its findings, and its report says "partial". */
  allowPartial?: boolean;
  /** The thread failed or its answer was not backed by its checks. */
  failed: boolean;
  error?: string;
  /** Why the scan failed or stopped early, in plain words (cause and a short message without secrets). */
  failure?: { cause: string; message: string };
  /** The thread's closing summary: coverage and what was not reached. */
  summary?: string;
  /** Set when more than one pass ran: how many were asked for, finished with a report, and could not finish. */
  passes?: { requested: number; completed: number; failed: number };
  /** Set when the scan ran in batches: what was and was not reviewed. */
  coverage?: ScanCoverage;
  /** Set when the scan ran as one thread: which source files it opened. */
  fileCoverage?: ScanFileCoverage;
  /** Set when a scan recorded nothing and did not open every source file: what it did not open. The report shows it as a warning. */
  shallowReview?: string;
  /** Every pass's thread, first to last. */
  threadIds?: readonly string[];
  /** The tier map's decision for this scan, when a tier map applied. */
  tier?: ScanTierInfo;
  /** `--fail-on-skip`: a scan the tier skipped exits 1. */
  failOnSkip?: boolean;
  /** `--known`: what other tools already reported. Findings are labelled against it; `onlyNew` leaves the matched ones out. */
  known?: { items: readonly KnownItem[]; tools: readonly string[]; onlyNew?: boolean };
  /** `--scope` or `--repo-scope`: the declared scope. Findings it names out of scope are labelled, listed apart and left out of the counts and the exit code. */
  scope?: ScopeDeclaration;
  /** `--scope-sarif suppress`: SARIF results labelled out of scope carry a suppression. */
  scopeSarifSuppress?: boolean;
  /** Pre-pass hits from rules the user supplied with --rules; findings at the same rule or place are tagged. */
  customLeads?: readonly { ruleId: string; path?: string; startLine?: number; endLine?: number }[];
}

/** A path inside the scanned folder, relative to it with forward slashes; undefined when it points outside. */
export function repoRelativePath(path: string, roots: readonly string[] = []): string | undefined {
  let value = path.trim().replace(/\\/g, "/");
  for (const root of roots) {
    const base = root.replace(/\\/g, "/").replace(/\/+$/, "");
    if (base && (value === base || value.startsWith(`${base}/`))) { value = value.slice(base.length).replace(/^\/+/, ""); break; }
  }
  value = value.replace(/^(\.\/)+/, "");
  if (!value || value.startsWith("/") || /^[A-Za-z]:\//.test(value) || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(value) || value.split("/").includes("..")) return undefined;
  return value;
}

/** Where a finding is, as a key that does not depend on the model's wording or on the machine: the same place in unchanged code. */
export function locationKey(relativePath: string, startLine: number): string {
  return createHash("sha256").update(`${relativePath}:${startLine}`).digest("hex").slice(0, 24);
}

/**
 * The stored finding with its path relative to the scanned folder, the category as its rule id (the tool stores
 * "manual"), and a location-based fingerprint. The stored fingerprint hashes the title and the evidence text, which the
 * model words differently on every run, and the SARIF key would also carry the absolute checkout path.
 */
function reportFinding(finding: Finding, roots: readonly string[]): Finding {
  const annotation = finding.reviewAnnotation;
  const path = annotation ? repoRelativePath(annotation.path, roots) : undefined;
  const located = annotation && path ? { ...annotation, path } : undefined;
  // A finding stored before the category rules, or imported, is filed under the same rules as a new one.
  const cwe = [...(finding.evidence.analysis ?? "").slice(0, 400).matchAll(/cwe[-_/ :]*0*(\d{1,5})\b/gi)].map(m => `CWE-${m[1]}`);
  const classified = classifyFinding({ category: finding.category, title: finding.title, description: finding.description, cwe });
  const category = classified.category;
  const label = finding.categoryLabel ?? classified.unknownLabel ?? classified.refinedFrom;
  return {
    ...finding,
    category,
    ...(label && label !== category ? { categoryLabel: label } : {}),
    templateId: finding.templateId === "manual" ? category : finding.templateId,
    ...(located ? { reviewAnnotation: located, fingerprint: `loc:${locationKey(located.path, located.startLine)}` } : { reviewAnnotation: undefined }),
  };
}

/** A finding that more than one pass found, merged: how many of the passes did, and which other findings it absorbed. */
export type MergedFinding = Finding & { foundInPasses?: number; mergedFindingIds?: string[] };

interface Cluster { path: string | undefined; title: string; start: number; end: number; passes: Set<number>; best: Finding; members: { finding: Finding; pass: number }[] }

const weight = (finding: Finding): number => (SEVERITIES.length - rank(finding.severity)) * 1_000_000 + finding.description.length + finding.evidence.request.length + finding.evidence.response.length + (finding.evidence.analysis?.length ?? 0);

const asInput = (finding: Finding) => ({ title: finding.title, category: finding.category, description: finding.description, evidenceAnalysis: finding.evidence.analysis, ...(finding.reviewAnnotation ? { location: finding.reviewAnnotation } : {}) });

/**
 * The findings of several passes over the same code as one list. Two findings are one flaw when they cite the same file
 * and the same category (or CWE) at overlapping lines, or, across passes, at lines up to a few apart
 * (a finding with no location merges only on the same title). Findings in different files or categories never merge.
 * Inside one pass, findings merge only on overlapping lines, so two different flaws close together in one pass stay two.
 * The merged finding is the most severe, most detailed version; it records how many passes found it and the ids of the
 * findings it absorbed. A flaw only some passes find is a useful signal, and the union is the point.
 */
export function mergePasses(passes: readonly (readonly Finding[])[], roots: readonly string[] = []): MergedFinding[] {
  const clusters: Cluster[] = [];
  passes.forEach((findings, pass) => {
    for (const raw of findings) {
      const finding = reportFinding(raw, roots);
      const location = finding.reviewAnnotation;
      const start = location?.startLine ?? 0;
      const end = location?.endLine ?? start;
      const title = finding.title.trim().toLowerCase();
      const match = clusters.find(cluster => {
        if (!location || !cluster.path) return !location && !cluster.path && !cluster.passes.has(pass) && cluster.title === title;
        return cluster.members.some(member => member.pass === pass
          ? member.finding.reviewAnnotation !== undefined && linesWithin(member.finding.reviewAnnotation, location, 0) && sameFlaw(asInput(member.finding), asInput(finding))
          : sameFlaw(asInput(member.finding), asInput(finding), { nearWithoutTitle: true }));
      });
      if (match) {
        match.passes.add(pass);
        match.members.push({ finding, pass });
        match.start = Math.min(match.start, start);
        match.end = Math.max(match.end, end);
        if (weight(finding) > weight(match.best)) match.best = finding;
      } else clusters.push({ path: location?.path, title, start, end, passes: new Set([pass]), best: finding, members: [{ finding, pass }] });
    }
  });
  return clusters.map(cluster => {
    const absorbed = cluster.members.map(member => member.finding.id).filter(id => id !== cluster.best.id);
    return { ...cluster.best, ...(passes.length > 1 ? { foundInPasses: cluster.passes.size } : {}), ...(absorbed.length ? { mergedFindingIds: absorbed } : {}) };
  });
}

/** The findings with their status against the known set, those already known left out with --only-new, and the counts of all of them. */
export function markKnown<T extends Finding>(outcome: ScanOutcome, findings: readonly T[]): { findings: T[]; summary?: ScanKnownSummary } {
  if (!outcome.known) return { findings: [...findings] };
  const marked = classifyKnown(findings, outcome.known.items) as unknown as T[];
  const tally = { new: 0, alreadyKnown: 0, confirmedIndependently: 0 };
  for (const finding of marked) { if (finding.knownStatus === "new") tally.new++; else { tally.alreadyKnown++; if (finding.confirmedIndependently) tally.confirmedIndependently++; } }
  const kept = outcome.known.onlyNew ? marked.filter(finding => finding.knownStatus === "new") : marked;
  const hidden = marked.length - kept.length;
  return { findings: kept, summary: { tools: [...outcome.known.tools], total: outcome.known.items.length, findings: tally, ...(hidden ? { hidden } : {}) } };
}

/** The findings with the declared scope's label (in-scope or out-of-scope) where an entry names them. Nothing is removed. */
export function applyScope<T extends Finding>(outcome: ScanOutcome, findings: readonly T[]): T[] {
  if (!outcome.scope) return [...findings];
  const now = Date.parse(outcome.completedAt);
  const at = Number.isFinite(now) ? now : Date.now();
  const { entries, source } = outcome.scope;
  return findings.map(finding => labelWithScope(finding, entries, source, at));
}

const outOfScopeOf = (findings: readonly Finding[]): Finding[] => findings.filter(finding => finding.scope === "out-of-scope");
const inScopeOf = (findings: readonly Finding[]): Finding[] => findings.filter(finding => finding.scope !== "out-of-scope");
const scopeSummary = (outcome: ScanOutcome) => outcome.scope ? { source: outcome.scope.source, inScope: outcome.scope.inScopeVectors, outOfScope: outcome.scope.outOfScopeVectors, ...(outcome.scope.unmatched ? { unmatchedEntries: outcome.scope.unmatched } : {}) } : undefined;

const count = (findings: readonly Finding[], severity: ScanSeverity) => findings.filter(finding => finding.severity === severity).length;
const compareRank = (a: Finding, b: Finding): number => rank(a.severity) - rank(b.severity) || a.title.localeCompare(b.title);
/** In scope first (declared in-scope vectors before the rest), then findings outside the declared scope; each part by severity. */
const byRank = (findings: readonly Finding[]): Finding[] => orderByScope(findings, (a, b) => compareFindingsByBusinessContext(a, b) || compareRank(a, b));

export function applyBusinessContext<T extends Finding>(outcome: ScanOutcome, findings: readonly T[]): T[] {
  return outcome.businessContext ? findings.map(finding => labelBusinessContext(finding, outcome.businessContext!, outcome.target, outcome.businessRepository)) : [...findings];
}

/** The shared report type the exporter understands (md, sarif, html, pdf), with this scan's facts on top of the stored rows. */
export function toScanReport(outcome: ScanOutcome, stored: ScanReport): ScanReport {
  const total = outcome.passes?.requested ?? 1;
  const tagged = tagCustomFindings(stored.findings.map(finding => reportFinding(finding, outcome.roots ?? [])), outcome.customLeads);
  const known = markKnown(outcome, applyScope(outcome, tagged));
  const findings = byRank(applyBusinessContext(outcome, known.findings).map(shaped => {
    const found = (shaped as MergedFinding).foundInPasses;
    // The exporters have no field for it, so say it where every format shows it.
    return total > 1 && found ? { ...shaped, description: `${shaped.description}\n\nFound in ${found} of ${total} scan passes.` } : shaped;
  }));
  return {
    ...stored,
    // A remote-style label makes the exporters write repo-relative paths (a folder label is read as a checkout location).
    target: /^[A-Za-z][A-Za-z0-9+.-]*:|^git@/.test(outcome.target) ? outcome.target : `source:${outcome.target}`,
    startedAt: outcome.startedAt,
    completedAt: outcome.completedAt,
    durationMs: Math.max(0, Date.parse(outcome.completedAt) - Date.parse(outcome.startedAt)),
    findings,
    // The headline counts are the findings inside the declared scope; the labelled ones are listed apart.
    summary: { totalAttacks: 0, totalFindings: inScopeOf(findings).length, critical: count(inScopeOf(findings), "critical"), high: count(inScopeOf(findings), "high"), medium: count(inScopeOf(findings), "medium"), low: count(inScopeOf(findings), "low"), info: count(inScopeOf(findings), "info") },
    ...(outcome.scope ? { scopeInfo: { source: outcome.scope.source, inScopeVectors: outcome.scope.inScopeVectors, outOfScopeVectors: outcome.scope.outOfScopeVectors, ...(outcome.scope.unmatched ? { unmatched: outcome.scope.unmatched } : {}), ...(outcome.scopeSarifSuppress ? { sarifSuppress: true } : {}) } } : {}),
    scanStatus: scanStatus(outcome),
    ...(outcome.failure ? { scanFailure: { cause: outcome.failure.cause, message: outcome.failure.message } } : {}),
    ...(outcome.coverage ? { coverage: outcome.coverage } : {}),
    ...(outcome.fileCoverage ? { fileCoverage: outcome.fileCoverage } : {}),
    ...(outcome.tier ? { tier: outcome.tier } : {}),
    ...(known.summary ? { known: known.summary } : {}),
    // The stored rows carry a note that the export was rebuilt from a legacy record; a scan is not one.
    warnings: [...(outcome.tier?.skipped ? [{ stage: "report" as const, message: `Skipped by tier ${outcome.tier.name}${outcome.tier.reason ? `: ${outcome.tier.reason}` : ""}. Nothing was scanned.` }] : []), ...(outcome.tier?.prepassOnly ? [{ stage: "report" as const, message: `Tier ${outcome.tier.name} is pre-pass only: the findings are scanner hits, not reviewed by a model.` }] : []), ...(outcome.coverage && !outcome.coverage.complete ? [{ stage: "report" as const, message: `Partial review: ${outcome.coverage.statement}.${outcome.coverage.resume ? ` ${outcome.coverage.stoppedBy ? `Stopped by ${outcome.coverage.stoppedBy}. ` : ""}Continue with: ${outcome.coverage.resume}` : ""}` }] : []),...(outcome.shallowReview ? [{ stage: "report" as const, message: outcome.shallowReview }] : []),...(outcome.passes && outcome.passes.failed > 0 ? [{ stage: "report" as const, message: `${outcome.passes.failed} of ${outcome.passes.requested} scan passes could not finish; the findings may be incomplete.` }] : [])].concat(outcome.budgetExhausted ? [{ stage: "report" as const, message: `Stopped at the $${outcome.budgetUsd} budget; findings are partial.` }] : outcome.timedOut ? [{ stage: "report" as const, message: "Stopped at the time limit; findings are partial." }] : []),
    executionSuccessful: !outcome.failed,
    ...(outcome.costUsd !== undefined ? { estimatedCostUsd: outcome.costUsd } : {}),
    ...(outcome.budgetExhausted ? { costCeilingExceeded: true, exitReason: "cost_ceiling_exceeded" as const } : {}),
    ...(outcome.error ? { error: outcome.error } : {}),
  };
}

/** Whether the scan stopped before it reviewed everything: the budget, the time limit or units not reached. */
export function isPartial(outcome: ScanOutcome): boolean {
  return outcome.budgetExhausted || outcome.timedOut === true || (outcome.coverage !== undefined && !outcome.coverage.complete);
}

/** The `status` of the JSON report. With --allow-partial every early stop is "partial"; the reason stays in `coverage` and the summary. */
export function scanStatus(outcome: ScanOutcome): string {
  if (outcome.failed) return "failed";
  if (outcome.tier?.skipped) return "skipped";
  if (outcome.tier?.prepassOnly) return "prepass_only";
  if (outcome.allowPartial && isPartial(outcome)) return "partial";
  return outcome.budgetExhausted ? "budget_exhausted" : outcome.timedOut ? "timed_out" : outcome.coverage && !outcome.coverage.complete ? "partial" : "complete";
}

/** The documented JSON contract of `0 scan --format json`. Field names are stable within a schemaVersion. */
export function scanJson(outcome: ScanOutcome, stored: readonly Finding[]): Record<string, unknown> {
  const known = markKnown(outcome, applyScope(outcome, tagCustomFindings(stored.map(finding => reportFinding(finding, outcome.roots ?? [])), outcome.customLeads)));
  const findings = byRank(applyBusinessContext(outcome, known.findings));
  const inScope = inScopeOf(findings);
  const outside = outOfScopeOf(findings);
  return {
    schemaVersion: SCAN_REPORT_SCHEMA_VERSION,
    target: outcome.target,
    threadId: outcome.threadId,
    startedAt: outcome.startedAt,
    completedAt: outcome.completedAt,
    budgetUsd: outcome.budgetUsd,
    ...(outcome.costUsd !== undefined ? { costUsd: outcome.costUsd } : {}),
    ...(outcome.threadIds && outcome.threadIds.length > 1 ? { threadIds: outcome.threadIds } : {}),
    ...(outcome.passes && outcome.passes.requested > 1 ? { passes: outcome.passes } : {}),
    status: scanStatus(outcome),
    ...(outcome.failure ? { failure: { cause: outcome.failure.cause, message: outcome.failure.message } } : {}),
    ...(outcome.coverage ? { coverage: outcome.coverage } : {}),
    ...(outcome.fileCoverage ? { fileCoverage: outcome.fileCoverage } : {}),
    ...(outcome.tier ? { tier: outcome.tier } : {}),
    ...(known.summary ? { known: known.summary } : {}),
    ...(outcome.error ? { error: outcome.error } : {}),
    ...(outcome.shallowReview ? { warnings: [outcome.shallowReview] } : {}),
    ...(outcome.summary ? { summary: outcome.summary } : {}),
    // Headline counts are the findings inside the declared scope. Out-of-scope findings are counted apart and still listed.
    counts: { total: inScope.length, critical: count(inScope, "critical"), high: count(inScope, "high"), medium: count(inScope, "medium"), low: count(inScope, "low"), info: count(inScope, "info") },
    ...(outcome.scope ? { scope: scopeSummary(outcome), outOfScopeCounts: { total: outside.length, critical: count(outside, "critical"), high: count(outside, "high"), medium: count(outside, "medium"), low: count(outside, "low"), info: count(outside, "info") } } : {}),
    findings: findings.map(finding => ({
      id: finding.id,
      // A hash of the file and first cited line, so a flaw in the same place of unchanged code keeps it from scan to scan
      // (it does not depend on how the model worded the finding). Absent when the finding cites no location.
      ...(finding.fingerprint?.startsWith("loc:") ? { fingerprint: finding.fingerprint.slice(4) } : {}),
      title: finding.title,
      ...(finding.ruleSource ? { ruleSource: finding.ruleSource } : {}),
      ...(finding.knownStatus ? { knownStatus: finding.knownStatus } : {}),
      ...(finding.confirmedIndependently ? { confirmedIndependently: true } : {}),
      ...(finding.knownBy ? { knownBy: finding.knownBy } : {}),
      severity: finding.severity,
      category: finding.category,
      ...(finding.businessContext ? { businessContext: finding.businessContext } : {}),
      status: finding.status,
      ...(finding.scope ? { scope: finding.scope, ...(finding.scopeReason ? { scopeReason: finding.scopeReason } : {}), ...(finding.scopeSource ? { scopeSource: finding.scopeSource } : {}) } : {}),
      // With several passes: how many of them found this flaw. A flaw only one pass found is real but less certain.
      ...((finding as MergedFinding).foundInPasses !== undefined ? { foundInPasses: (finding as MergedFinding).foundInPasses } : {}),
      description: finding.description || finding.evidence.analysis || "",
      ...(finding.reviewAnnotation ? { location: { path: finding.reviewAnnotation.path, startLine: finding.reviewAnnotation.startLine, ...(finding.reviewAnnotation.endLine !== undefined ? { endLine: finding.reviewAnnotation.endLine } : {}) } } : {}),
      evidence: finding.evidence,
      ...(finding.confidence !== undefined ? { confidence: finding.confidence } : {}),
      ...(finding.cvssScore !== undefined ? { cvssScore: finding.cvssScore } : {}),
      ...(finding.cvssVector ? { cvssVector: finding.cvssVector } : {}),
      ...(finding.impactAssessment ? { impact: finding.impactAssessment } : {}),
      ...(finding.reviewAnnotation?.suggestion ? { suggestedFix: { replacement: finding.reviewAnnotation.suggestion } } : {}),
    })),
  };
}

/**
 * Exit code: 1 for a failed scan or a finding at or above the threshold, 3 for a scan that stopped before it reviewed
 * everything (budget, time limit, units not reached), else 0. With `allowPartial` a partial scan exits by its findings only.
 */
export function scanExitCode(outcome: ScanOutcome, findings: readonly Finding[], failOn: ScanSeverity | undefined): number {
  if (outcome.failed) return 1;
  if (outcome.tier?.skipped) return outcome.failOnSkip ? 1 : 0;
  // With --only-new, a finding that was already known does not fail the run.
  findings = markKnown(outcome, findings.map(finding => reportFinding(finding, outcome.roots ?? []))).findings;
  // A finding the declared scope names out of scope is listed in the report but does not fail the run.
  findings = inScopeOf(applyScope(outcome, findings));
  if (failOn && findings.some(finding => rank(finding.severity) <= rank(failOn))) return 1;
  // Units not reviewed mean the review is partial, whatever stopped it.
  return isPartial(outcome) && !outcome.allowPartial ? 3 : 0;
}
