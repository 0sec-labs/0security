/**
 * What a scan that ended before it reviewed everything tells the reader: what stopped it, how much is left and the exact
 * command that continues it. Pure, so the text can be tested without a console.
 */
import type { CoverageSummary } from "@0/engine/storage";

export interface StopFacts {
  /** The scan stopped at its spending limit. */
  budgetHit: boolean;
  budgetUsd: number;
  timedOut: boolean;
  timeoutSeconds: number;
  /** The reasons batches failed, first to last. */
  failures: readonly string[];
}

export interface ResumeHint {
  command: string;
  /** For example "16 of 57 entry points not reached". */
  left: string;
  /** For example "the $0.1 budget". */
  stoppedBy: string;
  /** The stderr and report lines, ready to print. */
  text: string;
}

/** A shell word: left as it is when it needs no quoting, else in single quotes. */
export function shellQuote(value: string): string {
  return /^[A-Za-z0-9_./:@%+=,-]+$/.test(value) ? value : `'${value.replace(/'/g, `'\\''`)}'`;
}

/** The command that continues scan `scanId` of `folder`. */
export function resumeCommand(folder: string, scanId: string): string {
  return `0 scan ${shellQuote(folder)} --resume ${shellQuote(scanId)}`;
}

function stoppedBy(stop: StopFacts, summary: CoverageSummary): string {
  if (stop.budgetHit) return `the $${Number(stop.budgetUsd.toFixed(4))} budget`;
  if (stop.timedOut) return `the ${stop.timeoutSeconds}s time limit`;
  if (stop.failures.length) {
    const unique = [...new Set(stop.failures.map(reason => reason.trim()).filter(Boolean))];
    const reason = unique[0] ? `: ${unique[0].slice(0, 160)}` : "";
    return `${stop.failures.length === 1 ? "a failed batch" : `${stop.failures.length} failed batches`}${reason}`;
  }
  const reasons = Object.keys(summary.notReached);
  if (reasons.length === 1 && reasons[0] === "not opened") return "files the model did not open";
  return reasons.length ? reasons.join(", ") : "an earlier run";
}

/** How much is left: entry points first, then groups of other files. */
export function leftText(summary: CoverageSummary): string {
  const { entryPoints, otherGroups } = summary;
  const parts: string[] = [];
  if (entryPoints.pending) parts.push(`${entryPoints.pending} of ${entryPoints.total} entry point${entryPoints.total === 1 ? "" : "s"} not reached`);
  if (otherGroups.pending) parts.push(`${otherGroups.pending} of ${otherGroups.total} group${otherGroups.total === 1 ? "" : "s"} of other files not reached`);
  return parts.join("; ");
}

/** The hint for a scan with units pending; undefined when the review is complete. */
export function resumeHint(folder: string, summary: CoverageSummary, stop: StopFacts): ResumeHint | undefined {
  if (summary.complete) return undefined;
  const command = resumeCommand(folder, summary.scanId);
  const left = leftText(summary);
  const by = stoppedBy(stop, summary);
  const more = stop.budgetHit ? "\nAdd --budget <usd> to allow more spend." : "";
  return { command, left, stoppedBy: by, text: `Stopped by ${by}; ${left}.\nContinue with: ${command}${more}` };
}
