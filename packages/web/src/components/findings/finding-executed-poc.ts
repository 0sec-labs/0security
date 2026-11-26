import { executedPocLine, parseExecutedPoc, type ExecutedPoc, type ExecutedPocOutcome } from "@0/engine/shared/executed-poc";

export type ExecutedPocView = {
  outcome: ExecutedPocOutcome;
  /** Short chip text for a list row and the properties panel. */
  label: string;
  /** The one honest sentence, shared with the CLI and the reports. */
  line: string;
  /** Run facts for the detail view; empty for static-only. */
  facts: string[];
};

const LABELS: Record<ExecutedPocOutcome, string> = {
  "executed-proven": "PoC proven",
  "executed-failed": "PoC failed",
  "static-only": "Static only",
};

/**
 * What the dashboard shows for a finding's executed-PoC record. Only a complete harness record of a container run can
 * be shown as proven or failed: anything the parser refuses is not shown as an executed result. The server derives a
 * `static-only` record (with no timestamps) for a high or critical finding that was never attempted; that one is
 * accepted as static-only and nothing else is.
 */
export function executedPocView(value: unknown): ExecutedPocView | null {
  if (value === null || value === undefined) return null;
  let record: ExecutedPoc | undefined = parseExecutedPoc(value);
  if (!record && typeof value === "object" && !Array.isArray(value)) {
    const derived = value as Partial<ExecutedPoc>;
    if (derived.outcome === "static-only" && typeof derived.reason === "string" && !derived.run) {
      record = { schemaVersion: 1, harness: "0security-executed-poc/1", outcome: "static-only", reason: derived.reason, stepIds: [], startedAt: "", finishedAt: "" };
    }
  }
  if (!record) return null;
  const run = record.run;
  const facts: string[] = [];
  if (run) {
    if (run.imageDigest) facts.push(`Image ${run.imageDigest.slice(0, 19)}`);
    if (run.isolation === "container") facts.push("Container, network off");
    facts.push(`${(run.durationMs / 1000).toFixed(1)}s${run.exitCode !== undefined && run.exitCode !== null ? `, exit ${run.exitCode}` : ""}`);
    if (record.stepIds.length) facts.push(`Steps ${record.stepIds.join(", ")}`);
  }
  return { outcome: record.outcome, label: LABELS[record.outcome], line: executedPocLine(record), facts };
}
