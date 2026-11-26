import { readableError } from "./error-text.js";
/** Shared plain-text table for `list` commands: left-aligned, two-space gutters, no colour. */
export interface TableColumn<T> { header: string; value: (row: T) => string | number | undefined | null; max?: number }
export function renderTable<T>(rows: readonly T[], columns: readonly TableColumn<T>[]): string {
  const cell = (column: TableColumn<T>, row: T) => {
    const text = String(column.value(row) ?? "").replace(/\s+/g, " ");
    const max = column.max ?? 60;
    return text.length > max ? `${text.slice(0, max - 1)}…` : text;
  };
  const widths = columns.map(column => Math.max(column.header.length, ...rows.map(row => cell(column, row).length)));
  const line = (values: string[]) => values.map((value, index) => value.padEnd(widths[index]!)).join("  ").trimEnd();
  return [line(columns.map(column => column.header)), ...rows.map(row => line(columns.map(column => cell(column, row))))].join("\n");
}

/** True when the command line asks for machine-readable output (`--json`, or `--format json` or `ndjson`), so a failure can be reported the same way. */
export function wantsJsonOutput(argv: readonly string[]): boolean {
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "--") return false;
    if (arg === "--json" || arg === "--format=json" || arg === "--format=ndjson") return true;
    if (arg === "--format" && (argv[i + 1] === "json" || argv[i + 1] === "ndjson")) return true;
  }
  return false;
}
/** The text for an error on stderr: one `{"error": ...}` line for machine-readable output, red text otherwise. */
export function errorLine(message: string, json: boolean, paint: (text: string) => string = text => text): string {
  return json ? JSON.stringify({ error: message }) : paint(message);
}

/** A usage problem (bad flag value, missing --yes); exits 2. Everything else that fails exits 1. */
export class UsageError extends Error {}
export function finishWithError(error: unknown, deps: { err(text: string): void }, json: boolean | undefined): void {
  const message = readableError(error instanceof Error ? error.message : String(error));
  deps.err(json ? JSON.stringify({ error: message }) : message);
  process.exitCode = error instanceof UsageError ? 2 : 1;
}
