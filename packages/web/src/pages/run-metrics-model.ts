/** Missing receipts must remain distinct from an actually measured zero. */
export function metricTotal(value: number, unknownRuns: number | undefined, runs: number, currency = false): string {
  const unknown = unknownRuns ?? 0;
  if (runs > 0 && unknown >= runs) return "Unknown";
  const known = currency ? `$${value.toFixed(4)}` : String(value);
  return unknown > 0 ? `${known} (+${unknown} unknown)` : known;
}
