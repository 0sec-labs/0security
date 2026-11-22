/** The `resolved N, unresolved M` line shared by `0 sbom generate` and `0 sbom check`. */
const SHOWN_UNRESOLVED = 20;
/** `resolved N, unresolved M`, then what was not analysed. Resolved counts components with a known version; unresolved counts declarations, profiles, parents and BOMs that were skipped, never guessed. */
export function resolutionLine(resolved: number, unresolved: string[]): string {
  const lines = [`resolved ${resolved}, unresolved ${unresolved.length}`];
  if (unresolved.length) {
    lines.push(...unresolved.slice(0, SHOWN_UNRESOLVED).map(item => `  not analysed: ${item}`));
    if (unresolved.length > SHOWN_UNRESOLVED) lines.push(`  and ${unresolved.length - SHOWN_UNRESOLVED} more (all are in the SBOM metadata properties named 0:unresolved)`);
  }
  return lines.join("\n");
}
