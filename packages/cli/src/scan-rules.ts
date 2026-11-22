/**
 * Rules the operator names with `0 scan --rules`. They are passed to the pattern scanners as given and are never found by
 * looking inside the scanned folder: a change under review could otherwise delete the rule that catches its own bug.
 */
import { existsSync, realpathSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { parseScannerList, scannerById, scannerTakesRules, type ImportedFinding } from "@0/engine/shared";
import type { Finding } from "@0/engine/shared";

/** Absolute, real paths of the named rule files and folders. Throws a message naming the first one that is missing. */
export function resolveRulePaths(values: readonly string[] | undefined): string[] {
  const out: string[] = [];
  for (const value of values ?? []) {
    const path = resolve(value);
    if (!existsSync(path)) throw new Error(`--rules ${value}: no such file or folder.`);
    const kind = statSync(path);
    if (!kind.isFile() && !kind.isDirectory()) throw new Error(`--rules ${value} is not a file or a folder.`);
    const real = realpathSync(path);
    if (!out.includes(real)) out.push(real);
  }
  return out;
}

/** Throws unless a scanner that reads these rules is selected, and the pre-pass is on. */
export function checkRulesScanners(scanners: readonly string[] | undefined, prepass: string | undefined): void {
  if (prepass === "off") throw new Error("--rules runs in the pre-pass; drop --prepass off.");
  const ids = parseScannerList(scanners);
  if (!ids.some(id => { const spec = scannerById(id); return spec && scannerTakesRules(spec); })) {
    throw new Error("--rules is read by semgrep and opengrep, not by foxguard. Add --scanner semgrep or --scanner opengrep.");
  }
}

const GAP = 3;
const sameRule = (leadRule: string, findingRule: string): boolean => leadRule === findingRule || leadRule.endsWith(`.${findingRule}`);

/** The findings, with `ruleSource: "custom"` and a note where a custom-rule lead points at the same rule or the same lines. */
export function tagCustomFindings<T extends Finding>(findings: readonly T[], leads: readonly Pick<ImportedFinding, "ruleId" | "path" | "startLine" | "endLine">[] | undefined): T[] {
  if (!leads?.length) return [...findings];
  return findings.map(finding => {
    const where = finding.reviewAnnotation;
    const hit = leads.find(lead => sameRule(lead.ruleId, finding.templateId)
      || (where && lead.path === where.path && lead.startLine !== undefined && where.startLine >= lead.startLine - GAP && where.startLine <= (lead.endLine ?? lead.startLine) + GAP));
    if (!hit) return finding;
    return { ...finding, ruleSource: "custom" as const, description: `${finding.description}\n\nFlagged by your rule ${hit.ruleId} (from --rules).` };
  });
}
