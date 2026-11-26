/**
 * `0 findings context check <file>`: which rules of a business context file match which current findings, and
 * which match nothing. Read-only. Exit 0 when every rule that applies matched a finding, 1 when one matched
 * nothing, 2 when the file is not valid.
 */
import type { Command } from "commander";
import { effectiveTriageStatus } from "@0/engine/shared";
import { listOsecRunDatabasePaths, osecDB, resolveOsecDbPath, resolveOsecRunStorage } from "@0/engine/storage";
import { applicableEntries, entryMatches, findingPath, repositoryRulesApply, type BusinessContext, type ContextEntry } from "../business-context.js";
import { loadContextFor, REPOSITORY_FLAG_HELP, type LoadDeps } from "../business-context-load.js";
import { finishWithError, UsageError } from "./output.js";

export interface ContextCheckDeps { out(text: string): void; err(text: string): void; load?: LoadDeps }
const defaults: ContextCheckDeps = { out: text => process.stdout.write(`${text}\n`), err: text => process.stderr.write(`${text}\n`) };
interface CheckOptions { dbPath?: string; scan?: string; repository?: string; json?: boolean }

export interface CheckedFinding { id: string; path?: string; severity: string; title: string }
export type RuleStatus = "matched" | "unused" | "other-repository" | "repository-unknown";
export interface CheckedRule { ref: string; repository?: string; match?: string; tags: string[]; status: RuleStatus; matches: number; examples: CheckedFinding[] }
export interface ContextCheck { file: string; repository?: string; findings: number; touched: number; rules: CheckedRule[]; unused: number }

const plain = (value: string): string => value.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim().slice(0, 120);
const MAX_EXAMPLES = 3;

/** Pure: checks every rule of the file against the findings. A repository rule for another repository is reported, not counted as unused. */
export function checkContext(context: BusinessContext, findings: readonly CheckedFinding[], repository: string | undefined, file: string): ContextCheck {
  const applicable = new Set<ContextEntry>(applicableEntries(context, repository));
  const rows: Array<{ entry: ContextEntry; repository?: string }> = [...context.entries.map(entry => ({ entry })), ...context.repositories.flatMap(rules => rules.entries.map(entry => ({ entry, repository: rules.pattern })))];
  const touched = new Set<string>();
  const rules = rows.map(({ entry, repository: scope }): CheckedRule => {
    const base = { ref: entry.ref, ...(scope ? { repository: scope } : {}), ...(entry.match !== undefined ? { match: entry.match } : {}), tags: entry.tags };
    if (!applicable.has(entry)) return { ...base, status: scope && repository === undefined ? "repository-unknown" : "other-repository", matches: 0, examples: [] };
    const hits = findings.filter(finding => entryMatches(entry, finding.path));
    for (const hit of hits) touched.add(hit.id);
    return { ...base, status: hits.length ? "matched" : "unused", matches: hits.length, examples: hits.slice(0, MAX_EXAMPLES) };
  });
  return { file, ...(repository ? { repository } : {}), findings: findings.length, touched: touched.size, rules, unused: rules.filter(rule => rule.status === "unused").length };
}

export function renderCheck(check: ContextCheck): string {
  const lines = [`${check.file}${check.repository ? ` (repository ${check.repository})` : ""}`, `${check.touched} of ${check.findings} finding${check.findings === 1 ? "" : "s"} touched by at least one rule.`, ""];
  for (const rule of check.rules) {
    const head = `${rule.ref}${rule.repository ? ` for ${plain(rule.repository)}` : ""}  ${rule.match !== undefined ? plain(rule.match) : "every finding"}  [${rule.tags.join(", ")}]`;
    if (rule.status === "unused") lines.push(`${head}\n  matches nothing`);
    else if (rule.status === "other-repository") lines.push(`${head}\n  not applied: the repository is not ${plain(rule.repository ?? "")}`);
    else if (rule.status === "repository-unknown") lines.push(`${head}\n  not checked: the repository is unknown; pass --repository`);
    else lines.push(`${head}\n  matches ${rule.matches} finding${rule.matches === 1 ? "" : "s"}`, ...rule.examples.map(example => `    ${example.severity}  ${plain(example.path ?? "(no path)")}  ${plain(example.title)}`));
  }
  lines.push("", check.unused ? `${check.unused} rule${check.unused === 1 ? "" : "s"} match nothing.` : "Every rule that applies matches at least one finding.");
  return lines.join("\n");
}

/** The newest row of each fingerprint across the databases, without fixed, false-positive, accepted or suppressed ones. */
function currentFindings(options: CheckOptions): CheckedFinding[] {
  const dbPaths = options.dbPath ? [options.dbPath] : options.scan ? [resolveOsecRunStorage({ runId: options.scan, resume: true }).dbPath] : [...new Set([...listOsecRunDatabasePaths(), resolveOsecDbPath()])];
  const latest = new Map<string, CheckedFinding & { timestamp: number }>();
  for (const dbPath of dbPaths) {
    let db: osecDB | undefined;
    try {
      db = new osecDB(dbPath);
      for (const row of db.listFindings({ limit: 5000, ...(options.scan ? { scanId: options.scan } : {}) }) as unknown as Array<Record<string, unknown>>) {
        if (row.status === "fixed" || row.status === "false-positive") continue;
        const triage = effectiveTriageStatus({ triageStatus: String(row.triageStatus ?? "new"), triageExpiresAt: typeof row.triageExpiresAt === "string" ? row.triageExpiresAt : undefined });
        if (triage === "accepted" || triage === "suppressed") continue;
        const key = String(row.fingerprint ?? row.id);
        const seen = latest.get(key);
        const timestamp = Number(row.timestamp ?? 0);
        if (!seen || seen.timestamp < timestamp) latest.set(key, { id: String(row.id), severity: String(row.severity), title: String(row.title), timestamp, ...(findingPath(row.reviewAnnotation) ? { path: findingPath(row.reviewAnnotation)! } : {}) });
      }
    } catch { /* an unreadable run database holds nothing to check */ } finally { db?.close(); }
  }
  return [...latest.values()].map(({ timestamp: _at, ...finding }) => finding);
}

export async function runContextCheck(file: string, options: CheckOptions, deps: ContextCheckDeps = defaults): Promise<void> {
  try {
    // The file is named explicitly here; the findingsContext setting is not consulted.
    const loaded = await loadContextFor({ context: file, ...(options.repository ? { repository: options.repository } : {}) }, deps.load);
    if (!loaded) throw new UsageError("Name a context file.");
    const check = checkContext(loaded.context, currentFindings(options), loaded.repository, file);
    deps.out(options.json ? JSON.stringify(check, null, 2) : renderCheck(check));
    if (check.unused) process.exitCode = 1;
  } catch (error) { finishWithError(error, deps, options.json); }
}

export function registerFindingsContextCommand(parent: Command, deps: ContextCheckDeps = defaults): void {
  const group = parent.command("context").description("Work with the business context file that orders findings");
  group.command("check <file>")
    .description("List which rules of a context file match which current findings, and which match nothing")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--scan <scanId>", "Only the findings of this scan")
    .option("--repository <name>", REPOSITORY_FLAG_HELP)
    .option("--json", "Print JSON")
    .addHelpText("after", "\nExit codes: 0 every rule that applies matches a finding, 1 a rule matches nothing, 2 the file is not valid.")
    .action(async (file: string, options: CheckOptions, command: Command) => {
      const merged = { ...command.parent?.parent?.opts(), ...command.opts() } as CheckOptions;
      await runContextCheck(file, { ...options, dbPath: options.dbPath ?? merged.dbPath, scan: options.scan ?? merged.scan, ...(options.repository ?? merged.repository ? { repository: options.repository ?? merged.repository } : {}) }, deps);
    });
}
