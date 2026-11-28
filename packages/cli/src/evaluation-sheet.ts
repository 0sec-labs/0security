/**
 * The evaluation sheet: one folder that lets a person judge the findings of one scan by hand and compare tools run on the
 * same repository. `0security scan --evaluation-sheet <folder>` writes it after a scan and
 * `0security findings export --scan <id> --format sheet -o <folder>` writes it again from the stored findings.
 *
 * Building the sheet reads the findings and the facts of the run; it calls no model and no network service. The folder holds
 * its own fixed files only. The README says plainly that the sheet is for human judgement and is not an accuracy result.
 */
import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { compareFindingsByBusinessContext, parseFindingBusinessContext, type Finding } from "@0/engine/shared";
import { repoRelativePath, scanStatus, type ScanOutcome } from "./scan-report.js";
import { UsageError } from "./commands/output.js";

export const SHEET_FILES = ["README.md", "review.csv", "findings.json", "run.json"] as const;
export const SHEET_SCHEMA = "0.evaluation-sheet.v1";
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const NO_LOCATION = "(no location recorded)";
const NOT_VERIFIED = "not verified";
const NOT_RECORDED = "not recorded";

/** The facts of the run that are not in the findings. Everything absent is written as "not recorded", never guessed. */
export interface SheetRun {
  /** `scan`: the facts came from the scan that just ran. `stored`: rebuilt later from the findings database. */
  source: "scan" | "stored";
  generatedAt: string;
  /** The exact command line, and the version of the CLI that ran it. */
  command: string;
  cliVersion: string;
  target?: string;
  commit?: string;
  uncommittedChanges?: boolean;
  scanId?: string;
  model?: string;
  reasoning?: string;
  startedAt?: string;
  completedAt?: string;
  durationMs?: number;
  costUsd?: number;
  budgetUsd?: number;
  tokens?: number;
  status?: string;
  /** What the scan did and did not review, in words. */
  coverage?: string;
  warnings?: string[];
  /** The pattern scanners that ran before the model, with the version each reported. */
  scanners?: Array<{ id: string; version?: string }>;
}

export interface SheetFinding {
  id: string;
  findingId: string;
  severity: string;
  location: { path: string; startLine: number; endLine?: number } | null;
  title: string;
  category: string;
  reportedBy: string | null;
  description: string;
  verdict: string;
  fixExplanation: string | null;
  businessContext: { rank: number; tags: string[]; shift: number; score: number; rationale: string } | null;
  confidence: number | null;
}

export interface SheetFile { name: (typeof SHEET_FILES)[number]; text: string }
export interface Sheet { files: SheetFile[]; findings: SheetFinding[]; findingsSha256: string }

const sha256 = (text: string): string => createHash("sha256").update(text).digest("hex");
const oneLine = (text: string): string => text.replace(/[\u0000-\u001f\u007f\u2028\u2029]+/g, " ").replace(/\s+/g, " ").trim();
const compareText = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
const severityRank = (severity: string): number => { const index = SEVERITIES.indexOf(severity.toLowerCase()); return index < 0 ? SEVERITIES.length : index; };

/**
 * What was checked about a finding, in the words the rest of the product uses. A finding nobody checked says "not verified".
 * No label here means the finding is true or false: the model wrote the finding and the model-written script, and a person judges.
 */
export function verdictOf(finding: Finding): string {
  const reproduction = finding.reproduction?.result;
  if (reproduction?.status === "reproduced") return "reproduced: the sandbox run observed the canary";
  if (reproduction?.status === "not-reproduced") return "not reproduced in the sandbox (this does not show the finding is false)";
  const verification = finding.verification_result;
  if (verification?.status === "reproduced") return "reproduced by replay";
  if (verification?.status === "not_reproduced") return "not reproduced by replay (this does not show the finding is false)";
  const executed = finding.executedPoc;
  if (executed?.outcome === "script-matched") return "script matched: a model-written script printed the expected text in a container (not proof)";
  if (executed?.outcome === "script-unmatched") return "script unmatched: the model-written script did not print the expected text (this does not show the finding is false)";
  const source = finding.sourceVerification;
  if (source?.status === "matched") return "source check matched: the cited code matches the finding's predicates (nothing was run)";
  if (source?.status === "not_confirmed") return "source check did not confirm the finding";
  if (source?.status === "inconclusive") return "source check was inconclusive";
  return NOT_VERIFIED;
}

/** The rows of the sheet, in the order severity, path, line (a finding without a location last in its severity). */
export function sheetFindings(findings: readonly Finding[], roots: readonly string[] = []): SheetFinding[] {
  // The rank in the operator's business-context order, when any finding has one. Severity is never changed.
  const byContext = [...findings].sort((a, b) => compareFindingsByBusinessContext(a, b) || compareText(a.id, b.id));
  const rankOf = new Map(byContext.map((finding, index) => [finding.id, index + 1]));
  const rows = findings.map(finding => {
    const at = finding.reviewAnnotation;
    const path = at?.path ? (repoRelativePath(at.path, roots) ?? (roots.length ? undefined : at.path.replace(/\\/g, "/"))) : undefined;
    const context = parseFindingBusinessContext(finding.businessContext);
    const row: Omit<SheetFinding, "id"> = {
      findingId: finding.id,
      severity: finding.severity,
      location: path && at ? { path, startLine: at.startLine, ...(at.endLine !== undefined && at.endLine !== at.startLine ? { endLine: at.endLine } : {}) } : null,
      title: oneLine(finding.title),
      category: finding.category,
      reportedBy: finding.tool ?? null,
      description: (finding.description || finding.evidence?.analysis || "").trim(),
      verdict: verdictOf(finding),
      fixExplanation: at?.fixExplanation?.trim() || null,
      businessContext: context ? { rank: rankOf.get(finding.id)!, tags: context.tags, shift: context.shift, score: context.score, rationale: context.rationale } : null,
      confidence: finding.confidence ?? null,
    };
    return row;
  });
  rows.sort((a, b) =>
    severityRank(a.severity) - severityRank(b.severity)
    || (a.location ? 0 : 1) - (b.location ? 0 : 1)
    || compareText(a.location?.path ?? "", b.location?.path ?? "")
    || (a.location?.startLine ?? 0) - (b.location?.startLine ?? 0)
    || compareText(a.title, b.title)
    || compareText(a.findingId, b.findingId));
  // A short id that does not change with the order of other findings: it comes from what the finding is and where it is.
  const taken = new Map<string, number>();
  return rows.map(row => {
    const base = `F${sha256([row.severity, row.location?.path ?? "", row.location?.startLine ?? "", row.category, row.title].join("\u0000")).slice(0, 8)}`;
    const seen = (taken.get(base) ?? 0) + 1;
    taken.set(base, seen);
    return { id: seen === 1 ? base : `${base}-${seen}`, ...row };
  });
}

/** One CSV cell: a cell a spreadsheet would read as a formula gets a leading apostrophe, then quoting where needed. */
export function csvCell(value: string | number | null | undefined): string {
  let text = String(value ?? "");
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export const CSV_COLUMNS = ["id", "severity", "location", "title", "category", "verification verdict", "fix explanation", "business context rank", "business context", "description", "true positive", "false positive", "unsure", "notes", "list hash"] as const;

const locationText = (row: SheetFinding): string => row.location ? `${row.location.path}:${row.location.startLine}${row.location.endLine !== undefined ? `-${row.location.endLine}` : ""}` : NO_LOCATION;

/** The reviewers' sheet. It starts with a byte order mark so Excel reads unicode, and uses CRLF line ends as RFC 4180 asks. */
export function reviewCsv(rows: readonly SheetFinding[], findingsSha256: string): string {
  const anyContext = rows.some(row => row.businessContext);
  const lines = [CSV_COLUMNS.map(csvCell).join(",")];
  for (const row of rows) {
    lines.push([
      row.id, row.severity, locationText(row), row.title, row.category, row.verdict, row.fixExplanation ?? "none recorded",
      row.businessContext ? row.businessContext.rank : anyContext ? "not set" : "none declared",
      row.businessContext ? `${row.businessContext.tags.join("; ")}${row.businessContext.tags.length ? " " : ""}(shift ${row.businessContext.shift})` : "",
      row.description.length > 1500 ? `${row.description.slice(0, 1500)}...` : row.description,
      "", "", "", "", findingsSha256.slice(0, 16),
    ].map(csvCell).join(","));
  }
  return `﻿${lines.join("\r\n")}\r\n`;
}

const money = (value: number | undefined): string => value === undefined ? `${NOT_RECORDED} (the provider reported no cost)` : `$${value.toFixed(4)}`;
const seconds = (ms: number | undefined): string => ms === undefined || !Number.isFinite(ms) ? NOT_RECORDED : `${(ms / 1000).toFixed(1)} s`;

function runJson(run: SheetRun, count: number, findingsSha256: string): Record<string, unknown> {
  return {
    schema: SHEET_SCHEMA,
    generatedAt: run.generatedAt,
    source: run.source,
    command: run.command,
    cliVersion: run.cliVersion,
    repository: { target: run.target ?? null, commit: run.commit ?? null, uncommittedChanges: run.uncommittedChanges ?? null },
    scanId: run.scanId ?? null,
    model: run.model ?? null,
    reasoning: run.reasoning ?? null,
    scanners: run.scanners ?? null,
    startedAt: run.startedAt ?? null,
    completedAt: run.completedAt ?? null,
    durationMs: run.durationMs ?? null,
    costUsd: run.costUsd ?? null,
    budgetUsd: run.budgetUsd ?? null,
    tokens: run.tokens ?? null,
    status: run.status ?? null,
    coverage: run.coverage ?? null,
    warnings: run.warnings ?? [],
    findings: { count, sha256: findingsSha256 },
  };
}

function readme(run: SheetRun, rows: readonly SheetFinding[], findingsSha256: string): string {
  const scanners = run.scanners === undefined ? NOT_RECORDED : run.scanners.length ? run.scanners.map(s => !s.version ? `${s.id} (version not reported)` : s.version.toLowerCase().startsWith(s.id.toLowerCase()) ? s.version : `${s.id} ${s.version}`).join(", ") : "none ran before the model";
  return `${[
    "# Evaluation sheet",
    "",
    "**This sheet is for human judgement. It is not an accuracy result.** Nothing in it says how many findings are right or how many real flaws the scan missed. The columns `true positive`, `false positive`, `unsure` and `notes` in `review.csv` are blank on purpose: a person fills them in. Counts made from one small repository and one reviewer are an opinion about that repository, not a measure of a tool.",
    "",
    "## How to use it",
    "",
    "1. Open `review.csv` in a spreadsheet. Rows are ordered by severity, then path, then line; a finding without a location comes last in its severity.",
    "2. For each row read the code at the location, then put a mark (for example `x`) in exactly one of `true positive`, `false positive` or `unsure`. Write why in `notes`.",
    "3. To compare tools, run each on the same repository at the same commit, and have each tool's findings judged the same way, ideally by people who do not know which tool wrote them.",
    "4. Two reviewers who want to be sure they judged the same output compare the list hash below.",
    "",
    "## What was run",
    "",
    `- Command: \`${run.command.replace(/`/g, "'")}\``,
    `- CLI version: \`${run.cliVersion}\``,
    `- Repository: ${run.target ? `\`${run.target}\`` : NOT_RECORDED}, commit ${run.commit ? `\`${run.commit}\`${run.uncommittedChanges ? " (the working tree had uncommitted changes, so the code that was scanned may differ from this commit)" : ""}` : NOT_RECORDED}`,
    `- Model: ${run.model ? `\`${run.model}\`${run.reasoning ? ` (reasoning ${run.reasoning})` : ""}` : NOT_RECORDED}`,
    `- Pattern scanners before the model: ${scanners}`,
    `- Cost: ${money(run.costUsd)}${run.budgetUsd !== undefined ? ` (budget $${run.budgetUsd})` : ""}${run.tokens !== undefined ? `, ${run.tokens} tokens` : ""}`,
    `- Time: ${seconds(run.durationMs)}`,
    `- Scan status: ${run.status ?? NOT_RECORDED}`,
    `- Coverage: ${run.coverage ?? NOT_RECORDED}`,
    ...(run.warnings?.length ? ["", "Warnings from the scan:", ...run.warnings.map(w => `- ${oneLine(w)}`)] : []),
    ...(run.source === "stored" ? ["", "This sheet was rebuilt from stored findings. The findings database does not keep the cost, model, scanner versions or coverage of a scan, so those are written as not recorded here. Write the sheet with `0security scan --evaluation-sheet <folder>` to keep them."] : []),
    "",
    "## The findings",
    "",
    `- ${rows.length} finding${rows.length === 1 ? "" : "s"}${rows.length === 0 ? ". An empty sheet is not a clean result: read the coverage line above for what was reviewed" : ""}.`,
    `- List hash (SHA-256 of \`findings.json\`): \`${findingsSha256}\`. The last column of \`review.csv\` carries its first 16 characters. Check it with \`shasum -a 256 findings.json\`.`,
    "- The verification verdict says whether anything checked the finding. \"not verified\" means nothing did. No verdict, including a matched script, shows that a finding is true; the script is written by the model.",
    "- The business-context rank is the position in the order of the work priorities the operator declared (`--business-context`). It does not change severity and is not observed exposure.",
    "- Fix explanations are written by the model and have not been tried.",
    "",
    "## Files",
    "",
    "| File | What it holds |",
    "| --- | --- |",
    "| `review.csv` | One row per finding with the blank judgement columns. UTF-8 with a byte order mark; cells that a spreadsheet could read as a formula start with an apostrophe. |",
    "| `findings.json` | The same findings with all fields, in the same order. Its hash is the list hash. |",
    "| `run.json` | The command, version, repository commit, model, scanner versions, cost, time, status and coverage in machine-readable form. |",
    "| `README.md` | This file. |",
    "",
    "The sheet may quote the scanned code. Treat the folder as you treat the repository.",
  ].join("\n")}\n`;
}

/** Everything the folder will hold. No model, no network. */
export function buildSheet(findings: readonly Finding[], run: SheetRun, roots: readonly string[] = []): Sheet {
  const rows = sheetFindings(findings, roots);
  const findingsText = `${JSON.stringify({ schema: SHEET_SCHEMA, count: rows.length, findings: rows }, null, 2)}\n`;
  const findingsSha256 = sha256(findingsText);
  return {
    findings: rows,
    findingsSha256,
    files: [
      { name: "README.md", text: readme(run, rows, findingsSha256) },
      { name: "review.csv", text: reviewCsv(rows, findingsSha256) },
      { name: "findings.json", text: findingsText },
      { name: "run.json", text: `${JSON.stringify(runJson(run, rows.length, findingsSha256), null, 2)}\n` },
    ],
  };
}

/** What the scan covered, in words, from the facts the outcome holds. */
export function coverageStatement(outcome: ScanOutcome): string {
  const parts: string[] = [];
  if (outcome.tier?.skipped) parts.push("Skipped by the tier map: nothing was scanned.");
  else if (outcome.tier?.prepassOnly) parts.push("Pre-pass only: the findings are pattern-scanner hits, and no model reviewed the code.");
  else if (outcome.threadId === "none") parts.push("Nothing was scanned.");
  if (outcome.coverage) parts.push(`${outcome.coverage.statement}.`);
  else if (outcome.fileCoverage) parts.push(`The scan opened ${outcome.fileCoverage.opened} of ${outcome.fileCoverage.inScope} source files in scope${outcome.fileCoverage.unopenedCount ? `; ${outcome.fileCoverage.unopenedCount} not opened` : ""}.`);
  else if (!parts.length) parts.push("No file-level coverage was recorded for this scan; a model reviewed the folder in one thread and its own summary is not a coverage guarantee.");
  if (outcome.budgetExhausted) parts.push(`Stopped at the $${outcome.budgetUsd} budget; findings are partial.`);
  if (outcome.timedOut) parts.push("Stopped at the time limit; findings are partial.");
  if (outcome.shallowReview) parts.push(oneLine(outcome.shallowReview));
  return parts.join(" ");
}

export interface SheetRunInput {
  outcome: ScanOutcome;
  command: string;
  cliVersion: string;
  now: Date;
  model: string;
  reasoning?: string;
  commit?: string;
  uncommittedChanges?: boolean;
  scanners?: Array<{ id: string; version?: string }>;
}

export function sheetRunOf(input: SheetRunInput): SheetRun {
  const { outcome } = input;
  const warnings = [outcome.failure ? `The scan did not finish cleanly: ${oneLine(outcome.failure.message)}` : undefined, outcome.error && !outcome.failure ? oneLine(outcome.error) : undefined, outcome.unbatched ? oneLine(outcome.unbatched) : undefined].filter((text): text is string => text !== undefined);
  const duration = Date.parse(outcome.completedAt) - Date.parse(outcome.startedAt);
  return {
    source: "scan", generatedAt: input.now.toISOString(), command: input.command, cliVersion: input.cliVersion, target: outcome.target,
    ...(input.commit ? { commit: input.commit } : {}), ...(input.uncommittedChanges !== undefined ? { uncommittedChanges: input.uncommittedChanges } : {}),
    ...(outcome.threadId !== "none" ? { scanId: outcome.threadId } : {}),
    ...(outcome.threadId === "none" || outcome.tier?.prepassOnly ? {} : { model: input.model, ...(input.reasoning ? { reasoning: input.reasoning } : {}) }),
    startedAt: outcome.startedAt, completedAt: outcome.completedAt, ...(Number.isFinite(duration) ? { durationMs: Math.max(0, duration) } : {}),
    ...(outcome.costUsd !== undefined ? { costUsd: outcome.costUsd } : {}), budgetUsd: outcome.budgetUsd, ...(outcome.tokens !== undefined ? { tokens: outcome.tokens } : {}),
    status: scanStatus(outcome), coverage: coverageStatement(outcome), warnings,
    ...(input.scanners ? { scanners: input.scanners } : {}),
  };
}

/** `argv` as one line a person can paste: arguments with spaces or shell characters are single-quoted. */
export function commandLineOf(argv: readonly string[]): string {
  const quote = (arg: string): string => /^[A-Za-z0-9_@%+=:,./-]+$/.test(arg) ? arg : `'${arg.replace(/'/g, "'\\''")}'`;
  return ["0security", ...argv.map(quote)].join(" ");
}

/**
 * Throws unless the folder is new, empty, or `overwrite` was asked for; refuses links. Called before a scan spends anything.
 * Returns the resolved path.
 */
export function checkSheetFolder(folder: string, overwrite: boolean): string {
  const target = resolve(folder);
  let info;
  try { info = lstatSync(target); } catch { info = undefined; }
  if (info) {
    if (info.isSymbolicLink()) throw new UsageError(`'${folder}' is a symbolic link; give a real folder.`);
    if (!info.isDirectory()) throw new UsageError(`'${folder}' exists and is not a folder.`);
    const present = readdirSync(target);
    if (present.length && !overwrite) throw new UsageError(`'${folder}' is not empty. Use a new or empty folder, or pass the overwrite option to replace the sheet files in it (other files are left alone).`);
  } else {
    const parent = dirname(target);
    if (!existsSync(parent) || !statSync(parent).isDirectory()) throw new UsageError(`The parent of '${folder}' does not exist.`);
  }
  return target;
}

/** Writes the sheet's own fixed files. With `overwrite`, only files of those names are replaced and only if they are regular files. */
export function writeSheet(folder: string, sheet: Sheet, overwrite: boolean): string {
  const target = checkSheetFolder(folder, overwrite);
  mkdirSync(target, { recursive: true });
  for (const file of sheet.files) {
    const path = join(target, file.name);
    let existing;
    try { existing = lstatSync(path); } catch { existing = undefined; }
    if (existing && !existing.isFile()) throw new UsageError(`Refusing to overwrite ${file.name}: it is not a regular file.`);
  }
  for (const file of sheet.files) writeFileSync(join(target, file.name), file.text, { mode: 0o600 });
  return target;
}
