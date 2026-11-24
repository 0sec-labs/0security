import type { Command } from "commander";
import chalk from "chalk";
import { acceptanceExpiresWithin, describeAttackerImpact, compareFindingsBySeverity, effectiveTriageStatus } from "@0/engine/shared";
import type { Finding, FindingTriageStatus, LayerVerdict } from "@0/engine/shared";
import { writePresentationLine, writePresentationErrorLine } from "../presentation/process-output.js";
import {
  FindingsService,
  listOsecRunDatabasePaths,
  osecDB,
  resolveOsecDbPath,
  resolveOsecRunStorage,
} from "@0/engine/storage";
import { buildFindingConsoleCommand } from "../finding-handoff.js";
import { resolveFindingId, shortFindingId, shortFingerprint } from "../finding-id.js";
import { rowVerification, verificationPhrase } from "../finding-verification.js";
import { reproductionDetail, reproductionPhrase, rowReproduction } from "../finding-reproduction.js";
import { auditTriage, buildTriageRequest, triageLabel, type TriageFlags } from "./findings-triage.js";
import { UsageError } from "./output.js";
import { foldSimilarGroups } from "./findings-dedupe.js";
import { adjustmentFor, contextScore, describeAdjustment, findingPath, loadBusinessContext, type BusinessContext } from "../business-context.js";

type FindingsListOptions = {
  dbPath?: string;
  scan?: string;
  severity?: string;
  category?: string;
  status?: string;
  triage?: string;
  expiring?: string;
  scope?: string;
  context?: string;
  limit?: string;
  all?: boolean;
};

type FindingRow = {
  id: string;
  scanId: string;
  title: string;
  severity: string;
  category: string;
  status: string;
  fingerprint?: string | null;
  triageStatus?: string | null;
  triageNote?: string | null;
  triageExpiresAt?: string | null;
  triageApprover?: string | null;
  /** Declared-scope label from `0 scan --scope`; null when no declared vector names the finding. */
  scope?: string | null;
  scopeReason?: string | null;
  scopeSource?: string | null;
  /** JSON of the second-pass verification from `0 findings verify`; null until verified. */
  modelVerification?: string | null;
  /** JSON of the proposed proof and harness result; null until either exists. */
  reproduction?: string | null;
  pocSteps?: string | null;
  timestamp: number;
  score?: number | null;
  cvssScore?: number | null;
  cvssVector?: string | null;
  impactAssessment?: string | null;
  templateId: string;
  description: string;
  evidenceRequest: string;
  evidenceResponse: string;
  evidenceAnalysis?: string | null;
  /**
   * JSON-encoded `LayerVerdict[]` as persisted by the scanner. Nullable and
   * possibly malformed — it is a TEXT column written across engine versions,
   * so `parseLayerVerdicts` treats any parse failure as "no record" rather
   * than throwing in a display path.
   */
  layerVerdicts?: string | null;
};

/**
 * Decode the persisted `layerVerdicts` column into the array shape
 * `summarizeTriageProvenance` expects.
 *
 * Intentionally lenient: this feeds a read-only display, and a finding whose
 * verdict blob is unreadable should still render its evidence. A decode
 * failure yields `[]`, which provenance reports as every layer `unrecorded` —
 * the honest answer, and never a claim that a layer ran.
 */
function parseLayerVerdicts(raw: string | null | undefined): LayerVerdict[] {
  if (!raw) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as LayerVerdict[]) : [];
  } catch {
    return [];
  }
}

function resolveFindingsOptions(opts: FindingsListOptions, command?: Command): FindingsListOptions {
  const inherited = command?.parent && typeof command.parent.opts === "function"
    ? command.parent.opts() as FindingsListOptions
    : {};
  const local = command && typeof command.opts === "function"
    ? command.opts() as FindingsListOptions
    : {};
  return { ...inherited, ...local, ...opts };
}

/**
 * Resolve the effective `--db-path` for a subcommand action, falling back
 * to the parent `findings` command's parsed option when the subcommand's
 * own slot is empty. Commander binds `--db-path` to the parent when both
 * declare it (see #324), so subcommand actions cannot rely on `opts.dbPath`
 * alone.
 */
function resolveDbPath(
  opts: { dbPath?: string; scan?: string },
  command?: Command,
): string | undefined {
  if (opts.dbPath) return opts.dbPath;
  const parentOpts =
    command?.parent && typeof command.parent.opts === "function"
      ? command.parent.opts() as { dbPath?: string; scan?: string }
      : undefined;
  if (parentOpts?.dbPath) return parentOpts.dbPath;

  const scanId = opts.scan ?? parentOpts?.scan;
  if (!scanId) return undefined;
  return resolveOsecRunStorage({ runId: scanId, resume: true }).dbPath;
}

function withFindingsListOptions(command: Command, options: { defaultLimit?: string } = {}): Command {
  const withFilters = command
    .option("--db-path <path>", "Path to SQLite database")
    .option("--scan <scanId>", "Filter by scan ID")
    .option("--severity <severity>", "Filter by severity: critical, high, medium, low, info")
    .option("--category <category>", "Filter by attack category")
    .option("--status <status>", "Filter by status: discovered, verified, confirmed, scored, reported, fixed, false-positive")
    .option("--triage <triage>", "Filter by triage: new, accepted, suppressed")
    .option("--expiring <days>", "Only accepted risks that expire within this many days")
    .option("--context <file>", "Business context file (JSON): order findings by what matters to you, with the reason shown. See the docs")
    .option("--scope <scope>", "in: findings not labelled out of scope; out: only those the declared scope (0security scan --scope) labelled out of scope; all (default): both, each labelled");
  return options.defaultLimit
    ? withFilters.option("--limit <n>", "Max findings/groups to show", options.defaultLimit)
    : withFilters.option("--limit <n>", "Max findings/groups to show");
}

function resolveFindingByPrefix(rows: FindingRow[], id: string): FindingRow | undefined {
  return resolveFindingId(rows, id);
}

/** Opens the database that holds this finding (scans keep one database per run); the shared one when none does. */
async function openDatabaseHolding(id: string, selectedDbPath?: string): Promise<{ db: osecDB; dbPath: string | undefined }> {
  if (selectedDbPath) return { db: new osecDB(selectedDbPath), dbPath: selectedDbPath };
  if (listOsecRunDatabasePaths().length === 0) return { db: new osecDB(), dbPath: undefined };
  const source = await new FindingsService({ sharedDbPath: resolveOsecDbPath(), listPaths: listOsecRunDatabasePaths }).sourceOfFinding(id, { prefix: true });
  return { db: new osecDB(source?.id), dbPath: source?.id };
}

function triageColor(status?: string | null) {
  switch (status?.split(" ")[0]) {
    case "accepted":
      return chalk.green;
    case "suppressed":
      return chalk.gray;
    default:
      return chalk.cyan;
  }
}

function severityColor(severity: string) {
  return severity === "critical" ? chalk.red.bold
    : severity === "high" ? chalk.redBright
    : severity === "medium" ? chalk.yellow
    : severity === "low" ? chalk.blue
    : chalk.gray;
}

function statusColor(status: string) {
  return status === "reported" ? chalk.green
    : status === "scored" ? chalk.cyan
    : status === "verified" ? chalk.yellow
    : status === "false-positive" ? chalk.strikethrough.gray
    : chalk.white;
}

type PriorityRow = Pick<FindingRow, "id" | "category" | "severity" | "cvssScore" | "impactAssessment" | "timestamp">;
function priorityFinding(row: PriorityRow) {
  let impactAssessment: unknown;
  try { impactAssessment = row.impactAssessment ? JSON.parse(row.impactAssessment) : undefined; } catch { /* Legacy malformed JSON remains unassessed. */ }
  return { severity: row.severity, category: row.category, cvssScore: row.cvssScore, impactAssessment };
}
function compareRows(a: PriorityRow, b: PriorityRow): number {
  return compareFindingsBySeverity(priorityFinding(a), priorityFinding(b)) || b.timestamp - a.timestamp || b.id.localeCompare(a.id);
}
function renderVerification(row: FindingRow, withProof = true): void {
  const phrase = verificationPhrase(rowVerification(row));
  if (phrase) console.log(`  ${chalk.gray(phrase)}`);
  const proof = withProof ? reproductionPhrase(row as { reproduction?: unknown; pocSteps?: unknown }) : undefined;
  if (proof) console.log(`  ${chalk.gray(`proof: ${proof}`)}`);
}
/** Orders by severity moved by your business context, then as without it. Severity itself is never changed. */
function contextComparer(context: BusinessContext): (a: FindingRow, b: FindingRow) => number {
  const score = (row: FindingRow) => contextScore(row.severity, adjustmentFor(context, findingPath((row as { reviewAnnotation?: unknown }).reviewAnnotation)));
  return (a, b) => score(b) - score(a) || compareRows(a, b);
}
function renderPriority(row: FindingRow, context?: BusinessContext): void {
  console.log(`  ${chalk.white.bold(row.title)}${row.scope === "out-of-scope" ? chalk.yellow("  [out of scope]") : ""}`);
  const why = context ? describeAdjustment(adjustmentFor(context, findingPath((row as { reviewAnnotation?: unknown }).reviewAnnotation))) : "";
  if (why) console.log(`  ${chalk.gray("Business context:")} ${why}`);
  if (row.scope === "out-of-scope") console.log(`  ${chalk.gray("Outside declared scope:")} ${row.scopeReason ?? "no reason given"}${row.scopeSource ? chalk.gray(` (${row.scopeSource})`) : ""}`);
  const attacker = describeAttackerImpact(priorityFinding(row));
  if (attacker) console.log(`  ${chalk.gray(`${attacker.label ?? "What an attacker can do"}:`)} ${attacker.can}`);
  console.log(`  ${chalk.gray("Technical severity:")} ${severityColor(row.severity)(row.severity)}${row.cvssScore != null ? `  CVSS: ${row.cvssScore}` : ""}${row.cvssVector ? `  CVSS vector: ${row.cvssVector}` : ""}  ${statusColor(row.status)(row.status)}  ${triageColor(effectiveTriageStatus(row))(triageLabel(row))}`);
}

async function renderFindingsList(opts: FindingsListOptions): Promise<void> {
  const selectedDbPath = resolveDbPath(opts);
  const dbPaths = selectedDbPath
    ? [selectedDbPath]
    : listOsecRunDatabasePaths();
  const legacyDbPath = resolveOsecDbPath();
  if (!selectedDbPath && !dbPaths.includes(legacyDbPath)) {
    dbPaths.push(legacyDbPath);
  }

  const limit = Number(opts.limit ?? "50");
  if (!Number.isSafeInteger(limit) || limit < 0 || limit > 5000) throw new Error("Finding limit must be an integer between 0 and 5000.");
  // Read the context before any database is opened: a bad file changes nothing.
  const context = opts.context ? loadBusinessContext(opts.context) : undefined;
  const choice = (name: string, value: string | undefined, allowed: readonly string[]): void => { if (value !== undefined && !allowed.includes(value)) throw new Error(`Unknown ${name} "${value}". Use one of: ${allowed.join(", ")}.`); };
  choice("severity", opts.severity, ["critical", "high", "medium", "low", "info"]);
  choice("status", opts.status, ["discovered", "verified", "confirmed", "scored", "reported", "fixed", "false-positive"]);
  choice("triage", opts.triage, ["new", "accepted", "suppressed"]);
  choice("scope", opts.scope, ["in", "out", "all"]);
  let expiringDays: number | undefined;
  if (opts.expiring !== undefined) {
    expiringDays = Number(opts.expiring);
    if (!Number.isSafeInteger(expiringDays) || expiringDays < 1 || expiringDays > 3650) throw new UsageError("--expiring must be a whole number of days from 1 to 3650.");
    if (opts.triage && opts.triage !== "accepted") throw new UsageError("--expiring lists accepted risks; drop --triage or use --triage accepted.");
  }
  // The stored status of a lapsed acceptance is still "accepted", so "new" and "expiring" are decided here, on the effective status.
  const scopeWanted = (row: FindingRow): boolean => opts.scope === undefined || opts.scope === "all" || (opts.scope === "out") === (row.scope === "out-of-scope");
  const wanted = (row: FindingRow): boolean => scopeWanted(row) && (!opts.triage || effectiveTriageStatus(row) === opts.triage) && (expiringDays === undefined || acceptanceExpiresWithin(row, expiringDays));
  const filterLater = opts.triage === "new" || expiringDays !== undefined || opts.scope === "in" || opts.scope === "out";
  const filters = { scanId: opts.scan, severity: opts.severity, category: opts.category, status: opts.status, triageStatus: filterLater ? undefined : opts.triage };
  const queryLimit = filterLater || context ? 5000 : limit;
  const rows: FindingRow[] = [];
  const groups: Array<{ fingerprint: string; latest: FindingRow; count: number; scans: number; similar?: number }> = [];
  if (!opts.all && !opts.scan && !selectedDbPath && dbPaths.length > 1) {
    // The same merged view the web Findings page uses: one family per fingerprint across every database.
    const merged = await new FindingsService({ sharedDbPath: resolveOsecDbPath(), listPaths: listOsecRunDatabasePaths }).list();
    const selected = merged.families.filter(({ latest }) =>
      (!opts.severity || latest.severity === opts.severity) && (!opts.category || latest.category === opts.category)
      && (!opts.status || latest.status === opts.status) && wanted(latest as FindingRow)).slice(0, context ? undefined : limit);
    for (const family of selected) groups.push({ fingerprint: family.key, latest: family.latest as FindingRow, count: family.count, scans: family.scanCount });
  } else {
    for (const dbPath of dbPaths) {
      const db = new osecDB(dbPath);
      try {
        if (opts.all) rows.push(...(db.listFindingsBySeverity({ ...filters, limit: queryLimit }) as FindingRow[]).filter(wanted));
        else for (const family of db.listFindingFamiliesBySeverity({ ...filters, limit: queryLimit }).filter(entry => wanted(entry.latest as FindingRow))) groups.push({ fingerprint: family.key, latest: family.latest as FindingRow, count: family.count, scans: family.scanCount });
      } finally { db.close(); }
    }
  }
  const order = context ? contextComparer(context) : compareRows;
  rows.sort(order);
  groups.sort((a, b) => order(a.latest as FindingRow, b.latest as FindingRow));
  // One line per flaw: groups that cite the same place under the same category are one (see findings-dedupe.ts).
  groups.splice(0, groups.length, ...foldSimilarGroups(groups));
  if (!(opts.all ? rows.length : groups.length)) {
    console.log(chalk.gray("No findings found."));
    return;
  }
  console.log("");
  console.log(chalk.red.bold("  \u25C6 0") + chalk.gray(opts.all ? ` findings (${Math.min(rows.length, limit)})` : ` finding groups (${Math.min(groups.length, limit)})`));
  console.log("");
  if (opts.all) {
    for (const f of rows.slice(0, limit)) {
      renderPriority(f, context);
      renderVerification(f);
      console.log(`  ${chalk.gray(shortFindingId(f.id))}  ${chalk.gray(f.category)}  ${chalk.gray(`scan:${f.scanId.slice(0, 8)}`)}  ${chalk.gray(`fp:${shortFingerprint(f.fingerprint ?? f.id)}`)}`);
      console.log("");
    }
    return;
  }
  for (const group of groups.slice(0, limit)) {
    const f = group.latest;
    renderPriority(f, context);
    renderVerification(f);
    console.log(`  ${chalk.gray(`fp:${shortFingerprint(group.fingerprint)}`)}  ${chalk.gray(f.category)}  ${chalk.gray(`${group.count} hits / ${group.scans} scans${group.similar ? `, ${group.similar} similar merged` : ""}`)}  ${chalk.gray(`latest:${f.scanId.slice(0, 8)}`)}`);
    if (f.triageNote) console.log(`  ${chalk.gray("note:")} ${chalk.dim(f.triageNote)}${f.triageApprover && effectiveTriageStatus(f) === "accepted" ? chalk.gray(` (approver: ${f.triageApprover})`) : ""}`);
    console.log("");
  }
}

async function mutateTriage(
  id: string,
  triageStatus: FindingTriageStatus,
  flags: TriageFlags,
  dbPath?: string,
): Promise<void> {
  // Validate before opening a database: a bad flag changes nothing.
  const request = buildTriageRequest(triageStatus, flags);
  const { db } = await openDatabaseHolding(id, dbPath);
  try {
    const rows = db.listFindings({ limit: 5000 }) as FindingRow[];
    const finding = resolveFindingByPrefix(rows, id);
    if (!finding) {
      throw new Error(`Finding '${id}' not found.`);
    }
    db.updateFindingTriage(finding.id, request.status, request.note, request.details);
    auditTriage({ findingId: finding.id, fingerprint: finding.fingerprint ?? finding.id, from: String(finding.triageStatus ?? "new"), request });
    const related = finding.fingerprint ? db.getRelatedFindings(finding.fingerprint) as FindingRow[] : [finding];
    console.log(
      `${chalk.green("Updated")} ${chalk.white(related.length.toString())} ${chalk.gray("findings in family")} ${chalk.gray(`fp:${shortFingerprint(finding.fingerprint ?? finding.id)}`)} ${chalk.gray(`→ ${triageStatus}${request.details.expiresAt ? ` until ${request.details.expiresAt.slice(0, 10)}` : ""}`)}`
    );
  } finally {
    db.close();
  }
}

export function registerFindingsCommand(program: Command): void {
  // `--all` only declared on the parent so `0 findings list --all`
  // and `0 findings --all list` both resolve via the parent's parsed
  // opts (see #325). If both parent and subcommand declared it, Commander
  // would clobber the user's `true` with the subcommand's default `false`.
  const findingsCmd = withFindingsListOptions(
    program
      .command("findings")
      .description("Browse and manage persisted findings"),
    { defaultLimit: "50" },
  )
    .option("--all", "Show raw finding rows instead of grouped fingerprints", false)
    .action(async (opts: FindingsListOptions, command: Command) => {
      const resolved = resolveFindingsOptions(opts, command);
      await renderFindingsList(resolved);
    });

  withFindingsListOptions(
    findingsCmd
      .command("list")
      .description("List findings from the database")
      // No default: with positional options the parent never sees a flag typed after `list`, and a default here would clobber the parent's `--all`.
      .option("--all", "Show raw finding rows instead of grouped fingerprints")
  ).action(async (opts: FindingsListOptions, command: Command) => {
    const resolved = resolveFindingsOptions(opts, command);
    await renderFindingsList(resolved);
  });

  findingsCmd
    .command("show")
    .description("Show detailed information about a finding")
    .argument("<id>", "Finding ID (full or prefix)")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--json", "Print JSON")
    .action(async (id: string, opts: { dbPath?: string; json?: boolean }, command: Command) => {
      const { db, dbPath: selectedDbPath } = await openDatabaseHolding(id, resolveDbPath(opts, command));

      try {
        const all = db.listFindings({ limit: 5000 }) as FindingRow[];
        const finding = resolveFindingByPrefix(all, id);
        if (!finding) {
          throw new Error(`Finding '${id}' not found.`);
        }

        const related = finding.fingerprint ? db.getRelatedFindings(finding.fingerprint) as FindingRow[] : [finding];

        if (opts.json) {
          const { modelVerification: _raw, reproduction: _rawRepro, ...plain } = finding as FindingRow & { reproduction?: unknown };
          const stored = rowVerification(finding);
          const proofRecord = rowReproduction(finding as { reproduction?: unknown; pocSteps?: unknown });
          console.log(JSON.stringify({ ...plain, ...(stored ? { verification: stored } : {}), ...(proofRecord ? { reproduction: proofRecord } : {}), related: related.map((row) => ({ id: row.id, scanId: row.scanId, status: row.status, triage: row.triageStatus ?? "new" })) }, null, 2));
          return;
        }
        console.log("");
        console.log(chalk.red.bold("  \u25C6 0") + chalk.gray(" finding detail"));
        console.log("");

        renderPriority(finding);
        renderVerification(finding, false);
        console.log(`  ${chalk.gray("Category:")} ${finding.category}`);
        if (finding.score != null) {
          console.log(`  ${chalk.gray("Score:")} ${chalk.cyan(String(finding.score) + "/100")}`);
        }
        console.log("");
        console.log(`  ${chalk.gray("ID:")}         ${finding.id}`);
        console.log(`  ${chalk.gray("Scan:")}       ${finding.scanId}`);
        console.log(`  ${chalk.gray("Template:")}   ${finding.templateId}`);
        console.log(`  ${chalk.gray("Fingerprint:")} ${(finding.fingerprint ?? finding.id)}`);
        console.log(`  ${chalk.gray("Family size:")} ${related.length}`);
        console.log(`  ${chalk.gray("Time:")}       ${new Date(finding.timestamp).toISOString()}`);
        if (finding.triageNote) {
          console.log(`  ${chalk.gray("Triage:")}     ${finding.triageNote}`);
        }
        if (finding.triageExpiresAt || finding.triageApprover) {
          console.log(`  ${chalk.gray("Acceptance:")} ${triageLabel(finding)}${finding.triageApprover ? `, approver (label): ${finding.triageApprover}` : ""}`);
        }
        const verification = rowVerification(finding);
        if (verification) {
          console.log(`  ${chalk.gray("Verification:")} ${verification.verdict}${verification.advisorySeverity ? `, advisory severity ${verification.advisorySeverity}` : ""} (${verification.model ?? "model"}, ${verification.verifiedAt.slice(0, 10)}; advice only, severity and status are unchanged)`);
          console.log(`  ${chalk.dim(verification.reasoning)}`);
          if (verification.applied) console.log(`  ${chalk.gray("Suppressed by 0security findings verify --apply.")}`);
        }
        const proofDetail = reproductionDetail(finding as { reproduction?: unknown; pocSteps?: unknown });
        if (proofDetail) console.log(`  ${chalk.gray(`${proofDetail.label}:`)}        ${proofDetail.line}`);
        console.log("");
        console.log(`  ${chalk.gray("Description:")}`);
        console.log(`  ${finding.description}`);
        console.log("");
        console.log(`  ${chalk.gray("Evidence \u2014 Request:")}`);
        console.log(`  ${chalk.dim(finding.evidenceRequest)}`);
        console.log("");
        console.log(`  ${chalk.gray("Evidence \u2014 Response:")}`);
        console.log(`  ${chalk.dim(finding.evidenceResponse)}`);
        if (finding.evidenceAnalysis) {
          console.log("");
          console.log(`  ${chalk.gray("Evidence \u2014 Analysis:")}`);
          console.log(`  ${chalk.dim(finding.evidenceAnalysis)}`);
        }
        if (related.length > 1) {
          console.log("");
          console.log(`  ${chalk.gray("Related Findings:")}`);
          for (const row of related.slice(0, 20)) {
            console.log(`  ${chalk.gray(shortFindingId(row.id))} ${chalk.gray(`scan:${row.scanId.slice(0, 8)}`)} ${chalk.white(row.status)} ${triageColor(row.triageStatus)(String(row.triageStatus ?? "new"))}`);
          }
        }
        console.log(`  ${chalk.gray("Continue in chat:")}`);
        console.log(`  ${chalk.cyan(buildFindingConsoleCommand(finding, selectedDbPath))}`);
        console.log("");
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exit(1);
      } finally {
        db.close();
      }
    });

  findingsCmd
    .command("accept")
    .description("Mark a finding family as accepted")
    .argument("<id>", "Finding ID (full or prefix)")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--reason <text>", "Why the risk is accepted (required; --note is the same)")
    .option("--note <text>", "Alias of --reason")
    .option("--expires <date|days>", "When the acceptance ends: 2026-12-31 or 90d (required). The finding reopens after it.")
    .option("--approver <name>", "Who approved it: a label you type, not a login")
    .action(async (id: string, opts: TriageFlags & { dbPath?: string }, command: Command) => {
      await mutateTriage(id, "accepted", opts, resolveDbPath(opts, command));
    });

  findingsCmd
    .command("suppress")
    .description("Suppress a finding family across duplicate occurrences")
    .argument("<id>", "Finding ID (full or prefix)")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--note <text>", "Suppression reason")
    .option("--approver <name>", "Who approved it: a label you type, not a login")
    .action(async (id: string, opts: TriageFlags & { dbPath?: string }, command: Command) => {
      await mutateTriage(id, "suppressed", opts, resolveDbPath(opts, command));
    });

  findingsCmd
    .command("reopen")
    .description("Reset a finding family back to new")
    .argument("<id>", "Finding ID (full or prefix)")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--note <text>", "Optional triage note")
    .action(async (id: string, opts: TriageFlags & { dbPath?: string }, command: Command) => {
      await mutateTriage(id, "new", opts, resolveDbPath(opts, command));
    });
}
