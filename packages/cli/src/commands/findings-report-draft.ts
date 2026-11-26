/**
 * `0 findings report-draft <finding> --stage early-warning|notification|final` writes the text of a draft report
 * about one finding, for a manufacturer that has to tell the authorities about an actively exploited vulnerability.
 *
 * It is deterministic and calls no model. Every field is either copied from the finding record, copied from a fact
 * the operator supplied, or left as a visible `[to be completed by the manufacturer: ...]` blank. Nothing here
 * claims exploitation, user impact or a patch that the operator did not supply, and nothing is submitted: a person
 * reviews the draft and files it through the authority's own channel.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import type { Command } from "commander";
import { attackerImpactSentence, VERSION, type Finding } from "@0/engine/shared";
import { findingDatabasePaths, loadFindingFocus } from "../finding-focus.js";
import { resolveFindingId, shortFingerprint } from "../finding-id.js";
import { osecDB } from "@0/engine/storage";
import { finishWithError, UsageError } from "./output.js";
import { contextOptionsOf, loadContextFor, REPOSITORY_FLAG_HELP, withBusinessContext, type LoadedContext } from "../business-context-load.js";

export const REPORT_STAGES = ["early-warning", "notification", "final"] as const;
export type ReportStage = (typeof REPORT_STAGES)[number];

/** Facts only the manufacturer knows. Each is optional; a missing one becomes a visible blank. */
export interface ReportFacts {
  product?: string;
  manufacturer?: string;
  contact?: string;
  affectedVersions?: string;
  exploitedSince?: string;
  /** How the manufacturer knows the vulnerability is being exploited, in the operator's words. */
  exploitationEvidence?: string;
  maliciousActor?: string;
  memberStates?: string;
  mitigation?: string;
  userMeasures?: string;
  /** What is available to users (a fixed version, an update, a workaround), in the operator's words. */
  correctiveMeasure?: string;
  correctiveMeasureDate?: string;
  /** Files the operator attaches by reference: only name, size and SHA-256 are written, never the content. */
  evidenceFiles?: Array<{ name: string; bytes: number; sha256: string }>;
}

const FACT_KEYS: ReadonlyArray<keyof Omit<ReportFacts, "evidenceFiles">> = [
  "product", "manufacturer", "contact", "affectedVersions", "exploitedSince", "exploitationEvidence", "maliciousActor",
  "memberStates", "mitigation", "userMeasures", "correctiveMeasure", "correctiveMeasureDate",
];

export interface DraftContext {
  finding: Finding;
  /** What was scanned, from the scan that recorded the finding. */
  target?: string;
  facts: ReportFacts;
  /** Version of `0` that wrote the draft. */
  toolVersion: string;
  /** When the draft was written (ISO-8601). */
  generatedAt: string;
}

const blank = (what: string): string => `[to be completed by the manufacturer: ${what}]`;
const clean = (value: string | undefined): string | undefined => (value && value.trim() ? value.trim() : undefined);
/** A supplied fact, or a visible blank. */
const fact = (value: string | undefined, what: string): string => clean(value) ?? blank(what);
/** One line in a table cell or list item: collapse whitespace and keep pipes from breaking a table. */
const oneLine = (value: string): string => value.replace(/\s+/g, " ").trim();
const cell = (value: string): string => oneLine(value).replace(/\|/g, "\\|");
const quote = (value: string): string => value.trim().split(/\r?\n/).map(line => `> ${line}`).join("\n");
const iso = (ms: number): string | undefined => (Number.isFinite(ms) && ms > 0 ? new Date(ms).toISOString() : undefined);

export const STAGE_TITLES: Readonly<Record<ReportStage, string>> = {
  "early-warning": "Early warning",
  notification: "Vulnerability notification",
  final: "Final report",
};

const STAGE_TIMING: Readonly<Record<ReportStage, string>> = {
  "early-warning": "the first, short report: within 24 hours of becoming aware of an actively exploited vulnerability",
  notification: "the second report: within 72 hours of becoming aware",
  final: "the last report, after a corrective or mitigating measure is available; the period is set by the Regulation",
};

/** What the finding record says about where the problem is. */
function location(finding: Finding): string | undefined {
  const at = finding.reviewAnnotation;
  if (!at?.path) return undefined;
  return `${at.path}${at.startLine ? `:${at.startLine}${at.endLine && at.endLine !== at.startLine ? `-${at.endLine}` : ""}` : ""}`;
}

function disclaimer(stage: ReportStage): string[] {
  return [
    `> **DRAFT. Not submitted.** This is a draft of the ${STAGE_TITLES[stage].toLowerCase()} prepared with a tool (\`0\`) from a finding record and from facts the operator supplied. It has not been reviewed by a person, it is not a legal opinion and it does not show that any obligation has been met.`,
    ">",
    "> A person at the manufacturer must read it, correct it, complete every blank and submit it through the channel the competent authority or CSIRT designates. Nothing has been sent anywhere. Reporting duties for actively exploited vulnerabilities come from Article 14 of Regulation (EU) 2024/2847 (the Cyber Resilience Act); confirm the current requirements, the content each report needs and the deadlines with the authority and your legal advisers before relying on this text.",
  ];
}

function sourceTable(ctx: DraftContext): string[] {
  const { finding, target } = ctx;
  const where = location(finding);
  const found = iso(finding.timestamp);
  const rows: Array<[string, string]> = [
    ["Finding id", `\`${finding.id}\`${finding.fingerprint ? ` (fingerprint \`${finding.fingerprint}\`)` : ""}`],
    ["Title", cell(finding.title)],
    ["Severity", `${finding.severity} (as recorded by the scanner or reviewer; not a measure of real-world exploitation)`],
    ...(finding.businessContext ? [["Operator business context (unverified; the severity is unchanged)", cell(finding.businessContext.rationale)] as [string, string]] : []),
    ["Category", cell(finding.category)],
    ["Where", where ? `\`${cell(where)}\`` : blank("location; the finding record has none")],
    ...(target ? [["Scanned target", `\`${cell(target)}\``] as [string, string]] : []),
    ["Recorded status", `${finding.status}${finding.triageStatus ? `, triage: ${finding.triageStatus}` : ""}${finding.workflowStatus ? `, workflow: ${finding.workflowStatus}` : ""}`],
    ["Record created in the findings database (not when the weakness was introduced or first exploited)", found ?? blank("date; the finding record has none")],
    ...(finding.tool ? [["Reported by", cell(finding.tool)] as [string, string]] : []),
    ...(finding.cvssScore !== undefined ? [["CVSS", `${finding.cvssScore}${finding.cvssVector ? ` (${cell(finding.cvssVector)})` : ""}`] as [string, string]] : []),
  ];
  return ["| Field | Value |", "| --- | --- |", ...rows.map(([key, value]) => `| ${key} | ${value} |`)];
}

function productSection(ctx: DraftContext): string[] {
  const { facts } = ctx;
  return [
    "## Manufacturer and product",
    "",
    `- Manufacturer: ${fact(facts.manufacturer, "legal name of the manufacturer")}`,
    `- Product with digital elements: ${fact(facts.product, "product name")}`,
    `- Affected versions: ${fact(facts.affectedVersions, "affected versions; the finding record does not establish them")}`,
    `- Contact for this report: ${fact(facts.contact, "name, role and contact details of the person who submits")}`,
    `- Member States where the product is made available: ${fact(facts.memberStates, "Member States")}`,
  ];
}

function exploitationSection(ctx: DraftContext, heading: string): string[] {
  const { facts } = ctx;
  const supplied = clean(facts.exploitedSince) || clean(facts.exploitationEvidence);
  return [
    heading,
    "",
    `- Exploited since / first known exploitation: ${fact(facts.exploitedSince, "date and time (UTC) of the first known exploitation")}`,
    `- How the manufacturer knows it is being exploited: ${fact(facts.exploitationEvidence, "the evidence of exploitation; the finding record is a scanner result and does not by itself show that anyone has exploited the vulnerability")}`,
    `- Suspected malicious act or actor: ${fact(facts.maliciousActor, "only if known; otherwise state that it is unknown")}`,
    ...(supplied ? [] : ["", "No exploitation facts were supplied. This draft therefore does not state that the vulnerability is being exploited. Confirm with your advisers whether a report is required before filing one."]),
  ];
}

function vulnerabilitySection(ctx: DraftContext, depth: "short" | "full"): string[] {
  const { finding } = ctx;
  const impact = attackerImpactSentence(finding);
  const lines = [
    "## The vulnerability (from the finding record)",
    "",
    ...sourceTable(ctx),
    "",
    "Attacker impact, as assessed in the finding record:",
    "",
    impact ? quote(impact) : blank("impact on the product and its users; the finding record has no assessed attacker impact"),
  ];
  if (depth === "full") {
    lines.push("", "Description from the finding record (review it before sending; it can contain details that help an attacker):", "", clean(finding.description) ? quote(finding.description) : blank("description"));
    if (clean(finding.triageNote)) lines.push("", "Triage note from the finding record:", "", quote(finding.triageNote!));
  }
  return lines;
}

function measuresSection(ctx: DraftContext, depth: "notification" | "final"): string[] {
  const { facts } = ctx;
  const lines = [
    "## Measures",
    "",
    `- Mitigation the manufacturer has taken or recommends: ${fact(facts.mitigation, "mitigating measures; none were supplied")}`,
    `- What users can do now: ${fact(facts.userMeasures, "measures users can take")}`,
  ];
  if (depth === "final") {
    lines.push(
      `- Corrective measure (security update or fix) available to users: ${fact(facts.correctiveMeasure, "the fix or update, how users get it; none was supplied, so none is claimed")}`,
      `- Date the corrective measure became available: ${fact(facts.correctiveMeasureDate, "date")}`,
    );
  } else if (clean(facts.correctiveMeasure)) {
    lines.push(`- Corrective measure: ${clean(facts.correctiveMeasure)}`);
  }
  return lines;
}

function evidenceSection(ctx: DraftContext): string[] {
  const files = ctx.facts.evidenceFiles ?? [];
  return [
    "## Supporting material",
    "",
    ...(files.length
      ? ["Files the operator named. Only their names and checksums are listed here; attach them yourself if you choose to.", "", "| File | Size | SHA-256 |", "| --- | --- | --- |", ...files.map(file => `| ${cell(file.name)} | ${file.bytes} bytes | \`${file.sha256}\` |`)]
      : [blank("supporting material, such as logs showing exploitation; none was supplied")]),
  ];
}

function sensitivity(): string[] {
  return [
    "## Sensitivity",
    "",
    `- Information that should be handled as sensitive, and why: ${blank("anything whose disclosure would help attackers before a fix is available")}`,
  ];
}

function footer(ctx: DraftContext): string[] {
  return ["---", "", `Draft generated ${ctx.generatedAt} by \`0\` ${ctx.toolVersion} from finding \`${ctx.finding.id}\`. Deterministic text, no model was used. Facts not marked as taken from the finding record come from the operator's flags or file and have not been checked.`];
}

/** The Markdown draft for one stage. */
export function buildReportDraft(stage: ReportStage, ctx: DraftContext): string {
  const head = [`# ${STAGE_TITLES[stage]} (draft): ${oneLine(ctx.finding.title)}`, "", `Stage: ${STAGE_TITLES[stage]}, ${STAGE_TIMING[stage]}.`, "", ...disclaimer(stage), ""];
  const body: string[][] = [];
  if (stage === "early-warning") {
    body.push(
      productSection(ctx),
      exploitationSection(ctx, "## Exploitation"),
      vulnerabilitySection(ctx, "short"),
      ["## Next", "", "The notification follows with more detail. Nothing in this early warning describes the technical cause beyond the title and category above."],
    );
  } else if (stage === "notification") {
    body.push(
      productSection(ctx),
      exploitationSection(ctx, "## Exploitation"),
      vulnerabilitySection(ctx, "full"),
      measuresSection(ctx, "notification"),
      evidenceSection(ctx),
      sensitivity(),
    );
  } else {
    body.push(
      productSection(ctx),
      vulnerabilitySection(ctx, "full"),
      exploitationSection(ctx, "## Exploitation and actors"),
      measuresSection(ctx, "final"),
      evidenceSection(ctx),
      ["## Lessons and follow-up", "", `- Root cause and what the manufacturer changes so it does not recur: ${blank("root cause analysis")}`],
      sensitivity(),
    );
  }
  return `${[...head, ...body.map(section => section.join("\n")).flatMap(section => [section, ""]), ...footer(ctx)].join("\n")}\n`;
}

export function buildAllDrafts(ctx: DraftContext): string {
  return REPORT_STAGES.map(stage => buildReportDraft(stage, ctx)).join("\n\n");
}

const MAX_FILE_BYTES = 200 * 1024 * 1024;
const MAX_FACTS_BYTES = 256 * 1024;

/** Name, size and SHA-256 of a file, read as bytes and never included in the draft. */
export function describeEvidenceFile(path: string): { name: string; bytes: number; sha256: string } {
  const full = resolve(path);
  let info;
  try { info = statSync(full); } catch { throw new UsageError(`--evidence-file '${path}' does not exist.`); }
  if (!info.isFile() || info.size > MAX_FILE_BYTES) throw new UsageError(`--evidence-file '${path}' must be a regular file of at most 200 MB.`);
  return { name: basename(full), bytes: info.size, sha256: createHash("sha256").update(readFileSync(full)).digest("hex") };
}

/** Facts from a JSON file, using the same names as the flags in camel case. Unknown keys are an error: a typo must not silently become a blank. */
export function readFactsFile(path: string): ReportFacts {
  const full = resolve(path);
  let text: string;
  try {
    const info = statSync(full);
    if (!info.isFile() || info.size > MAX_FACTS_BYTES) throw new Error("size");
    text = readFileSync(full, "utf8");
  } catch { throw new UsageError(`--facts '${path}' must be a JSON file of at most 256 KB.`); }
  let value: unknown;
  try { value = JSON.parse(text); } catch { throw new UsageError(`--facts '${path}' is not valid JSON.`); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new UsageError("--facts must be a JSON object.");
  const facts: ReportFacts = {};
  const files: string[] = [];
  for (const [key, entry] of Object.entries(value)) {
    if (key === "evidenceFiles") {
      if (!Array.isArray(entry) || entry.some(item => typeof item !== "string")) throw new UsageError("--facts: evidenceFiles must be a list of file paths.");
      files.push(...entry as string[]);
    } else if ((FACT_KEYS as readonly string[]).includes(key)) {
      if (typeof entry !== "string") throw new UsageError(`--facts: ${key} must be a string.`);
      (facts as Record<string, string>)[key] = entry;
    } else throw new UsageError(`--facts: unknown key '${key}'. Known keys: ${[...FACT_KEYS, "evidenceFiles"].join(", ")}.`);
  }
  if (files.length) facts.evidenceFiles = files.map(file => describeEvidenceFile(file));
  return facts;
}

export interface ReportDraftOptions {
  stage?: string; product?: string; manufacturer?: string; contact?: string; affectedVersions?: string; exploitedSince?: string;
  exploitationEvidence?: string; maliciousActor?: string; memberStates?: string; mitigation?: string; userMeasures?: string;
  correctiveMeasure?: string; correctiveMeasureDate?: string; evidenceFile?: string[]; facts?: string; output?: string; dbPath?: string;
  context?: string; repository?: string;
  /** The loaded business context; set by the command from --context or the findingsContext setting. */
  ranking?: LoadedContext
}

export interface ReportDraftDeps {
  out(text: string): void;
  err(text: string): void;
  write(path: string, text: string): void;
  load(id: string, dbPath?: string): { finding: Finding; target?: string };
  now(): Date;
  version: string;
}

export function runReportDraft(id: string, options: ReportDraftOptions, deps: ReportDraftDeps): void {
  const stage = options.stage;
  if (!stage || (stage !== "all" && !(REPORT_STAGES as readonly string[]).includes(stage))) throw new UsageError(`--stage must be one of: ${REPORT_STAGES.join(", ")}, all.`);
  const fromFile = options.facts ? readFactsFile(options.facts) : {};
  // Flags win over the file.
  const facts: ReportFacts = { ...fromFile };
  for (const key of FACT_KEYS) { const value = options[key]; if (clean(value)) facts[key] = value!; }
  if (options.evidenceFile?.length) facts.evidenceFiles = [...(fromFile.evidenceFiles ?? []), ...options.evidenceFile.map(file => describeEvidenceFile(file))];
  const loaded = deps.load(id, options.dbPath);
  if (options.ranking) loaded.finding = withBusinessContext([loaded.finding], options.ranking)[0]!;
  const ctx: DraftContext = { finding: loaded.finding, ...(loaded.target ? { target: loaded.target } : {}), facts, toolVersion: deps.version, generatedAt: deps.now().toISOString() };
  const text = stage === "all" ? buildAllDrafts(ctx) : buildReportDraft(stage as ReportStage, ctx);
  if (options.output) { deps.write(resolve(options.output), text); deps.err(`Wrote ${options.output}. This is a draft: a person must review it and submit it; nothing was sent.`); }
  else deps.out(text);
}

const defaults: ReportDraftDeps = {
  out: text => process.stdout.write(text),
  err: text => process.stderr.write(`${text}\n`),
  write: (path, text) => writeFileSync(path, text, { mode: 0o600 }),
  load(id, dbPath) {
    const wanted = id.trim().replace(/^fp:/i, "");
    const hits: Array<{ id: string; path: string }> = [];
    for (const path of findingDatabasePaths(dbPath)) {
      if (!existsSync(path)) { if (dbPath) throw new UsageError(`Database does not exist: ${path}`); continue; }
      const db = new osecDB(path, { readOnly: true });
      try {
        const rows = db.listFindings({ limit: 5000 }) as Array<{ id: string; fingerprint?: string | null }>;
        // The id forms `0 findings` prints: a full id, an id prefix, the distinctive part of an imported id, or `fp:<fingerprint prefix>`.
        const byId = resolveFindingId(rows, id);
        const row = byId ?? (wanted.length >= 6 ? (() => { const m = rows.filter(r => r.fingerprint && shortFingerprint(r.fingerprint).startsWith(wanted)); if (m.length > 1) throw new UsageError(`Finding '${id}' is ambiguous: it matches ${m.length} findings.`); return m[0]; })() : undefined);
        if (row) hits.push({ id: row.id, path });
      } finally { db.close(); }
    }
    if (hits.length > 1) throw new UsageError(`Finding '${id}' is in more than one database; pass --db-path.`);
    if (!hits[0]) throw new UsageError(`Finding '${id}' was not found. Use an id or fingerprint from \`0security findings list\`, or pass --db-path.`);
    const focus = loadFindingFocus(hits[0].id, { dbPath: hits[0].path });
    return { finding: focus.finding, ...(focus.target ? { target: focus.target } : {}) };
  },
  now: () => new Date(),
  version: VERSION,
};

export function registerFindingsReportDraftCommand(parent: Command, deps?: ReportDraftDeps): void {
  const collect = (value: string, previous: string[] = []) => [...previous, value];
  parent.command("report-draft <finding>")
    .description("Write a draft early warning, notification or final report about one finding (Markdown; nothing is sent)")
    .requiredOption("--stage <stage>", "early-warning, notification, final or all")
    .option("--product <name>", "Product name")
    .option("--manufacturer <name>", "Legal name of the manufacturer")
    .option("--contact <text>", "Who submits the report and how to reach them")
    .option("--affected-versions <text>", "Affected product versions")
    .option("--exploited-since <when>", "When exploitation is known to have started")
    .option("--exploitation-evidence <text>", "How you know it is being exploited")
    .option("--malicious-actor <text>", "Suspected malicious act or actor, if known")
    .option("--member-states <text>", "Member States where the product is available")
    .option("--mitigation <text>", "Mitigation taken or recommended")
    .option("--user-measures <text>", "What users can do now")
    .option("--corrective-measure <text>", "The fix or update available to users")
    .option("--corrective-measure-date <when>", "When the corrective measure became available")
    .option("--evidence-file <file>", "Name and SHA-256 of a supporting file (its content is never copied); repeat for several", collect)
    .option("--facts <file>", "JSON file with the same facts (camelCase keys, for example affectedVersions); flags win")
    .option("-o, --output <file>", "Write to a file instead of stdout")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--context <file>", "Business context file (JSON): add why the finding ranks where it does. Defaults to the file set with `0security config set findingsContext`")
    .option("--repository <name>", REPOSITORY_FLAG_HELP)
    .addHelpText("after", "\nEvery field is taken from the finding or from what you supply here; everything else is left as a visible blank. It is a draft: a person reviews it and submits it through the authority's channel. Article 14 of Regulation (EU) 2024/2847 is the starting point; confirm current requirements.")
    .action(async (id: string, options: ReportDraftOptions, command: Command) => {
      const merged = { ...command.parent?.opts(), ...options } as ReportDraftOptions;
      const resolved = deps ?? defaults;
      try { runReportDraft(id, { ...options, dbPath: options.dbPath ?? merged.dbPath, ranking: await loadContextFor(contextOptionsOf(options, command)) }, resolved); }
      catch (error) { finishWithError(error, resolved, false); }
    });
}
