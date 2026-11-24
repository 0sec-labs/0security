/**
 * `0 findings evidence <folder>` writes one folder of security-testing and vulnerability-handling evidence: the
 * findings with their triage state and timestamps (JSON and Markdown), a SARIF file, a CycloneDX SBOM, an optional
 * advisory check, the fix branches that exist in a repository, and a README that says what each file shows and what
 * it does not.
 *
 * It claims no compliance with anything. It never writes outside the folder it is given, writes only its own fixed
 * file names, and leaves out proof-of-concept and evidence bodies unless `--include-evidence` is passed. Nothing
 * touches the network unless `--check-advisories` is passed.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync, unlinkSync, readdirSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import type { Command } from "commander";
import { checkBomAgainstOsv, exportReport, generateSbom, type Advisory, type Bom } from "@0/engine";
import { attackerImpactSentence, VERSION, type Finding, type ScanReport } from "@0/engine/shared";
import { osecDB } from "@0/engine/storage";
import { findingDatabasePaths, loadFindingFocus } from "../finding-focus.js";
import { mergeFindingSnapshots, emptyFindingSnapshot } from "../web/report-artifacts.js";
import { evidenceSigningRefusal, signEvidence } from "../enterprise-bridge.js";
import { buildEvidenceStatement, EVIDENCE_SIGNATURE_FILE } from "./evidence-signature.js";
import { BRANCH_PREFIX, fixBranchName } from "./fix.js";
import { finishWithError, UsageError } from "./output.js";

/** The only files this command writes. */
export const EVIDENCE_FILES = ["README.md", "manifest.json", "findings.json", "findings.md", "findings.sarif", "sbom.cdx.json", "advisories.json", "fixes.md", EVIDENCE_SIGNATURE_FILE] as const;

export interface EvidenceFindingRecord {
  id: string; fingerprint: string | null; title: string; severity: string; category: string; status: string;
  triageStatus: string | null; triageNote: string | null; triageExpiresAt: string | null; triageApprover: string | null; workflowStatus: string | null; workflowAssignee: string | null;
  workflowUpdatedAt: string | null; detectedAt: string | null; location: string | null; reportedBy: string | null;
  cvssScore: number | null; cvssVector: string | null; attackerImpact: string | null;
  scanId: string | null; scanTarget: string | null; scanStartedAt: string | null; scanModel: string | null;
  evidence?: { request: string; response: string; analysis: string | null };
}

export interface EvidenceInput {
  findings: Array<{ finding: Finding; scanId: string | null; scanTarget: string | null; scanStartedAt: string | null; scanModel: string | null; tool?: string | null }>;
  unreadable: string[];
}

export interface EvidenceDeps {
  err(text: string): void;
  /** Findings from the findings databases. */
  load(options: { dbPath?: string; scan?: string }): EvidenceInput;
  /** Run git in a folder; undefined when it fails or git is absent. */
  git(repo: string, args: string[]): string | undefined;
  fetch?: typeof fetch;
  now(): Date;
  version(): string;
  /** Signed bundles (paid). Defaults to the license-gated enterprise code. */
  signing?: { refusal(): string | null; sign(statementJson: string, privateKeyPem: string): unknown };
}

export interface EvidenceOptions {
  repo?: string; checkAdvisories?: boolean; includeEvidence?: boolean; dbPath?: string; scan?: string; name?: string;
  /** Path of the customer's Ed25519 private key (PEM). Signs the folder. Needs the evidence-signing license. */
  sign?: string;
}

const iso = (ms: number): string | null => (Number.isFinite(ms) && ms > 0 ? new Date(ms).toISOString() : null);
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

function recordOf(entry: EvidenceInput["findings"][number], includeEvidence: boolean): EvidenceFindingRecord {
  const finding = entry.finding;
  const at = finding.reviewAnnotation;
  return {
    id: finding.id, fingerprint: finding.fingerprint ?? null, title: finding.title, severity: finding.severity, category: finding.category,
    status: finding.status, triageStatus: finding.triageStatus ?? null, triageNote: finding.triageNote ?? null, triageExpiresAt: finding.triageExpiresAt ?? null, triageApprover: finding.triageApprover ?? null,
    workflowStatus: finding.workflowStatus ?? null, workflowAssignee: finding.workflowAssignee ?? null, workflowUpdatedAt: finding.workflowUpdatedAt ?? null,
    detectedAt: iso(finding.timestamp), location: at?.path ? `${at.path}${at.startLine ? `:${at.startLine}` : ""}` : null, reportedBy: entry.tool ?? finding.tool ?? null,
    cvssScore: finding.cvssScore ?? null, cvssVector: finding.cvssVector ?? null, attackerImpact: attackerImpactSentence(finding) ?? null,
    scanId: entry.scanId, scanTarget: entry.scanTarget, scanStartedAt: entry.scanStartedAt, scanModel: entry.scanModel,
    ...(includeEvidence ? { evidence: { request: finding.evidence?.request ?? "", response: finding.evidence?.response ?? "", analysis: finding.evidence?.analysis ?? null } } : {}),
  };
}

const cell = (value: string | number | null): string => String(value ?? "").replace(/\s+/g, " ").replace(/\|/g, "\\|").trim() || "-";

export function findingsMarkdown(records: EvidenceFindingRecord[], includeEvidence: boolean): string {
  const lines = [
    "# Findings", "",
    `${records.length} finding${records.length === 1 ? "" : "s"} from the findings database. Times are UTC. "Detected" is when the finding was recorded; "Last workflow change" is when its workflow state last changed, if that was recorded.`, "",
    "| Id | Severity | Title | Category | Status | Triage | Workflow | Where | Detected | Last workflow change | Reported by |", "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ...records.map(r => `| \`${r.id}\` | ${cell(r.severity)} | ${cell(r.title)} | ${cell(r.category)} | ${cell(r.status)} | ${cell(r.triageStatus)} | ${cell(r.workflowStatus)} | ${cell(r.location)} | ${cell(r.detectedAt)} | ${cell(r.workflowUpdatedAt)} | ${cell(r.reportedBy)} |`),
  ];
  const noted = records.filter(r => r.triageNote || r.attackerImpact || r.triageExpiresAt || r.triageApprover);
  if (noted.length) {
    lines.push("", "## Notes", "");
    for (const r of noted) {
      lines.push(`### \`${r.id}\` ${cell(r.title)}`, "");
      if (r.triageNote) lines.push(`- ${r.triageStatus === "accepted" ? "Reason for accepting the risk" : "Triage note"}: ${cell(r.triageNote)}`);
      if (r.triageExpiresAt) lines.push(`- ${r.triageStatus === "accepted" ? "Accepted until" : "Earlier acceptance expired"}: ${cell(r.triageExpiresAt.slice(0, 10))}`);
      if (r.triageApprover) lines.push(`- Approver (a label typed by the operator, not verified): ${cell(r.triageApprover)}`);
      if (r.attackerImpact) lines.push(`- Attacker impact (assessed): ${cell(r.attackerImpact)}`);
      lines.push("");
    }
  }
  if (includeEvidence) lines.push("", "Evidence bodies are in `findings.json` (`--include-evidence` was passed).");
  return `${lines.join("\n")}\n`;
}

/** The report the SARIF is made from: the findings, with evidence and proof-of-concept removed unless asked for. */
function reportOf(input: EvidenceInput, includeEvidence: boolean): ScanReport {
  if (!input.findings.length) return emptyFindingSnapshot();
  const findings = input.findings.map(({ finding }) => includeEvidence ? finding : { ...finding, evidence: { request: "", response: "" }, pocSteps: undefined, verificationSpec: undefined });
  const base = emptyFindingSnapshot();
  const merged = mergeFindingSnapshots([{ ...base, findings }]);
  return { ...merged, target: "Findings database", warnings: [{ stage: "report", message: "Findings export for evidence purposes. It is not a complete assessment report." }] };
}

/** Fix branches that exist in a repository, found with git only (no network). */
export function fixBranches(records: EvidenceFindingRecord[], repo: string, git: EvidenceDeps["git"]): { found: Array<{ finding: EvidenceFindingRecord; branch: string; ref: string; commit: string; date: string; subject: string }>; gitUsable: boolean } {
  const listing = git(repo, ["for-each-ref", "--format=%(refname:short)%09%(objectname)%09%(committerdate:iso-strict)%09%(contents:subject)", `refs/heads/${BRANCH_PREFIX}*`, `refs/remotes/*/${BRANCH_PREFIX}*`]);
  if (listing === undefined) return { found: [], gitUsable: false };
  const refs = listing.split("\n").filter(Boolean).map(line => { const [ref = "", commit = "", date = "", subject = ""] = line.split("\t"); return { ref, commit, date, subject }; });
  const found: Array<{ finding: EvidenceFindingRecord; branch: string; ref: string; commit: string; date: string; subject: string }> = [];
  for (const record of records) {
    const branch = fixBranchName(record.fingerprint ?? record.id);
    for (const ref of refs) if (ref.ref === branch || ref.ref.endsWith(`/${branch}`)) found.push({ finding: record, branch, ...ref });
  }
  return { found, gitUsable: true };
}

export function fixesMarkdown(records: EvidenceFindingRecord[], repo: string | undefined, git: EvidenceDeps["git"]): string {
  const lines = ["# Fix branches", ""];
  if (!repo) return `${[...lines, "No repository was given (`--repo <folder>`), so no fix branches were looked up.", "", "`0security` does not store pull request links in the findings database. Branches made by `0security findings fix` are named `0/fix-<12 hex characters>`; pass the repository to list the ones that exist there."].join("\n")}\n`;
  const { found, gitUsable } = fixBranches(records, repo, git);
  if (!gitUsable) return `${[...lines, "The folder given as `--repo` is not a git repository, or git is not available, so no fix branches were looked up."].join("\n")}\n`;
  lines.push("Branches in the repository, as seen by git on this machine, that `0security findings fix` would have made for one of the findings. A branch is a record that a fix was attempted. It does not show that the fix is correct, was reviewed or was merged.", "");
  if (!found.length) lines.push("None found. A fix branch may exist in a clone this machine does not have, or no fix was started.");
  else lines.push("| Finding | Branch | Commit | Last commit | Subject |", "| --- | --- | --- | --- | --- |", ...found.map(f => `| \`${f.finding.id}\` ${cell(f.finding.title)} | \`${f.ref}\` | \`${f.commit.slice(0, 12)}\` | ${cell(f.date)} | ${cell(f.subject)} |`));
  lines.push("", "`0security` does not store pull request links in the findings database. Look the branch up on your code host to find its pull request and its review.");
  return `${lines.join("\n")}\n`;
}

const sha256 = (text: string): string => createHash("sha256").update(text).digest("hex");

interface Produced { name: (typeof EVIDENCE_FILES)[number]; text: string }

const MAX_KEY_BYTES = 16 * 1024;

/** Reads the operator-named private key file. Never echoes its content. */
function readKeyFile(path: string, warnings: string[]): string {
  let info;
  try { info = statSync(path); } catch { throw new UsageError(`--sign key file '${path}' was not found.`); }
  if (!info.isFile() || info.size > MAX_KEY_BYTES) throw new UsageError(`--sign '${path}' is not a key file. Give the path of an Ed25519 private key in PEM format.`);
  if (process.platform !== "win32" && (info.mode & 0o077) !== 0) warnings.push(`The key file '${path}' can be read by other users. Restrict it with: chmod 600 ${path}`);
  try { return readFileSync(path, "utf8"); } catch { throw new UsageError(`--sign key file '${path}' cannot be read.`); }
}

export interface EvidenceResult { folder: string; files: Array<{ name: string; bytes: number; sha256: string }>; findings: number; signed: boolean; warnings: string[] }

function readme(args: { version: string; generatedAt: string; commit: string | null; dirty: boolean; repo: string | undefined; models: string[]; counts: { findings: number; components: number | null }; hasSbom: boolean; signed: boolean; sbomNote: string; advisories: "checked" | "not-requested"; includeEvidence: boolean; unreadable: string[]; files: Array<{ name: string; sha256: string }> }): string {
  const row = (file: string, shows: string, notShows: string) => `| \`${file}\` | ${shows} | ${notShows} |`;
  return `${[
    "# Security evidence",
    "",
    "This folder is a snapshot of security-testing and vulnerability-handling records taken from one machine. It is evidence a person can read, check and attach to technical documentation. **It is not a declaration of conformity, a certification or a claim that any product complies with any law, including Regulation (EU) 2024/2847 (the Cyber Resilience Act).** Conformity is the manufacturer's responsibility and depends on much that is not here.",
    "",
    "## How it was made",
    "",
    `- Produced by \`0\` version ${args.version} on ${args.generatedAt} (UTC).`,
    `- Repository: ${args.repo ? `\`${args.repo.split(sep).pop()}\`` : "none given (`--repo`)"}${args.commit ? `, commit \`${args.commit}\`${args.dirty ? " (the working tree had uncommitted changes, so the lockfiles may differ from this commit)" : ""}` : args.repo ? ", commit unknown (not a git repository, or git is unavailable)" : ""}.`,
    `- Models used by the scans that recorded the findings: ${args.models.length ? args.models.map(m => `\`${m}\``).join(", ") : "not recorded in the findings database"}. This command itself calls no model and no network service${args.advisories === "checked" ? " except the advisory lookup described below" : ""}.`,
    `- ${args.counts.findings} finding${args.counts.findings === 1 ? "" : "s"}${args.counts.components !== null ? `, ${args.counts.components} SBOM components` : ""}.`,
    `- Evidence and proof-of-concept bodies: ${args.includeEvidence ? "**included** in `findings.json` and `findings.sarif` (`--include-evidence`). They can contain working exploit details; handle the folder as sensitive." : "not included. Findings carry titles, locations and triage state only."}`,
    ...(args.unreadable.length ? [`- ${args.unreadable.length} stored finding${args.unreadable.length === 1 ? "" : "s"} could not be read and ${args.unreadable.length === 1 ? "is" : "are"} missing from the lists: ${args.unreadable.map(id => `\`${id}\``).join(", ")}.`] : []),
    "",
    "## Files",
    "",
    "| File | What it shows | What it does not show |",
    "| --- | --- | --- |",
    row("manifest.json", "The same facts as above in machine-readable form, and a SHA-256 for every other file.", "Anything about the product itself. The hashes show the files are unchanged since this folder was written, not who wrote them."),
    row("findings.json", "Each finding with severity, category, status, triage state and note, workflow state, when it was recorded, where it is, which scan and model found it.", "That a finding is real, exploitable or fixed unless the status says so; status and triage are whatever people and tools set. It is not a list of every weakness in the product: it holds only what the scans found."),
    row("findings.md", "The same list as a table for people.", "The same limits as `findings.json`."),
    row("findings.sarif", "The findings as SARIF 2.1.0 for code scanning tools and auditors.", "Scan coverage. Which files and checks were never looked at is not in this file."),
    row("sbom.cdx.json", args.hasSbom ? "A CycloneDX component list read from the lockfiles in the repository." : `Not written. ${args.sbomNote}`, "What is actually deployed. It is read from lockfiles as text, so it misses vendored code, system packages and anything built outside a lockfile. Nothing was installed or run."),
    row("advisories.json", args.advisories === "checked" ? "Known advisories for the SBOM components, from the public OSV database on the date above." : "Not written (`--check-advisories` was not passed).", "Vulnerabilities published after that date, or ones no database knows. An empty result is not a clean bill of health."),
    ...(args.signed ? [row(EVIDENCE_SIGNATURE_FILE, "A signature, made with a key the customer holds, over the SHA-256 of every other file in this folder (DSSE envelope around an in-toto statement). `0security evidence verify <folder> --pub <public key>` checks it offline.", "Who the key holder is, or that the findings are right. A signature shows these files are unchanged since the key holder signed them.")] : []),
    row("fixes.md", "Fix branches that exist in the repository for these findings.", "That a fix is correct, reviewed, merged or released. Pull request links are not stored by `0security` and are not listed."),
    "",
    "## Checksums",
    "",
    "| File | SHA-256 |",
    "| --- | --- |",
    ...args.files.map(file => `| \`${file.name}\` | \`${file.sha256}\` |`),
    "",
    "## Before you rely on it",
    "",
    "- Read it. Scanner output and model-written text can be wrong.",
    "- Obligations on manufacturers (vulnerability handling, reporting, technical documentation) are wider than this folder. Confirm the current requirements with your legal and compliance advisers.",
    "- If something here is an actively exploited vulnerability, the reporting duty is yours. `0security findings report-draft` writes a draft; a person reviews and submits it.",
  ].join("\n")}\n`;
}

/** Throws unless the folder is new, empty or holds only files this command wrote before; refuses links. */
export function prepareFolder(folder: string): string {
  const target = resolve(folder);
  let info;
  try { info = lstatSync(target); } catch { info = undefined; }
  if (info) {
    if (info.isSymbolicLink()) throw new UsageError(`'${folder}' is a symbolic link; give a real folder.`);
    if (!info.isDirectory()) throw new UsageError(`'${folder}' exists and is not a folder.`);
    const extra = readdirSync(target).filter(name => !(EVIDENCE_FILES as readonly string[]).includes(name));
    if (extra.length) throw new UsageError(`'${folder}' already holds other files (${extra.slice(0, 3).join(", ")}${extra.length > 3 ? ", ..." : ""}). Use a new or empty folder.`);
  } else {
    const parent = dirname(target);
    if (!existsSync(parent) || !statSync(parent).isDirectory()) throw new UsageError(`The parent of '${folder}' does not exist.`);
  }
  return target;
}

function write(target: string, name: string, text: string): void {
  const path = join(target, name);
  if (!(EVIDENCE_FILES as readonly string[]).includes(name) || dirname(path) !== target) throw new UsageError(`Refusing to write ${name}.`);
  let existing;
  try { existing = lstatSync(path); } catch { existing = undefined; }
  if (existing && !existing.isFile()) throw new UsageError(`Refusing to overwrite ${name}: it is not a regular file.`);
  writeFileSync(path, text, { mode: 0o600 });
}

export async function buildEvidence(folder: string, options: EvidenceOptions, deps: EvidenceDeps): Promise<EvidenceResult> {
  const target = prepareFolder(folder);
  const signing = deps.signing ?? { refusal: evidenceSigningRefusal, sign: signEvidence };
  let keyPem: string | undefined;
  const warnings: string[] = [];
  if (options.sign) {
    // Everything that can refuse runs before anything is written: license, then the key.
    const refusal = signing.refusal();
    if (refusal) throw new UsageError(refusal);
    keyPem = readKeyFile(options.sign, warnings);
    try { signing.sign("{}", keyPem); } catch (error) { throw new UsageError(error instanceof Error ? error.message : "The key file cannot sign."); }
  }
  let repo: string | undefined;
  if (options.repo) {
    repo = resolve(options.repo);
    let isFolder = false;
    try { isFolder = statSync(repo).isDirectory(); } catch { /* reported below */ }
    if (!isFolder) throw new UsageError(`--repo '${options.repo}' is not a folder.`);
    // Writing the evidence into the repository it describes would change what the next run reads.
    const real = (path: string): string => { try { return realpathSync(path); } catch { return path; } };
    const realRepo = real(repo);
    const realTarget = join(real(dirname(target)), target.split(sep).pop() ?? "");
    if (realTarget === realRepo || realTarget.startsWith(`${realRepo}${sep}`)) throw new UsageError("Choose an evidence folder outside the repository.");
  }
  if (options.checkAdvisories && !repo) throw new UsageError("--check-advisories needs --repo <folder>: advisories are looked up for the SBOM.");
  const generatedAt = deps.now().toISOString();
  const input = deps.load({ ...(options.dbPath ? { dbPath: options.dbPath } : {}), ...(options.scan ? { scan: options.scan } : {}) });
  const entries = [...input.findings].sort((a, b) => (SEVERITY_ORDER.indexOf(a.finding.severity) - SEVERITY_ORDER.indexOf(b.finding.severity)) || a.finding.id.localeCompare(b.finding.id));
  const sorted: EvidenceInput = { findings: entries, unreadable: input.unreadable };
  const records = entries.map(entry => recordOf(entry, Boolean(options.includeEvidence)));

  let bom: Bom | undefined;
  let sbomNote = "No repository was given (`--repo <folder>`).";
  let commit: string | null = null;
  let dirty = false;
  if (repo) {
    const result = generateSbom(repo, { toolVersion: VERSION, now: deps.now(), ...(options.name ? { name: options.name } : {}) });
    if (result.bom.components.length) bom = result.bom;
    else { sbomNote = "The repository has no supported lockfile with packages. For Maven, Gradle, NuGet or container images, generate an SBOM with syft or cdxgen and add it yourself."; warnings.push(sbomNote); }
    commit = deps.git(repo, ["rev-parse", "HEAD"])?.trim() || null;
    dirty = commit ? Boolean(deps.git(repo, ["status", "--porcelain"])?.trim()) : false;
    if (!commit) warnings.push("The repository is not a git repository (or git is unavailable): the commit is not recorded.");
  }

  // The only network use, done before anything is written so a failure leaves no half-made folder.
  let advisories: { advisories: Advisory[]; checked: number; withoutDetails?: number } | undefined;
  if (options.checkAdvisories) {
    if (!bom) throw new UsageError("--check-advisories needs an SBOM, and the repository has none to check.");
    advisories = await checkBomAgainstOsv(bom, deps.fetch ? { fetch: deps.fetch } : {}).catch(error => { throw new Error(`Could not check against OSV: ${error instanceof Error ? error.message : String(error)}`); });
  }

  const sarif = (await exportReport(reportOf(sorted, Boolean(options.includeEvidence)), "sarif", "0-findings")).body;
  const models = [...new Set(entries.map(entry => entry.scanModel).filter((model): model is string => Boolean(model)))].sort();
  const produced: Produced[] = [
    { name: "findings.json", text: `${JSON.stringify({ generatedAt, count: records.length, findings: records }, null, 2)}\n` },
    { name: "findings.md", text: findingsMarkdown(records, Boolean(options.includeEvidence)) },
    { name: "findings.sarif", text: `${new TextDecoder().decode(sarif).trimEnd()}\n` },
    ...(bom ? [{ name: "sbom.cdx.json" as const, text: `${JSON.stringify(bom, null, 2)}\n` }] : []),
    ...(advisories ? [{ name: "advisories.json" as const, text: `${JSON.stringify({ source: "OSV (https://api.osv.dev)", checkedAt: generatedAt, components: advisories.checked, advisoryCount: advisories.advisories.length, ...(advisories.withoutDetails ? { listedByIdOnly: advisories.withoutDetails } : {}), advisories: advisories.advisories }, null, 2)}\n` }] : []),
    { name: "fixes.md", text: fixesMarkdown(records, repo, deps.git) },
  ];
  const scanIds = [...new Set(entries.map(entry => entry.scanId).filter((id): id is string => Boolean(id)))].sort();
  const hashes = produced.map(file => ({ name: file.name, sha256: sha256(file.text) }));
  const manifest = {
    generatedAt, tool: { name: "0", version: deps.version() }, models, scanIds, includeEvidence: Boolean(options.includeEvidence),
    repository: repo ? { name: repo.split(sep).pop() ?? "", commit, uncommittedChanges: dirty } : null,
    counts: { findings: records.length, sbomComponents: bom ? bom.components.length : null, advisories: advisories ? advisories.advisories.length : null },
    files: hashes,
  };
  const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
  const readmeText = readme({ version: deps.version(), generatedAt, commit, dirty, repo, models, counts: { findings: records.length, components: bom ? bom.components.length : null }, hasSbom: Boolean(bom), signed: Boolean(keyPem), sbomNote, advisories: advisories ? "checked" : "not-requested", includeEvidence: Boolean(options.includeEvidence), unreadable: input.unreadable, files: [{ name: "manifest.json", sha256: sha256(manifestText) }, ...hashes] });

  mkdirSync(target, { recursive: true });
  const all: Produced[] = [{ name: "README.md", text: readmeText }, { name: "manifest.json", text: manifestText }, ...produced];
  if (keyPem) {
    const statement = buildEvidenceStatement(all.map(file => ({ name: file.name, sha256: sha256(file.text) })), {
      signedAt: deps.now().toISOString(), generatedAt, tool: manifest.tool, models, scanIds, repository: manifest.repository, counts: manifest.counts,
    });
    all.push({ name: EVIDENCE_SIGNATURE_FILE, text: `${JSON.stringify(signing.sign(statement, keyPem), null, 2)}\n` });
  }
  for (const file of all) write(target, file.name, file.text);
  // A file left by an earlier run that this run did not produce would contradict the README.
  for (const name of EVIDENCE_FILES) if (!all.some(file => file.name === name)) { try { if (lstatSync(join(target, name)).isFile()) unlinkSync(join(target, name)); } catch { /* not there */ } }
  if (options.includeEvidence) warnings.push("Evidence and proof-of-concept bodies are included. They can contain working exploit details: do not publish or share the folder without reading them.");
  return { folder: target, files: all.map(file => ({ name: file.name, bytes: Buffer.byteLength(file.text), sha256: sha256(file.text) })), findings: records.length, signed: Boolean(keyPem), warnings };
}

const defaults: EvidenceDeps = {
  err: text => process.stderr.write(`${text}\n`),
  load({ dbPath, scan }) {
    const seen = new Set<string>();
    const findings: EvidenceInput["findings"] = [];
    const unreadable: string[] = [];
    for (const path of findingDatabasePaths(dbPath)) {
      if (!existsSync(path)) continue;
      let db: osecDB | undefined;
      try {
        db = new osecDB(path, { readOnly: true });
        for (const row of db.listFindings({ limit: 5000 }) as Array<Record<string, unknown>>) {
          const id = typeof row.id === "string" ? row.id : "";
          const scanId = typeof row.scanId === "string" ? row.scanId : null;
          if (!id || seen.has(id) || (scan && scanId !== scan)) continue;
          seen.add(id);
          try {
            const scanRow = (scanId ? db.getScan(scanId) : undefined) as { target?: string; startedAt?: string; model?: string | null } | undefined;
            findings.push({ finding: loadFindingFocus(id, { dbPath: path }).finding, scanId, scanTarget: scanRow?.target ?? null, scanStartedAt: scanRow?.startedAt ?? null, scanModel: scanRow?.model ?? null, tool: typeof row.tool === "string" && row.tool ? row.tool : null });
          } catch { unreadable.push(id); }
        }
      } catch { /* an unreadable run database holds nothing to export */ } finally { db?.close(); }
    }
    return { findings, unreadable: unreadable.sort() };
  },
  git(repo, args) {
    try { return execFileSync("git", ["-C", repo, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 15000 }); } catch { return undefined; }
  },
  now: () => new Date(),
  version: () => VERSION,
};

export function registerFindingsEvidenceCommand(parent: Command, deps: EvidenceDeps = defaults): void {
  parent.command("evidence <folder>")
    .description("Write one folder of findings, SARIF, SBOM and fix branches, with a README that says what it does and does not show")
    .option("--repo <folder>", "Repository the findings are about: adds the SBOM, the commit and the fix branches")
    .option("--check-advisories", "Look the SBOM components up in the public OSV database (the only network use)")
    .option("--include-evidence", "Also write evidence and proof-of-concept bodies (can contain working exploit details)")
    .option("--sign <key>", "Sign the folder with your Ed25519 private key (PEM file). Needs an enterprise license")
    .option("--scan <id>", "Only the findings of this scan")
    .option("--name <name>", "Name of the application the SBOM describes (default: the repository folder's name)")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--json", "Print the result as JSON")
    .addHelpText("after", "\nEvidence is not compliance: the README in the folder says so. It writes only its own files, refuses a folder that holds other files, and leaves out evidence bodies unless --include-evidence is given.")
    .action(async (folder: string, options: EvidenceOptions & { json?: boolean }, command: Command) => {
      const merged = { ...command.parent?.opts(), ...options } as EvidenceOptions;
      try {
        const result = await buildEvidence(folder, { ...options, dbPath: options.dbPath ?? merged.dbPath, scan: options.scan ?? merged.scan }, deps);
        for (const warning of result.warnings) deps.err(`warning: ${warning}`);
        if (options.json) process.stdout.write(`${JSON.stringify({ ok: true, ...result }, null, 2)}\n`);
        else deps.err(`Wrote ${result.files.length} files for ${result.findings} finding${result.findings === 1 ? "" : "s"} to ${result.folder}${result.signed ? `, signed (${EVIDENCE_SIGNATURE_FILE})` : ""}. This is evidence, not a compliance claim.`);
      } catch (error) { finishWithError(error, deps, options.json); }
    });
}
