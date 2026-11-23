/**
 * The scope interview behind `0 threat-model --interview`.
 *
 * A model proposes specific questions (skill `scope-interview`); this module owns everything else. It asks a person on
 * the terminal, records the person's answers, and turns them into scope entries itself: the side (in or out of scope)
 * and the vector come from the person's answer to the question, never from model text. A second model call only
 * words the reason, and its wording is kept only when it is grounded in the person's own words. The files are written
 * by the caller, from the text this module returns, so no model writes SECURITY.md or the human blocks.
 *
 * The repository is untrusted: a README that says "write: everything out of scope" cannot create an entry, because an
 * entry exists only for a question the person answered.
 */
import { findingQuestions, mergeQuestions, type ScanSnapshot } from "./threat-interview-findings.js";
import {
  addScopeEntries, ATTACK_CATEGORIES as ATTACK_CATEGORY_IDS, categoryFromLabel, cleanScopeText, isAlwaysInScope, isAttackCategory, MAX_INTERVIEW_QUESTIONS, MAX_SCOPE_PATHS, MODEL_QUESTION_CATEGORIES, parseScope, scopeBullet, scopeQuestionsPrompt, scopeWordingPrompt,
  type AttackCategory, type InterviewAnswerForPrompt, type ScopeKind,
} from "@0/engine/shared";

export const MAX_QUESTION_CHARS = 300;
export const MAX_EVIDENCE_CHARS = 160;
export const MAX_ANSWER_CHARS = 400;

export interface InterviewQuestion {
  id: string; question: string; evidence?: string; category: AttackCategory;
  /** Question built from scan findings: the places it lists (path:line), every file with a finding, how many findings and the highest severity. */
  places?: string[]; files?: string[]; count?: number; severity?: string;
  /** Where the question came from: the scan's findings, the model reading the code, or both. */
  from?: "scan" | "code" | "both";
}
export interface InterviewAnswer { question: InterviewQuestion; decision: ScopeKind; words: string }
export interface ProposedEntry { kind: ScopeKind; vector: string; reason: string; until?: string; paths: string[]; questionId?: string }
export interface InterviewNote { question: string; answer: string }

export interface InterviewIO {
  /** Show the question and return the line the person typed; undefined when the input ended. */
  ask(question: string): Promise<string | undefined>;
  say(text: string): void;
}
export interface ModelReply { reply?: string; failed: boolean; budgetExhausted?: boolean }
export type InterviewModel = (prompt: string, title: string) => Promise<ModelReply>;

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]/g;

/** One line of plain text: no control characters, HTML or markup that would act in a report. */
export function plainLine(text: unknown, max: number): string {
  return typeof text === "string" ? cleanScopeText(text.replace(CONTROL, " "), max) : "";
}

/** The JSON a model returned in a fenced block (the last one), or the outermost braces; undefined when there is none. */
export function extractJson(reply: string | undefined): unknown {
  if (!reply) return undefined;
  const fences = [...reply.matchAll(/```(?:json)?\s*\n([\s\S]*?)```/gi)];
  const candidates = fences.map(match => match[1]!).reverse();
  const open = reply.indexOf("{"), close = reply.lastIndexOf("}");
  if (open >= 0 && close > open) candidates.push(reply.slice(open, close + 1));
  for (const text of candidates) { try { return JSON.parse(text); } catch { /* try the next */ } }
  return undefined;
}

const EVIDENCE = /^[A-Za-z0-9_@+./\\ -]{1,200}(?::\d{1,7}(?:-\d{1,7})?)?$/;

export interface ParsedQuestions { questions: InterviewQuestion[]; dropped: string[] }

/**
 * Questions from the model's JSON, checked: at most 8, each with a category of ours, text and evidence of sane length, no
 * markup. Evidence naming a file that is not in the folder is dropped (the question stays). A question about a vector
 * the person already declared (no paths) is dropped, as is a repeated id.
 */
export function parseQuestions(reply: string | undefined, options: { fileExists(relative: string): boolean; covered?: ReadonlySet<string> }): ParsedQuestions {
  const dropped: string[] = [];
  const data = extractJson(reply);
  const list = typeof data === "object" && data !== null && Array.isArray((data as { questions?: unknown }).questions) ? (data as { questions: unknown[] }).questions : undefined;
  if (!list) return { questions: [], dropped: ["the reply held no question list"] };
  const questions: InterviewQuestion[] = [];
  const ids = new Set<string>();
  for (const raw of list) {
    if (questions.length >= MAX_INTERVIEW_QUESTIONS) { dropped.push("more than 8 questions; the rest were ignored"); break; }
    if (typeof raw !== "object" || raw === null) { dropped.push("an item that is not a question"); continue; }
    const item = raw as Record<string, unknown>;
    const text = plainLine(item.question, MAX_QUESTION_CHARS);
    const given = plainLine(item.category, 80);
    const category = isAttackCategory(given.toLowerCase()) ? (given.toLowerCase() as AttackCategory) : categoryFromLabel(given);
    if (!text || !category) { dropped.push(`a question with ${!text ? "no text" : `the unknown vector '${given.slice(0, 40)}'`}`); continue; }
    if (isAlwaysInScope(category)) { dropped.push(`'${category}' is always in scope; not asked`); continue; }
    if (!MODEL_QUESTION_CATEGORIES.has(category)) { dropped.push(`'${category}' is not a class the interview asks about`); continue; }
    if (options.covered?.has(category)) { dropped.push(`'${category}' is already declared`); continue; }
    let id = plainLine(item.id, 40).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || `q${questions.length + 1}`;
    if (ids.has(id)) id = `${id}-${questions.length + 1}`;
    ids.add(id);
    let evidence = typeof item.evidence === "string" && item.evidence.length > MAX_EVIDENCE_CHARS ? "" : plainLine(item.evidence, MAX_EVIDENCE_CHARS);
    if (evidence) {
      const path = evidence.replace(/:\d+(?:-\d+)?$/, "").replace(/\\/g, "/").replace(/^\.\//, "");
      if (!EVIDENCE.test(evidence) || path.startsWith("/") || path.split("/").includes("..") || !options.fileExists(path)) evidence = "";
    }
    questions.push({ id, question: text, ...(evidence ? { evidence } : {}), category });
  }
  return { questions, dropped };
}

const DECISION = /^(in scope|out of scope|not sure|in|out|skip|[123])\b\s*[:,.-]?\s*([\s\S]*)$/i;

/** The decision a typed line makes, or undefined when it is not one. `words` is what the person added after it. */
export function parseDecision(line: string): { decision: ScopeKind | "skip"; words: string } | undefined {
  const match = DECISION.exec(line.trim());
  if (!match) return undefined;
  const key = match[1]!.toLowerCase();
  const decision = key === "1" || key === "in" || key === "in scope" ? "in" : key === "2" || key === "out" || key === "out of scope" ? "out" : "skip";
  return { decision, words: plainLine(match[2], MAX_ANSWER_CHARS) };
}

const CHOICES = "1 = yes, we want findings like this (in scope). 2 = no, do not report this (out of scope; add a reason after a colon, for example: 2: it sits behind our gateway). 3 = not sure.";

export interface AskedResult { answers: InterviewAnswer[]; skipped: number }

/** Print each question with its evidence, read the answer and collect it. Asks for a reason once when an answer has none. */
export async function askQuestions(questions: readonly InterviewQuestion[], io: InterviewIO): Promise<AskedResult> {
  const answers: InterviewAnswer[] = [];
  let skipped = 0;
  io.say(`\n${CHOICES}\n`);
  for (const [index, question] of questions.entries()) {
    io.say(`Question ${index + 1} of ${questions.length} (${question.category})\n  ${question.question}${question.evidence && !question.places ? `\n  Evidence: ${question.evidence}` : ""}`);
    let parsed: ReturnType<typeof parseDecision>;
    for (let attempt = 0; attempt < 2 && !parsed; attempt++) {
      const line = await io.ask(attempt === 0 ? "  Your answer (1, 2 or 3): " : "  Type 1, 2 or 3, then an optional reason: ");
      if (line === undefined) break;
      parsed = parseDecision(line);
    }
    if (!parsed || parsed.decision === "skip") { skipped++; io.say("  Skipped."); continue; }
    let words = parsed.words;
    if (!words) {
      const reason = await io.ask("  Why? One line, or Enter to leave it blank: ");
      words = plainLine(reason ?? "", MAX_ANSWER_CHARS);
    }
    answers.push({ question, decision: parsed.decision, words });
  }
  return { answers, skipped };
}

const tokens = (text: string): Set<string> => new Set(text.toLowerCase().match(/[a-z0-9]{3,}/g) ?? []);

/** A reason is kept only when most of its words are the person's own: a model cannot invent one. */
export function groundedReason(candidate: string, words: string): boolean {
  const mine = tokens(words);
  const theirs = [...tokens(candidate)];
  if (!theirs.length) return false;
  return theirs.filter(token => mine.has(token)).length / theirs.length >= 0.6;
}

const evidencePath = (question: InterviewQuestion): string | undefined => question.evidence?.replace(/:\d+(?:-\d+)?$/, "").replace(/\\/g, "/").replace(/^\.\//, "");

/** Every file the question is about: all files with a finding for a scan question, the evidence file for a code question. */
const questionFiles = (question: InterviewQuestion): string[] => {
  const files = new Set(question.files ?? []);
  const path = evidencePath(question);
  if (path) files.add(path);
  return [...files];
};

/** A glob is kept only when it names the evidence file, a folder above it, or something the person typed. */
export function allowedGlob(glob: string, question: InterviewQuestion, words: string): boolean {
  const base = glob.replace(/\/?\*\*?.*$/, "").replace(/\/+$/, "");
  if (base && questionFiles(question).some(path => path === base || path.startsWith(`${base}/`))) return true;
  return glob.length > 2 && words.toLowerCase().includes(glob.toLowerCase());
}

const validDate = (value: string): boolean => /^\d{4}-\d{2}-\d{2}$/.test(value) && new Date(`${value}T00:00:00Z`).toISOString().slice(0, 10) === value;

/** A date is kept only when the person's words name that date or its year, and it is still ahead. */
export function allowedUntil(value: string, words: string, now: Date): boolean {
  if (!validDate(value) || Date.parse(`${value}T00:00:00Z`) < now.getTime() - 24 * 3600 * 1000) return false;
  return words.includes(value) || words.includes(value.slice(0, 4));
}

export interface Wording { questionId: string; reason?: string; paths?: string[]; until?: string }

/** The model's wording, by question id, with every field checked as text. */
export function parseWording(reply: string | undefined): Wording[] {
  const data = extractJson(reply);
  const list = typeof data === "object" && data !== null && Array.isArray((data as { entries?: unknown }).entries) ? (data as { entries: unknown[] }).entries : [];
  const out: Wording[] = [];
  for (const raw of list.slice(0, MAX_INTERVIEW_QUESTIONS * 2)) {
    if (typeof raw !== "object" || raw === null) continue;
    const item = raw as Record<string, unknown>;
    const questionId = plainLine(item.questionId, 40);
    if (!questionId) continue;
    const paths = Array.isArray(item.paths) ? item.paths.map(path => plainLine(path, 200).replace(/\s/g, "")).filter(Boolean).slice(0, 5) : undefined;
    out.push({ questionId, reason: plainLine(item.reason, 400), ...(paths ? { paths } : {}), ...(typeof item.until === "string" ? { until: plainLine(item.until, 10) } : {}) });
  }
  return out;
}

/**
 * The entries the person's answers make. Side and vector come from the answer; the reason is the model's wording when it is
 * grounded in the person's words, else the person's words, else `not given`. An out-of-scope entry is limited to the
 * evidence file unless the person says otherwise.
 */
export function entriesFromAnswers(answers: readonly InterviewAnswer[], wording: readonly Wording[], now: Date): ProposedEntry[] {
  return answers.map(answer => {
    const word = wording.find(item => item.questionId === answer.question.id);
    const words = answer.words;
    const reason = words ? (word?.reason && groundedReason(word.reason, words) ? word.reason : words) : "not given";
    const wordedPaths = (word?.paths ?? []).filter(glob => allowedGlob(glob, answer.question, words));
    // An out-of-scope answer covers the places the question named. A class that spans more files than an entry can list stays class-wide: the entry is shown and can be edited before it is written.
    const files = questionFiles(answer.question);
    const paths = wordedPaths.length ? wordedPaths : answer.decision === "out" && files.length && files.length <= MAX_SCOPE_PATHS ? files : [];
    const until = word?.until && allowedUntil(word.until, words, now) ? word.until : undefined;
    return { kind: answer.decision, vector: answer.question.category, reason: plainLine(reason, 400).replace(/^[\u201c\u2018"']+|[\u201d\u2019"']+$/g, ""), ...(until ? { until } : {}), paths, questionId: answer.question.id };
  });
}

/** A line the person edits: `in|out vector: reason (until YYYY-MM-DD) [paths: a, b]`. */
export function parseEntryLine(line: string): ProposedEntry | undefined {
  const match = /^\s*(in|out)\b\s*[:,-]?\s*([\s\S]+)$/i.exec(line);
  if (!match) return undefined;
  const kind = match[1]!.toLowerCase() as ScopeKind;
  const parsed = parseScope(`## Scope\n### ${kind === "in" ? "In scope" : "Out of scope"}\n- ${match[2]!.replace(/[\r\n]+/g, " ")}\n`);
  const entry = parsed.entries[0];
  if (!entry || parsed.entries.length !== 1) return undefined;
  return { kind, vector: entry.category ?? entry.vector, reason: entry.reason || "not given", ...(entry.until ? { until: entry.until } : {}), paths: entry.paths };
}

export const entryLine = (entry: ProposedEntry): string => `${entry.kind === "in" ? "in scope" : "out of scope"}: ${scopeBullet(entry).slice(2)}`;

/** Show each proposed entry and ask: accept, edit or skip. Returns the entries the person kept. */
export async function confirmEntries(entries: readonly ProposedEntry[], io: InterviewIO): Promise<ProposedEntry[]> {
  const kept: ProposedEntry[] = [];
  for (const [index, entry] of entries.entries()) {
    io.say(`\nProposed entry ${index + 1} of ${entries.length}\n  ${entryLine(entry)}`);
    let current = entry;
    for (let round = 0; round < 3; round++) {
      const line = ((await io.ask("  Accept (a), edit (e) or skip (s)? [a]: ")) ?? "s").trim().toLowerCase();
      if (line === "" || line === "a" || line === "accept" || line === "y") { kept.push(current); break; }
      if (line === "s" || line === "skip" || line === "n") { io.say("  Skipped."); break; }
      if (line === "e" || line === "edit") {
        const typed = await io.ask("  New text, for example: out: dos: behind the gateway (until 2027-06-30) [paths: src/api/**]\n  > ");
        const edited = typed === undefined ? undefined : parseEntryLine(typed);
        if (!edited) { io.say("  I could not read that; the entry is unchanged."); continue; }
        current = { ...edited, ...(entry.questionId ? { questionId: entry.questionId } : {}) };
        io.say(`  Now: ${entryLine(current)}`);
        continue;
      }
      io.say("  Type a, e or s.");
    }
  }
  return kept;
}

/** A short unified view of what changes between two texts: the changed lines with two lines of context. */
export function diffText(before: string, after: string): string {
  const a = before.split(/\r\n|\r|\n/), b = after.split(/\r\n|\r|\n/);
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start++;
  let endA = a.length, endB = b.length;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) { endA--; endB--; }
  if (start === endA && start === endB) return "(no change)";
  const lead = a.slice(Math.max(0, start - 2), start).map(line => `  ${line}`);
  const tail = a.slice(endA, endA + 2).map(line => `  ${line}`);
  return [...lead, ...a.slice(start, endA).map(line => `- ${line}`), ...b.slice(start, endB).map(line => `+ ${line}`), ...tail].join("\n");
}

// ── The fixed questionnaire (used when no model can ask) ──

export interface FixedQuestion { id: string; text: string; kind: "text" | "out" | "in" | "accepted" }
export const FIXED_QUESTIONS: readonly FixedQuestion[] = [
  { id: "matters", kind: "text", text: "What matters most to protect in this application?" },
  { id: "actors", kind: "text", text: "Who are the actors (customers, staff, admins, other systems) and what may each do?" },
  { id: "out", kind: "out", text: "Which kinds of attack do you NOT care about, and why? One per line or separated by semicolons: vector: reason" },
  { id: "in", kind: "in", text: "Which kinds of attack DO you care about most? vector: reason" },
  { id: "data", kind: "text", text: "Which data must never leave the system?" },
  { id: "compliance", kind: "text", text: "Which compliance rules apply (for example GDPR, PCI, SOC 2)?" },
  { id: "accepted", kind: "accepted", text: "Which known weaknesses do you accept for now? vector: reason (until YYYY-MM-DD)" },
  { id: "other", kind: "text", text: "Anything else the code cannot show?" },
];

/** Entries from a list the person typed as `vector: reason; vector: reason`. Items that name no vector we know are kept as typed. */
export function entriesFromList(text: string, kind: ScopeKind): ProposedEntry[] {
  const items = text.split(/[;\n]+/).map(item => item.trim()).filter(item => item && !/^(none|n\/a|no|-)$/i.test(item));
  const out: ProposedEntry[] = [];
  for (const item of items.slice(0, 20)) {
    const parsed = parseScope(`## Scope\n### ${kind === "in" ? "In scope" : "Out of scope"}\n- ${item.replace(/[\r\n]+/g, " ")}\n`).entries[0];
    if (parsed) out.push({ kind, vector: parsed.category ?? parsed.vector, reason: parsed.reason || "not given", ...(parsed.until ? { until: parsed.until } : {}), paths: parsed.paths });
  }
  return out;
}

export async function runQuestionnaire(io: InterviewIO): Promise<{ entries: ProposedEntry[]; notes: InterviewNote[] }> {
  const entries: ProposedEntry[] = [];
  const notes: InterviewNote[] = [];
  io.say("\nAnswer each question in a line, or press Enter to skip it.\n");
  for (const [index, question] of FIXED_QUESTIONS.entries()) {
    const typed = plainLine((await io.ask(`${index + 1}. ${question.text}\n   > `)) ?? "", 1200);
    if (!typed) continue;
    notes.push({ question: question.text.replace(/ (One per line|vector:).*$/, ""), answer: typed });
    if (question.kind === "text") continue;
    entries.push(...entriesFromList(typed, question.kind === "in" ? "in" : "out"));
  }
  return { entries, notes };
}

// ── Writing ──

const SECTION = "## Scope decisions";

/** A question and answer as a bullet of the human block. */
export const noteBullet = (note: InterviewNote): string => `- ${plainLine(note.question, 300)} Answer: ${plainLine(note.answer, 600)}`;

/**
 * The threat-model text with the person's answers in a `## Scope decisions` section inside a human block. An existing
 * section keeps its text and gains the new bullets; a missing one is added at the end. Every other byte stays.
 */
export function upsertScopeDecisions(text: string, notes: readonly InterviewNote[], date: string, linkTarget: string | undefined): string {
  if (!notes.length) return text;
  const eol = /\r\n/.test(text) && !/[^\r]\n/.test(text) ? "\r\n" : "\n";
  const bullets = notes.map(noteBullet);
  const lines = text.split(/\r\n|\r|\n/);
  const at = lines.findIndex(line => /^##\s+Scope decisions\s*$/i.test(line));
  if (at >= 0) {
    let end = lines.length;
    for (let i = at + 1; i < lines.length; i++) if (/^#{1,2}\s/.test(lines[i]!)) { end = i; break; }
    let close = -1;
    for (let i = end - 1; i > at; i--) if (/<!--\s*\/human\s*-->/.test(lines[i]!)) { close = i; break; }
    if (close < 0) { let last = end; while (last > at + 1 && !lines[last - 1]!.trim()) last--; lines.splice(last, 0, ...bullets, "<!-- /human -->"); }
    else lines.splice(close, 0, ...bullets);
    return lines.join(eol);
  }
  const body = [SECTION, "", "<!-- human -->", `Answered by a person with 0 threat-model --interview on ${date}.${linkTarget ? ` The declared scope is in [SECURITY.md#scope](${linkTarget}).` : ""}`, "", ...bullets, "<!-- /human -->", ""];
  const tail = text.endsWith("\n") || text.endsWith("\r") ? "" : eol;
  return `${text}${tail}${eol}${body.join(eol)}`;
}

/** Make sure the summary links the scope: insert the line under `## Summary` unless a link to SECURITY.md#scope is already there. */
export function ensureScopeLink(text: string, linkTarget: string): string {
  if (/^Declared scope:/im.test(text)) return text;
  const eol = /\r\n/.test(text) && !/[^\r]\n/.test(text) ? "\r\n" : "\n";
  const lines = text.split(/\r\n|\r|\n/);
  const at = lines.findIndex(line => /^##\s+Summary\s*$/i.test(line));
  const line = `Declared scope: [SECURITY.md#scope](${linkTarget})`;
  if (at < 0) return text;
  lines.splice(at + 1, 0, ...(lines[at + 1]?.trim() === "" ? ["", line] : ["", line, ""]));
  return lines.join(eol);
}

export const scopeLinkFor = (outputRel: string): string => {
  const depth = outputRel.split("/").length - 1;
  return `${depth ? "../".repeat(depth) : ""}SECURITY.md#scope`;
};

const MINIMAL_HEADER = "# Security policy\n\nReport a vulnerability by contacting the maintainers privately.\n";

export interface InterviewParams {
  target: string;
  /** The folder the interview runs on (the work tree with --pr). */
  folder: string;
  draftPath: string;
  draftExists: boolean;
  securityText: string | undefined;
  /** Text of the human blocks already in the threat-model file. */
  humanText: readonly string[];
  io: InterviewIO;
  /** Absent when no model can be reached: the fixed questionnaire runs. */
  model?: InterviewModel;
  fileExists(relative: string): boolean;
  now: Date;
  /** The findings of a scan of the folder: the interview asks about the classes that came up. Absent: it asks from the code only. */
  scan?: ScanSnapshot;
  /** Why no scan is used, said once before the questions. */
  scanNote?: string;
}
export interface InterviewResult {
  mode: "model" | "questionnaire";
  /** Why the questionnaire ran instead of the model's questions. */
  fallbackReason?: string;
  asked: number;
  answered: number;
  entries: ProposedEntry[];
  notes: InterviewNote[];
  /** The SECURITY.md text to write, when the person confirmed a change. */
  securityText?: string;
  declined: boolean;
  /** The person's answers go to the human block of the threat model. */
  writeNotes: boolean;
  warnings: string[];
  /** Where the scan findings came from and how many questions they made, when a scan was used. */
  scan?: { source: string; findings: number; questions: number };
}

const covered = (securityText: string | undefined): Set<string> => new Set(parseScope(securityText ?? "").entries.filter(entry => entry.category && !entry.paths.length).map(entry => entry.category!));

const humanCovered = (humanText: readonly string[]): Set<string> => {
  const text = humanText.join("\n").toLowerCase();
  return new Set(ATTACK_CATEGORY_IDS.filter(id => text.includes(id) || text.includes(id.replace(/-/g, " "))));
};

/** Run the whole interview and return what to write. Writes nothing itself. */
export async function runInterview(params: InterviewParams): Promise<InterviewResult> {
  const { io } = params;
  const warnings: string[] = [];
  const existing = parseScope(params.securityText ?? "");
  let mode = "model" as InterviewResult["mode"];
  let fallbackReason: string | undefined;
  let entries: ProposedEntry[] = [];
  let notes: InterviewNote[] = [];
  let asked = 0;
  let answered = 0;

  const fallback = async (reason: string): Promise<void> => {
    mode = "questionnaire"; fallbackReason = reason;
    io.say(`Mode: fixed questionnaire (${reason}).`);
    const result = await runQuestionnaire(io);
    entries = result.entries; notes = result.notes; asked = FIXED_QUESTIONS.length; answered = result.notes.length;
  };

  let scanSummary: InterviewResult["scan"];
  if (!params.model) await fallback("no model could be reached");
  else {
    io.say("Mode: questions from the model, answers from you.");
    const fromScan = params.scan ? findingQuestions(params.scan.findings, { declared: existing.entries, humanText: params.humanText, fileExists: params.fileExists, now: params.now }) : undefined;
    if (params.scan) io.say(`Findings: ${params.scan.findings.length} from ${params.scan.label}. The questions cover the classes that came up.`);
    else io.say(params.scanNote ?? "No scan is used, so the questions come from reading the code only.");
    io.say("Reading the code to find what only you can decide...");
    const asking = await params.model(scopeQuestionsPrompt(params.target, { draftPath: params.draftPath, existing: { scope: existing.entries.map(entry => scopeBullet({ ...entry, vector: entry.category ?? entry.vector }).slice(2)), humanText: params.humanText } }), "Scope interview questions");
    const skip = new Set([...covered(params.securityText), ...humanCovered(params.humanText)]);
    const parsed = parseQuestions(asking.reply, { fileExists: params.fileExists, covered: skip });
    const noList = asking.failed || (!parsed.questions.length && parsed.dropped.some(note => note.startsWith("the reply held no question list")));
    const merged = mergeQuestions(fromScan?.questions ?? [], noList ? [] : parsed.questions);
    if (params.scan) scanSummary = { source: params.scan.source, findings: params.scan.findings.length, questions: fromScan?.questions.length ?? 0 };
    if (noList && !merged.length) {
      await fallback(asking.budgetExhausted ? "the interview budget was used up" : "the model did not return usable questions");
    } else if (!merged.length) {
      io.say("There is nothing the code or the scan cannot decide, so there is nothing to ask. Nothing was written.");
      return { mode, asked: 0, answered: 0, entries: [], notes: [], declined: false, writeNotes: false, warnings: parsed.dropped, ...(scanSummary ? { scan: scanSummary } : {}) };
    } else {
      warnings.push(...parsed.dropped);
      if (noList) warnings.push("the model did not return usable questions; the questions come from the scan only");
      asked = merged.length;
      const result = await askQuestions(merged, io);
      answered = result.answers.length;
      notes = result.answers.map(answer => ({ question: `${answer.question.question}${answer.question.evidence && !answer.question.places ? ` (${answer.question.evidence})` : ""}`, answer: `${answer.decision === "in" ? "in scope" : "out of scope"} (${answer.question.category})${answer.words ? `: ${answer.words}` : ""}` }));
      let wording: Wording[] = [];
      if (result.answers.length) {
        const forPrompt: InterviewAnswerForPrompt[] = result.answers.map(answer => ({ questionId: answer.question.id, category: answer.question.category, decision: answer.decision === "in" ? "in scope" : "out of scope", words: answer.words, ...(answer.question.evidence ? { evidence: answer.question.evidence } : {}) }));
        io.say("\nWording the entries from your answers...");
        const worded = await params.model(scopeWordingPrompt(params.target, forPrompt), "Scope interview wording");
        if (worded.failed) warnings.push("the wording call failed; your own words are used as the reasons");
        else wording = parseWording(worded.reply);
      }
      entries = entriesFromAnswers(result.answers, wording, params.now);
    }
  }

  // A reason the person did not give is asked once.
  if (mode === "questionnaire") {
    for (const entry of entries) {
      if (entry.reason !== "not given") continue;
      const why = plainLine((await io.ask(`Why is '${entry.vector}' ${entry.kind === "in" ? "in" : "out of"} scope? One line, or Enter to leave it blank: `)) ?? "", 400);
      if (why) entry.reason = why;
    }
  }
  const unmatched = entries.filter(entry => !categoryFromLabel(entry.vector));
  for (const entry of unmatched) warnings.push(`unmatched scope entry: '${entry.vector}' names no vulnerability category I know; it will be kept but labels nothing`);
  if (!entries.length) {
    io.say("\nNo scope entries came out of your answers.");
    return { mode, ...(fallbackReason ? { fallbackReason } : {}), asked, answered, entries: [], notes, declined: false, writeNotes: mode === "questionnaire" && notes.length > 0, warnings, ...(scanSummary ? { scan: scanSummary } : {}) };
  }
  const kept = await confirmEntries(entries, io);
  if (!kept.length) {
    io.say("\nNo entry was accepted. Nothing was written.");
    return { mode, ...(fallbackReason ? { fallbackReason } : {}), asked, answered, entries: [], notes, declined: true, writeNotes: false, warnings, ...(scanSummary ? { scan: scanSummary } : {}) };
  }
  const before = params.securityText ?? MINIMAL_HEADER;
  const after = addScopeEntries(before, kept);
  io.say(`\nChange to SECURITY.md${params.securityText === undefined ? " (new file)" : ""}:\n${diffText(params.securityText ?? "", after)}\n`);
  const sure = ((await io.ask("Write these changes? [y/N]: ")) ?? "n").trim().toLowerCase();
  if (sure !== "y" && sure !== "yes") {
    io.say("Nothing was written.");
    return { mode, ...(fallbackReason ? { fallbackReason } : {}), asked, answered, entries: kept, notes, declined: true, writeNotes: false, warnings, ...(scanSummary ? { scan: scanSummary } : {}) };
  }
  return { mode, ...(fallbackReason ? { fallbackReason } : {}), asked, answered, entries: kept, notes, securityText: after, declined: false, writeNotes: true, warnings, ...(scanSummary ? { scan: scanSummary } : {}) };
}
