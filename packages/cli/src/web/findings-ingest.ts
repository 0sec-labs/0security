// POST /api/v1/findings/ingest: the shared findings server's one write route. A CI job or another machine sends a
// SARIF 2.1.0 log or the findings JSON that `0 scan --format json` writes; the server stores it once per upload and
// once per finding, labelled with the repository and source.
import type { IncomingMessage } from "node:http";
import { createHash } from "node:crypto";
import { locationLabel, normalizeAttackCategory, parseSarif, type Finding } from "@0/engine/shared";
import type { IngestFindingsResult } from "@0/engine/storage";
import { FindingsAccessError } from "./findings-access-tokens.js";
import { WebRequestError } from "./dashboard-http.js";
import { findingsServiceFor } from "./findings-service.js";
import {
  INGEST_LIMITS, IngestError, findingsServerMessage, hasFindingsServer, ingestDigest, ingestFingerprint, parseIngestBody, parseIngestLabels,
} from "../findings-server-bridge.js";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
type Severity = (typeof SEVERITIES)[number];
const sha = (value: string): string => createHash("sha256").update(value).digest("hex");
const str = (value: unknown, max: number): string => (typeof value === "string" ? value : "").slice(0, max);

/** Read a request body as text, refusing more than `maxBytes`. */
export function readBodyText(req: IncomingMessage, maxBytes: number): Promise<string> {
  const declared = Number(req.headers["content-length"]);
  if (Number.isFinite(declared) && declared > maxBytes) { req.resume(); return Promise.reject(new IngestError(`The upload is larger than ${maxBytes / (1024 * 1024)} MB.`, 413)); }
  const { promise, resolve, reject } = Promise.withResolvers<string>();
  const chunks: Buffer[] = [];
  let bytes = 0;
  let settled = false;
  const onData = (chunk: Buffer | string) => {
    if (settled) return;
    const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += data.length;
    if (bytes > maxBytes) { settled = true; req.removeListener("data", onData); req.resume(); reject(new IngestError(`The upload is larger than ${maxBytes / (1024 * 1024)} MB.`, 413)); return; }
    chunks.push(data);
  };
  req.on("data", onData);
  req.on("end", () => { if (!settled) { settled = true; resolve(Buffer.concat(chunks, bytes).toString("utf8")); } });
  req.on("error", error => { if (!settled) { settled = true; reject(error); } });
  return promise;
}

function fromSarif(text: string, repo: string, now: number): Finding[] {
  let parsed;
  try { parsed = parseSarif(text); } catch (error) { throw new IngestError(error instanceof Error ? error.message : "The SARIF log could not be read."); }
  const seen = new Set<string>();
  const findings: Finding[] = [];
  for (const item of parsed.findings) {
    // Stable when lines move: the rule, the file and what the code says, not where it sits.
    const fingerprint = ingestFingerprint(repo, [item.tool, item.ruleId, item.path ?? "", `${item.method ?? ""} ${item.endpoint ?? ""}`, (item.snippet ?? item.description).replace(/\s+/g, " ").trim().slice(0, 300)].join("\n"));
    if (seen.has(fingerprint)) continue;
    seen.add(fingerprint);
    const where = locationLabel(item);
    findings.push({
      id: `fx-${fingerprint.slice(3)}-${sha(`${now}${findings.length}`).slice(0, 8)}`, fingerprint, templateId: `${item.tool}/${item.ruleId}`, title: item.title, description: item.description,
      category: item.category, severity: item.severity, tool: item.tool,
      evidence: { request: where, response: item.snippet ?? "", analysis: `Sent by a CI job or machine as SARIF from ${item.tool}. Not verified by this server.${item.cwe.length ? ` ${item.cwe.join(", ")}.` : ""}` },
      ...(item.path && item.startLine ? { reviewAnnotation: { path: item.path, startLine: item.startLine, ...(item.endLine && item.endLine >= item.startLine ? { endLine: item.endLine } : {}) } } : {}),
      timestamp: now, status: "discovered", triageStatus: "new", workflowStatus: "backlog",
    } as Finding);
  }
  return findings;
}

function fromFindingsJson(document: Record<string, unknown>, repo: string, now: number): Finding[] {
  const seen = new Set<string>();
  const findings: Finding[] = [];
  (document.findings as unknown[]).forEach((value, index) => {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new IngestError(`Finding ${index + 1} is not an object.`);
    const item = value as Record<string, unknown>;
    const title = str(item.title, 300).trim();
    if (!title) throw new IngestError(`Finding ${index + 1} has no title.`);
    const severity = item.severity;
    if (!SEVERITIES.includes(severity as Severity)) throw new IngestError(`Finding ${index + 1} has no valid severity (critical, high, medium, low or info).`);
    const evidence = item.evidence && typeof item.evidence === "object" && !Array.isArray(item.evidence) ? item.evidence as Record<string, unknown> : {};
    const request = str(evidence.request, 4000);
    const templateId = str(item.templateId, 200) || "findings-json";
    // A fingerprint the sender already has stays stable across their runs; otherwise the rule, title and first evidence line.
    const key = typeof item.fingerprint === "string" && item.fingerprint ? `fp:${item.fingerprint.slice(0, 200)}` : [templateId, title, request.split("\n")[0]!.replace(/:\d+(?::\d+)?/g, "").trim()].join("\n");
    const fingerprint = ingestFingerprint(repo, key);
    if (seen.has(fingerprint)) return;
    seen.add(fingerprint);
    const category = typeof item.category === "string" && item.category ? item.category.slice(0, 128) as Finding["category"] : normalizeAttackCategory(templateId || title).category;
    findings.push({
      id: `fx-${fingerprint.slice(3)}-${sha(`${now}${index}`).slice(0, 8)}`, fingerprint, templateId, title, description: str(item.description, 6000) || title,
      category, severity: severity as Severity, ...(typeof item.tool === "string" && item.tool ? { tool: item.tool.slice(0, 80) } : {}),
      evidence: { request, response: str(evidence.response, 4000), analysis: `Sent by a CI job or machine as findings JSON. Not verified by this server.${evidence.analysis ? `\n\n${str(evidence.analysis, 4000)}` : ""}` },
      timestamp: now, status: "discovered", triageStatus: "new", workflowStatus: "backlog",
    } as Finding);
  });
  return findings;
}

export interface IngestReply { status: number; data: IngestFindingsResult & { repo: string; source: string; format: string } }

/** Handle one ingest request for an already authenticated `write:findings` key. */
export async function handleFindingsIngest(req: Pick<IncomingMessage, "headers" | "method"> & IncomingMessage, url: URL, credential: { name: string }, dbPath: string | undefined): Promise<IngestReply> {
  if (req.method !== "POST") throw new FindingsAccessError("Send findings with POST.", 405);
  if (!hasFindingsServer()) throw new FindingsAccessError(findingsServerMessage(), 403);
  let labels, body, parsed;
  try {
    labels = parseIngestLabels(url.searchParams, credential.name);
    body = await readBodyText(req, INGEST_LIMITS.maxBytes);
    parsed = parseIngestBody(body);
  } catch (error) {
    if (error instanceof IngestError) throw new WebRequestError(error.message, error.statusCode);
    throw error;
  }
  const now = Date.now();
  let findings: Finding[];
  try { findings = parsed.format === "sarif" ? fromSarif(body, labels.repo, now) : fromFindingsJson(parsed.document, labels.repo, now); }
  catch (error) { if (error instanceof IngestError) throw new WebRequestError(error.message, error.statusCode); throw error; }
  const digest = ingestDigest(labels.repo, labels.source, body);
  const service = findingsServiceFor(dbPath);
  const shared = service.sources().sources[0]!;
  const result = await shared.withDatabase("write", db => db.ingestFindings({
    scanId: `fx-${digest}`, digest, repo: labels.repo, source: labels.source, ...(labels.ref ? { ref: labels.ref } : {}), ...(labels.commit ? { commit: labels.commit } : {}),
    actor: `key:${credential.name}`, format: parsed.format, findings,
  }));
  return { status: result.alreadyImported ? 200 : 201, data: { ...result, repo: labels.repo, source: labels.source, format: parsed.format } };
}
