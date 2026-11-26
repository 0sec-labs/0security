// Per-family finding routes (detail, triage, workflow) over the merged findings view.
import type { IncomingMessage, ServerResponse } from "node:http";
import type { osecDB } from "@0/engine/storage";
import { buildFindingConsoleCommand } from "../finding-handoff.js";
import { audit, auditActor, type AuditCaller } from "./audit.js";
import { json, readJsonObject, requireControlToken } from "./dashboard-http.js";
import { findingsServiceFor } from "./findings-service.js";
import {
  type DBEventRow, type DBFindingRow, type DBScanRow, type DBSessionRow, type DBVerdictRow,
  buildArtifacts, buildCases, buildWorkItems, buildWorkflowSummary, normalizeFinding, normalizeTriageStatus, normalizeWorkflowStatus,
} from "./dashboard-summaries.js";
import { workflowTransitionRejection } from "./dashboard-api.js";
import { hasFindingsServer, suppressionReasonError, triageHistoryAction } from "../findings-server-bridge.js";
import type { TargetFilter } from "./findings-scope.js";
import { findingFixInfo, locationOf } from "./finding-fix.js";

type Persisted = { id: string; kind: string; title?: string; label?: string; owner?: string | null; status?: string; summary?: string | null; content?: string | null };

function collect(db: osecDB, fingerprint: string) {
  const rows = (db.getRelatedFindings(fingerprint) as DBFindingRow[]).map(normalizeFinding);
  const scans = [...new Map(rows.map(row => db.getScan(row.scanId) as DBScanRow | undefined).filter(Boolean).map(scan => [scan!.id, scan!] as const)).values()];
  return {
    rows, scans,
    verdicts: db.listVerdicts(rows.map(row => row.id)) as DBVerdictRow[],
    sessions: db.listSessions({ scanIds: [...new Set(rows.map(row => row.scanId))], status: "running" }) as DBSessionRow[],
    events: scans.flatMap(scan => db.getEvents(scan.id) as DBEventRow[]),
    workItems: (db.listWorkItems?.({ findingFingerprint: fingerprint, limit: 50 }) ?? []) as Persisted[],
    artifacts: (db.listArtifacts?.({ findingFingerprint: fingerprint, limit: 100 }) ?? []) as Persisted[],
  };
}

export async function handleFindingFamilyRequest(
  req: IncomingMessage, res: ServerResponse, fingerprint: string, action: "triage" | "workflow" | undefined,
  dbPath: string | undefined, controlToken: string, engineBearer?: string, caller: AuditCaller = { engineRequest: false }, scope?: TargetFilter,
): Promise<void> {
  const findings = findingsServiceFor(dbPath);
  if (scope) {
    // A scoped account sees a family only when every scan that holds it is inside its scope.
    const targets = (await findings.readFamily(fingerprint, db => collect(db, fingerprint))).flatMap(part => part.scans.map(scan => scan.target));
    if (targets.length === 0 || !targets.every(target => scope(target))) { json(res, 404, { error: "Not found" }); return; }
  }
  if (req.method === "POST" && action === "triage") {
    if (!requireControlToken(req, res, controlToken, engineBearer)) return;
    const body = await readJsonObject<{ triageStatus?: string; triageNote?: string }>(req);
    const status = normalizeTriageStatus(body.triageStatus);
    const note = typeof body.triageNote === "string" ? body.triageNote : undefined;
    // With the shared findings server licensed, a suppression needs a reason and every decision is kept in the history.
    const recordHistory = hasFindingsServer();
    if (recordHistory) {
      const missingReason = suppressionReasonError(status, note);
      if (missingReason) { json(res, 400, { error: missingReason }); return; }
    }
    const actor = caller.engineRequest ? "engine" : caller.userId ?? "local operator";
    // The decision applies to the whole family, in every database that holds one of its findings.
    await findings.writeFamily(fingerprint, db => {
      const before = recordHistory ? db.getLatestFindingByFingerprint(fingerprint) : undefined;
      db.updateFindingTriageByFingerprint(fingerprint, status, note);
      if (recordHistory) {
        const labels = db.repoOfFingerprint(fingerprint);
        db.appendFindingHistory({ fingerprint, actor, action: triageHistoryAction(status), reason: note?.trim() || null, prevState: before?.triageStatus ?? "new", newState: status, repo: labels?.repo ?? null, source: labels?.source ?? null });
      }
    });
    audit({ actor: auditActor(caller), action: "finding.triage", subject: fingerprint, detail: { fingerprint, decision: status, ...(caller.userId ? { id: caller.userId } : {}) } });
    json(res, 200, { ok: true });
    return;
  }
  if (req.method === "POST" && action === "workflow") {
    if (!requireControlToken(req, res, controlToken, engineBearer)) return;
    const body = await readJsonObject<{ workflowStatus?: string; workflowAssignee?: string }>(req);
    const heads = (await findings.readFamily(fingerprint, db => db.getLatestFindingByFingerprint(fingerprint))).filter(Boolean);
    const current = heads.sort((a, b) => (b!.timestamp ?? 0) - (a!.timestamp ?? 0))[0];
    if (!current) { json(res, 404, { error: "Not found" }); return; }
    const rejection = workflowTransitionRejection(body.workflowStatus, current.workflowStatus);
    if (rejection) { json(res, rejection.status, { error: rejection.error }); return; }
    const assignee = typeof body.workflowAssignee === "string" ? body.workflowAssignee.trim() : null;
    const nextWorkflow = normalizeWorkflowStatus(body.workflowStatus);
    // Cancelled suppresses the finding, so with the shared findings server licensed it needs the same reason as Dismiss.
    const recordHistory = hasFindingsServer();
    const missingReason = recordHistory && nextWorkflow === "cancelled" && current.triageStatus !== "suppressed" ? suppressionReasonError("suppressed", current.triageNote) : null;
    if (missingReason) { json(res, 400, { error: `${missingReason} Dismiss the finding with a note instead.` }); return; }
    const actor = caller.engineRequest ? "engine" : caller.userId ?? "local operator";
    await findings.writeFamily(fingerprint, db => {
      const before = recordHistory ? db.getLatestFindingByFingerprint(fingerprint) : undefined;
      db.updateFindingWorkflowByFingerprint(fingerprint, nextWorkflow, assignee);
      const after = recordHistory ? db.getLatestFindingByFingerprint(fingerprint) : undefined;
      if (before && after && (before.triageStatus ?? "new") !== (after.triageStatus ?? "new")) {
        const labels = db.repoOfFingerprint(fingerprint);
        const newState = after.triageStatus ?? "new";
        db.appendFindingHistory({ fingerprint, actor, action: triageHistoryAction(newState), reason: newState === "suppressed" ? before.triageNote ?? null : null, prevState: before.triageStatus ?? "new", newState, repo: labels?.repo ?? null, source: labels?.source ?? null });
      }
    });
    json(res, 200, { ok: true });
    return;
  }

  const parts = await findings.readFamily(fingerprint, db => collect(db, fingerprint));
  const rows = parts.flatMap(part => part.rows).sort((a, b) => (b.timestamp ?? 0) - (a.timestamp ?? 0) || String(b.id).localeCompare(String(a.id)));
  if (rows.length === 0) { json(res, 404, { error: "Not found" }); return; }
  const verdicts = parts.flatMap(part => part.verdicts);
  const sessions = parts.flatMap(part => part.sessions);
  const scans = [...new Map(parts.flatMap(part => part.scans).map(scan => [scan.id, scan] as const)).values()];
  const workflow = buildWorkflowSummary(rows, verdicts, sessions);
  const scanIds = [...new Set(rows.map(row => row.scanId))];
  const familyCase = buildCases(scans, [{ fingerprint, latest: rows[0], count: rows.length, scanCount: scanIds.length, sourceScanIds: scanIds.sort(), workflow }])[0] ?? null;
  const workItems = parts.flatMap(part => part.workItems);
  const artifacts = parts.flatMap(part => part.artifacts);
  const merged = (await findings.list()).families.find(family => family.key === fingerprint);
  // Optional and additive: older clients ignore both. Neither reads a file from the repository.
  const location = locationOf(rows as Array<{ reviewAnnotation?: unknown }>);
  const fix = await findingFixInfo(fingerprint, String(rows[0]!.id), scope);
  json(res, 200, {
    location, fix,
    consoleCommand: buildFindingConsoleCommand(rows[0]!, dbPath),
    fingerprint, case: familyCase, latest: rows[0], rows, workflow,
    provenance: merged?.provenance ?? null,
    workItems: workItems.length > 0
      ? workItems.map(item => ({ id: item.id, kind: item.kind, title: item.title, owner: item.owner ?? null, status: item.status, summary: item.summary ?? "" }))
      : buildWorkItems({ fingerprint, workflow, rows, verdicts }),
    artifacts: artifacts.length > 0
      ? artifacts.map(artifact => ({ id: artifact.id, kind: artifact.kind, label: artifact.label, summary: artifact.content ? `${artifact.content.length} chars captured` : "Persisted artifact" }))
      : buildArtifacts({ fingerprint, latest: rows[0], verdicts, sessions, events: parts.flatMap(part => part.events) }),
  });
}
