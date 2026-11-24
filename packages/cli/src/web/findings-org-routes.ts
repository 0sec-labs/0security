// Org dashboard routes of the shared findings server, for the browser console:
//   GET /api/findings-server/overview?repo=owner/name   counts and rows across repositories
//   GET /api/findings-server/history/<fingerprint>      who changed a finding, when and why
// Reads of stored data stay available when a license has expired; without any license the answer says what is needed.
import type { IncomingMessage, ServerResponse } from "node:http";
import { json } from "./dashboard-http.js";
import { findingsServiceFor } from "./findings-service.js";
import { canReadFindingsServer, findingsServerMessage, hasFindingsServer, summarizeOrg } from "../findings-server-bridge.js";

const REPO = /^[A-Za-z0-9._\/-]{1,300}$/;
const FINGERPRINT = /^[A-Za-z0-9_.:-]{1,256}$/;

export function parseFindingsOrgPath(pathname: string): { kind: "overview" } | { kind: "history"; fingerprint: string } | null {
  if (pathname === "/api/findings-server/overview") return { kind: "overview" };
  const match = /^\/api\/findings-server\/history\/([^/]+)$/.exec(pathname);
  if (!match) return null;
  try { return { kind: "history", fingerprint: decodeURIComponent(match[1]!) }; } catch { return null; }
}

export async function handleFindingsOrgRequest(req: IncomingMessage, res: ServerResponse, url: URL, route: NonNullable<ReturnType<typeof parseFindingsOrgPath>>, dbPath: string | undefined): Promise<void> {
  if (req.method !== "GET") { json(res, 405, { error: "Method not allowed." }); return; }
  if (!canReadFindingsServer()) { json(res, 200, { available: false, canWrite: false, message: findingsServerMessage() }); return; }
  const canWrite = hasFindingsServer();
  const service = findingsServiceFor(dbPath);
  const shared = service.sources().sources[0]!;
  if (route.kind === "history") {
    if (!FINGERPRINT.test(route.fingerprint)) { json(res, 400, { error: "Invalid finding fingerprint." }); return; }
    const history = await shared.withDatabase("read", db => db.listFindingHistory(route.fingerprint));
    json(res, 200, { available: true, canWrite, fingerprint: route.fingerprint, history });
    return;
  }
  const repo = url.searchParams.get("repo") ?? undefined;
  if (repo !== undefined && !REPO.test(repo)) { json(res, 400, { error: "Invalid repository." }); return; }
  const all = await shared.withDatabase("read", db => db.listOrgFindings());
  const rows = repo ? all.filter(row => row.repo === repo) : all;
  json(res, 200, {
    available: true, canWrite,
    repos: [...new Set(all.map(row => row.repo))].sort(),
    summary: summarizeOrg(rows),
    findings: rows.slice(0, 500),
    truncated: rows.length > 500,
  });
}
