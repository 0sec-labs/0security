// SCIM 2.0 server (RFC 7643 and RFC 7644) for Users and Groups. Paid feature: scim. Server mode only.
// An identity provider signs in with a bearer token an owner made. SCIM manages the accounts it created and nothing else.
import type { IncomingMessage, ServerResponse } from "node:http";
import { audit } from "./audit.js";
import { WebRequestError, readJson } from "./dashboard-http.js";
import { TeamAuth, TeamAuthError } from "./team-auth.js";
import type { ScimGroupRecord } from "@0/engine/storage";
import { SCHEMA_GROUP, SCHEMA_USER, ScimError, applyPatch, errorFrom, featureMode, matchesFilter, paginate, parseFilter, requireFeature, resourceTypes, schemaDocuments, serviceProviderConfig } from "../enterprise-bridge.js";
import type { TeamUserRow } from "@0/engine/storage";

/**
 * What the license allows. `full`: everything. `read-only` (past the grace period): reads and deprovisioning only.
 * `none` (no license, or a license without scim): deprovisioning only. Disabling a person is never blocked by a
 * license, because blocking it would leave access open. Creating or changing access is always refused unless `full`.
 */
type Mode = "full" | "read-only" | "none";
const refuse = (): never => { throw new ScimError(403, undefined, requireFeature("scim") ?? "SCIM needs an enterprise license that includes scim."); };
const needFull = (mode: Mode): void => { if (mode !== "full") refuse(); };
const needRead = (mode: Mode): void => { if (mode === "none") refuse(); };

export const SCIM_BASE = "/scim/v2";
const MAX_BODY = 1_048_576;
const failureBooks = new WeakMap<TeamAuth, Map<string, { count: number; until: number }>>();

export interface ScimContext {
  auth: TeamAuth;
  /** Revokes the findings API keys a person created. */
  revokeApiKeys: (userId: string) => number;
  clientIp: string;
  baseUrl: string;
}

type Json = Record<string, unknown>;
const isObject = (value: unknown): value is Json => value !== null && typeof value === "object" && !Array.isArray(value);

function send(res: ServerResponse, status: number, body?: unknown, headers: Record<string, string> = {}): void {
  const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body), "utf8");
  res.writeHead(status, { "Content-Type": "application/scim+json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...(payload ? { "Content-Length": payload.length } : {}), ...headers });
  res.end(payload);
}

function userResource(ctx: ScimContext, row: TeamUserRow, groups: readonly ScimGroupRecord[]): Json {
  const mine = groups.filter(group => group.memberIds.includes(row.id));
  return {
    schemas: [SCHEMA_USER], id: row.id, ...(row.externalId ? { externalId: row.externalId } : {}), userName: row.userName ?? row.id,
    name: { formatted: row.name }, displayName: row.name, ...(row.email ? { emails: [{ value: row.email, type: "work", primary: true }] } : {}),
    active: row.active, groups: mine.map(group => ({ value: group.id, display: group.displayName, $ref: `${ctx.baseUrl}${SCIM_BASE}/Groups/${group.id}` })),
    meta: { resourceType: "User", created: row.createdAt, lastModified: row.updatedAt, location: `${ctx.baseUrl}${SCIM_BASE}/Users/${row.id}` },
  };
}

function groupResource(ctx: ScimContext, group: ScimGroupRecord, includeMembers = true): Json {
  const members = group.memberIds.flatMap(id => { const user = ctx.auth.scimAccount(id); return user ? [{ value: id, display: user.name, $ref: `${ctx.baseUrl}${SCIM_BASE}/Users/${id}` }] : []; });
  return {
    schemas: [SCHEMA_GROUP], id: group.id, ...(group.externalId ? { externalId: group.externalId } : {}), displayName: group.displayName, ...(includeMembers ? { members } : {}),
    meta: { resourceType: "Group", created: group.createdAt, lastModified: group.updatedAt, location: `${ctx.baseUrl}${SCIM_BASE}/Groups/${group.id}` },
  };
}

const text = (value: unknown, name: string, max = 160, required = false): string | undefined => {
  if (value === undefined || value === null || value === "") { if (required) throw new ScimError(400, "invalidValue", `${name} is required`); return undefined; }
  if (typeof value !== "string") throw new ScimError(400, "invalidValue", `${name} must be a string`);
  const trimmed = value.trim();
  if (trimmed.length > max) throw new ScimError(400, "invalidValue", `${name} is too long`);
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) throw new ScimError(400, "invalidValue", `${name} has control characters`);
  return trimmed || undefined;
};
const flag = (value: unknown): boolean | undefined => {
  if (value === undefined) return undefined;
  if (typeof value === "boolean") return value;
  if (typeof value === "string" && /^(true|false)$/i.test(value)) return value.toLowerCase() === "true";
  throw new ScimError(400, "invalidValue", "active must be true or false");
};

/** What 0 keeps from a SCIM user. Other attributes are accepted and not stored. */
function readUser(input: Json) {
  const userName = text(input.userName, "userName", 160, true)!;
  const name = isObject(input.name) ? input.name : {};
  const emails = Array.isArray(input.emails) ? input.emails.filter(isObject) : [];
  const primary = emails.find(item => item.primary === true) ?? emails[0];
  const email = text(primary?.value, "emails.value", 254) ?? (userName.includes("@") ? userName : undefined);
  const display = text(input.displayName, "displayName") ?? text(name.formatted, "name.formatted") ?? ([text(name.givenName, "name.givenName"), text(name.familyName, "name.familyName")].filter(Boolean).join(" ") || undefined) ?? userName;
  return { userName, name: display, externalId: text(input.externalId, "externalId", 256) ?? null, email: email ?? null, active: flag(input.active) };
}

function readGroup(input: Json) {
  const members = input.members === undefined ? [] : input.members;
  if (!Array.isArray(members) || members.length > 50_000) throw new ScimError(400, "invalidValue", "members must be a list");
  const ids = members.map(member => { if (!isObject(member) || typeof member.value !== "string") throw new ScimError(400, "invalidValue", "Each member needs a value"); return member.value; });
  return { displayName: text(input.displayName, "displayName", 256, true)!, externalId: text(input.externalId, "externalId", 256) ?? null, memberIds: ids };
}

async function body(req: IncomingMessage): Promise<Json> {
  let parsed: unknown;
  try { parsed = await readJson(req, MAX_BODY); }
  catch (error) { throw error instanceof WebRequestError && error.statusCode === 413 ? new ScimError(413, "tooMany", "The request body is too large") : new ScimError(400, "invalidSyntax", "The request body is not valid JSON"); }
  if (!isObject(parsed)) throw new ScimError(400, "invalidSyntax", "The request body must be a JSON object");
  return parsed;
}

function listQuery(url: URL, resources: Json[], includeMembers = true) {
  const filter = url.searchParams.get("filter");
  const matched = filter ? (() => { const node = parseFilter(filter); return resources.filter(resource => matchesFilter(node, resource)); })() : resources;
  const page = paginate(matched, { startIndex: url.searchParams.get("startIndex"), count: url.searchParams.get("count") });
  // The filter may name members; only the answer leaves them out.
  return includeMembers ? page : { ...page, Resources: page.Resources.map(resource => { const { members: _members, ...rest } = resource; return rest; }) };
}

/** Run a group change, then recompute roles. If that would leave nobody able to manage users, put the group back and refuse. */
function changeGroup<T>(ctx: ScimContext, actor: string, previous: ScimGroupRecord | null, created: { id: string } | null, change: () => T): T {
  const store = ctx.auth.scim!;
  const result = change();
  try { recordRoleChanges(ctx, actor); }
  catch (error) {
    if (created) store.deleteGroup(created.id);
    else if (previous) store.saveGroup({ id: previous.id, displayName: previous.displayName, externalId: previous.externalId, memberIds: previous.memberIds });
    throw error;
  }
  return result;
}

function recordRoleChanges(ctx: ScimContext, actor: string): void {
  for (const change of ctx.auth.applyScimGroupRoles()) audit({ actor, action: "user.role_changed", subject: change.userId, detail: { id: change.userId, old: change.old, new: change.new, source: change.source } });
}

function deprovision(ctx: ScimContext, actor: string, row: TeamUserRow, reason: "inactive" | "deleted"): TeamUserRow {
  if (ctx.auth.isLastManager(row.id)) throw new ScimError(409, "mutability", "This is the last account that can manage users, so it cannot be disabled");
  const next = ctx.auth.scimUpdate(row.id, { active: false, ...(reason === "deleted" ? { deleted: true } : {}) });
  const sessions = ctx.auth.revokeSessions(row.id);
  const keys = ctx.revokeApiKeys(row.id);
  audit({ actor, action: "user.deprovisioned", subject: row.id, detail: { id: row.id, source: "scim", reason, count: sessions + keys } });
  return next;
}

async function users(ctx: ScimContext, req: IncomingMessage, url: URL, id: string | undefined, actor: string, mode: Mode): Promise<{ status: number; body?: unknown; headers?: Record<string, string> }> {
  const method = req.method ?? "GET";
  const groups = ctx.auth.scim!.listGroups();
  const view = (row: TeamUserRow) => userResource(ctx, row, groups);
  if (!id) {
    if (method === "GET") { needRead(mode); return { status: 200, body: listQuery(url, ctx.auth.scimAccounts().map(view)) }; }
    if (method === "POST") {
      needFull(mode);
      const input = readUser(await body(req));
      const row = ctx.auth.scimCreate({ userName: input.userName, name: input.name, externalId: input.externalId, email: input.email, active: input.active ?? true });
      recordRoleChanges(ctx, actor);
      audit({ actor, action: "scim.user.created", subject: row.id, detail: { id: row.id, role: row.role, source: "scim" } });
      const fresh = ctx.auth.scimAccount(row.id)!;
      return { status: 201, body: view(fresh), headers: { Location: `${ctx.baseUrl}${SCIM_BASE}/Users/${row.id}` } };
    }
    throw new ScimError(405, undefined, "Use GET or POST");
  }
  const row = ctx.auth.scimAccount(id);
  if (!row) throw new ScimError(404, undefined, "User not found");
  if (method === "GET") { needRead(mode); return { status: 200, body: view(row) }; }
  if (method === "DELETE") { deprovision(ctx, actor, row, "deleted"); return { status: 204 }; }
  if (method !== "PUT" && method !== "PATCH") throw new ScimError(405, undefined, "Use GET, PUT, PATCH or DELETE");
  const incoming = await body(req);
  const next = method === "PATCH" ? applyPatch(view(row), incoming, { booleanAttributes: ["active"] }) : incoming;
  const input = readUser(method === "PATCH" ? next : { ...next, active: next.active ?? row.active });
  const wantActive = input.active ?? row.active;
  if (mode !== "full") {
    // Without a full license the only change SCIM can make is to disable the account.
    if (wantActive !== false) refuse();
    const done = row.active ? deprovision(ctx, actor, row, "inactive") : row;
    return { status: 200, body: view(done) };
  }
  let updated = ctx.auth.scimUpdate(row.id, { name: input.name, userName: input.userName, externalId: input.externalId, email: input.email });
  if (row.active && !wantActive) updated = deprovision(ctx, actor, updated, "inactive");
  else if (!row.active && wantActive) { updated = ctx.auth.scimUpdate(row.id, { active: true }); audit({ actor, action: "user.reactivated", subject: row.id, detail: { id: row.id, source: "scim" } }); }
  audit({ actor, action: "scim.user.updated", subject: row.id, detail: { id: row.id, source: "scim" } });
  return { status: 200, body: view(updated) };
}

function checkMembers(ctx: ScimContext, ids: readonly string[]): void {
  for (const id of ids) if (!ctx.auth.scimAccount(id)) throw new ScimError(400, "invalidValue", `Member ${id.slice(0, 60)} is not a user managed by SCIM`);
}

async function groups(ctx: ScimContext, req: IncomingMessage, url: URL, id: string | undefined, actor: string, mode: Mode): Promise<{ status: number; body?: unknown; headers?: Record<string, string> }> {
  const method = req.method ?? "GET";
  const store = ctx.auth.scim!;
  const members = url.searchParams.get("excludedAttributes")?.split(",").map(name => name.trim().toLowerCase()).includes("members") ? false : true;
  const view = (group: ScimGroupRecord) => groupResource(ctx, group, members);
  if (!id) {
    if (method === "GET") needRead(mode);
    if (method === "GET") return { status: 200, body: listQuery(url, store.listGroups().map(group => groupResource(ctx, group, true)), members) };
    if (method === "POST") {
      needFull(mode);
      const input = readGroup(await body(req));
      if (store.groupNameTaken(input.displayName)) throw new ScimError(409, "uniqueness", "displayName is already in use");
      checkMembers(ctx, input.memberIds);
      const group = store.saveGroup(input);
      changeGroup(ctx, actor, null, group, () => undefined);
      audit({ actor, action: "scim.group.created", subject: group.displayName, detail: { id: group.id, name: group.displayName, count: group.memberIds.length, source: "scim" } });
      return { status: 201, body: view(group), headers: { Location: `${ctx.baseUrl}${SCIM_BASE}/Groups/${group.id}` } };
    }
    throw new ScimError(405, undefined, "Use GET or POST");
  }
  const group = store.getGroup(id);
  if (!group) throw new ScimError(404, undefined, "Group not found");
  if (method === "GET") { needRead(mode); return { status: 200, body: view(group) }; }
  needFull(mode);
  if (method === "DELETE") {
    changeGroup(ctx, actor, group, null, () => store.deleteGroup(id));
    audit({ actor, action: "scim.group.deleted", subject: group.displayName, detail: { id, name: group.displayName, source: "scim" } });
    return { status: 204 };
  }
  if (method !== "PUT" && method !== "PATCH") throw new ScimError(405, undefined, "Use GET, PUT, PATCH or DELETE");
  const incoming = await body(req);
  const input = readGroup(method === "PATCH" ? applyPatch(groupResource(ctx, group, true), incoming) : incoming);
  if (store.groupNameTaken(input.displayName, id)) throw new ScimError(409, "uniqueness", "displayName is already in use");
  checkMembers(ctx, input.memberIds);
  const saved = changeGroup(ctx, actor, group, null, () => store.saveGroup({ id, ...input }));
  audit({ actor, action: "scim.group.updated", subject: saved.displayName, detail: { id, name: saved.displayName, count: saved.memberIds.length, source: "scim" } });
  // Okta and Entra accept the updated group or no body. The updated group is the safer answer.
  return { status: 200, body: view(saved) };
}

function bearer(req: IncomingMessage): string | undefined {
  const header = req.headers.authorization;
  return typeof header === "string" && /^Bearer\s+\S+$/i.test(header) ? header.replace(/^Bearer\s+/i, "") : undefined;
}

/** Handle a request under /scim/v2. The caller has already applied the host and origin rules. */
export async function handleScimRequest(req: IncomingMessage, res: ServerResponse, url: URL, ctx: ScimContext): Promise<void> {
  try {
    if (!ctx.auth.enabled || !ctx.auth.scim) throw new ScimError(404, undefined, "SCIM needs a team workspace");
    const now = Date.now();
    let failures = failureBooks.get(ctx.auth);
    if (!failures) { failures = new Map(); failureBooks.set(ctx.auth, failures); }
    const blocked = failures.get(ctx.clientIp);
    if (blocked && blocked.until > now && blocked.count >= 10) { send(res, 429, { ...errorFrom(new ScimError(429, "tooMany", "Too many failed sign-ins")).body }, { "Retry-After": String(Math.ceil((blocked.until - now) / 1000)) }); return; }
    const presented = bearer(req);
    const token = presented ? ctx.auth.scim.verifyToken(presented) : null;
    if (!token) {
      const row = blocked && blocked.until > now ? blocked : { count: 0, until: now + 60_000 };
      row.count++; failures.set(ctx.clientIp, row);
      if (failures.size > 1000) for (const [ip, entry] of failures) if (entry.until <= now) failures.delete(ip);
      audit({ actor: "anonymous", action: "scim.auth_failed", subject: url.pathname, outcome: "denied", detail: { client: ctx.clientIp, status: 401 } });
      send(res, 401, errorFrom(new ScimError(401, undefined, "A valid bearer token is required")).body, { "WWW-Authenticate": 'Bearer realm="scim"' });
      return;
    }
    failures.delete(ctx.clientIp);
    const mode = featureMode("scim");
    const actor = `scim:${token.name}`;
    const path = url.pathname.slice(SCIM_BASE.length).replace(/\/+$/, "");
    const method = req.method ?? "GET";
    const base = `${ctx.baseUrl}${SCIM_BASE}`;
    if (method === "GET" && ["/ServiceProviderConfig", "/ResourceTypes", "/Schemas"].includes(path)) {
      needRead(mode);
      return send(res, 200, path === "/ServiceProviderConfig" ? serviceProviderConfig() : path === "/ResourceTypes" ? paginate(resourceTypes(base), {}) : paginate(schemaDocuments(base), {}));
    }
    const m = /^\/(Users|Groups)(?:\/([^/]+))?$/.exec(path);
    if (!m) throw new ScimError(404, undefined, "No such SCIM endpoint");
    const id = m[2] === undefined ? undefined : decodeURIComponent(m[2]);
    const result = m[1] === "Users" ? await users(ctx, req, url, id, actor, mode) : await groups(ctx, req, url, id, actor, mode);
    send(res, result.status, result.body, result.headers);
  } catch (error) {
    if (error instanceof TeamAuthError) { const status = error.statusCode; send(res, status, errorFrom(new ScimError(status, status === 409 && /in use/.test(error.message) ? "uniqueness" : undefined, error.message)).body); return; }
    const { status, body: payload } = errorFrom(error);
    send(res, status, payload);
  }
}
