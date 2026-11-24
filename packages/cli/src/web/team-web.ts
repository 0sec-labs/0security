import type { IncomingMessage } from "node:http";
import { z } from "zod";
import { TeamAuth, TeamAuthError, getSessionId, type TeamIdentity } from "./team-auth.js";
import { decideRoute, hasFeature, requireFeature } from "../enterprise-bridge.js";
import { CollaborationService, type CollaborationResourceKind } from "./collaboration.js";
import type { ConsoleGateway } from "./console-gateway.js";
import { audit, auditActor } from "./audit.js";

type Reply = { status: number; data?: unknown; headers?: Record<string, string | string[]>; redirect?: string; xml?: string };
const readOnly = (method: string) => method === "GET" || method === "HEAD";

/** Sign-in is attributed to the named member; no credential, token or cookie value is recorded. */
function auditSignIn(user: TeamIdentity, kind: "password" | "sso" | "saml", client: string): void {
  audit({ actor: auditActor({ engineRequest: false, teamEnabled: true, displayName: user.displayName }), action: "access.login", subject: "console", detail: { id: user.userId, kind, role: user.role, client } });
}

/** The browser control token authorizes the transport, never a team identity. */
export function authorizeTeamApi(auth: TeamAuth, req: IncomingMessage, path: string): TeamIdentity | null {
  if (!auth.enabled) return null;
  const actor = auth.resolveSession(req);
  if (!actor) throw new TeamAuthError("Sign in to this workspace.");
  const method = req.method ?? "GET";
  if (hasFeature("rbac")) {
    // Licensed: one permission table decides every route. A route the table does not name is refused.
    if (/^\/api\/backends\/[^/]+\/proxy/.test(path) && !path.startsWith("/api/backends/local/proxy") && !actor.permissions.includes("settings.write")) throw new TeamAuthError("Remote engine access requires the settings.write permission.", 403);
    const decision = decideRoute(actor.permissions, method, path);
    if (!decision.allowed) {
      if (decision.code === "no_permission_defined") throw new TeamAuthError("This route has no permission rule and is refused.", 403);
      throw new TeamAuthError(`Your role (${actor.roleName}) does not include the ${decision.permission} permission.`, 403);
    }
    return actor;
  }
  // Registered remote engines carry machine credentials rather than browser account credentials.
  // Until a delegated team bridge exists, only the workspace owner may use them.
  if (/^\/api\/backends\/[^/]+\/proxy/.test(path) && !path.startsWith("/api/backends/local/proxy") && actor.role !== "owner") throw new TeamAuthError("Remote engine access requires a workspace owner.", 403);
  const ownerResource = /^\/api\/(?:control|workflow-engine|backends\/[^/]+\/proxy|console\/(?:checks|connections|credentials|auth|github|settings|plugins|mcp|services|processes|environment|execution|models|project|doctor|tools|learning))(?:\/|$)/;
  if (!readOnly(method) && actor.role === "viewer") throw new TeamAuthError("This account has read-only workspace access.", 403);
  if (!readOnly(method) && ownerResource.test(path) && actor.role !== "owner") throw new TeamAuthError("Only workspace owners can change engine settings.", 403);
  if (!readOnly(method) && /^\/api\/skills\/mounts(?:\/|$)/.test(path) && actor.role !== "owner") throw new TeamAuthError("Only workspace owners can mount host folders.", 403);
  const editorResource = /^\/api\/(?:skills|engagements|findings|finding-family|console\/(?:sessions|workflows|workflow-definitions|workflow-executions|workflow-triggers))(?:\/|$)/;
  const resumeRead = method === "POST" && /^\/api\/console\/saved\/[^/]+\/resume$/.test(path);
  if (!readOnly(method) && actor.role !== "owner" && !editorResource.test(path) && !resumeRead) throw new TeamAuthError("This action requires a workspace owner.", 403);
  return actor;
}

export async function handleTeamRequest(req: IncomingMessage, url: URL, auth: TeamAuth, collaboration: CollaborationService | undefined, gateway: ConsoleGateway, readBody: () => Promise<unknown>, validateResource?: (kind: CollaborationResourceKind, id: string) => void | Promise<void>, readForm?: () => Promise<Record<string, string>>): Promise<Reply | undefined> {
  if (!url.pathname.startsWith("/api/team/")) return;
  const method = req.method ?? "GET";
  const path = url.pathname.slice("/api/team/".length);
  if (path === "session" && method === "GET") return { status: 200, data: auth.status(req) };
  if (!auth.enabled) throw new TeamAuthError("Team mode is not configured.", 404);
  if (path === "auth/login" && method === "POST") {
    const client = req.socket.remoteAddress ?? "loopback";
    const login = await auth.login(await readBody(), client);
    auditSignIn(login.user, "password", client);
    return { status: 200, data: { user: login.user }, headers: { "Set-Cookie": login.setCookie } };
  }
  if (path === "auth/sso" && method === "GET") {
    const sso = await auth.beginSSO();
    return { status: 302, redirect: sso.url, headers: { "Set-Cookie": sso.setCookie } };
  }
  if (path === "auth/callback" && method === "GET") {
    const client = req.socket.remoteAddress ?? "loopback";
    let login: Awaited<ReturnType<TeamAuth["callback"]>>;
    try { login = await auth.callback(url.searchParams, req); }
    catch (error) {
      if (error instanceof TeamAuthError) audit({ actor: "anonymous", action: "access.login_failed", subject: "console", outcome: "denied", detail: { kind: "sso", reason: error.statusCode === 403 ? "not_a_member" : "verification_failed", status: error.statusCode, client } });
      throw error;
    }
    if (login.provisioned) audit({ actor: "sso", action: "user.provisioned", subject: login.user.userId, detail: { id: login.user.userId, role: login.user.role, source: "oidc", client } });
    if (login.roleChange) audit({ actor: "sso", action: "user.role_changed", subject: login.roleChange.userId, detail: { id: login.roleChange.userId, old: login.roleChange.old, new: login.roleChange.new, source: login.roleChange.source, client } });
    auditSignIn(login.user, "sso", client);
    return { status: 302, redirect: login.redirect, headers: { "Set-Cookie": login.setCookies } };
  }
  if (path.startsWith("auth/saml/")) return handleSamlRequest(req, url, path.slice("auth/saml/".length), method, auth, readForm);
  if (path === "auth/logout" && method === "POST") {
    const user = auth.resolveSession(req); // resolve before the session is destroyed
    const reply = { status: 200, data: { ok: true }, headers: { "Set-Cookie": auth.logout(req).setCookie } };
    if (user) audit({ actor: auditActor({ engineRequest: false, teamEnabled: true, displayName: user.displayName }), action: "access.logout", subject: "console", detail: { id: user.userId, kind: "team", role: user.role } });
    return reply;
  }
  if (!auth.resolveSession(req)) throw new TeamAuthError("Sign in to this workspace.");
  if (path === "roles" && method === "GET") return { status: 200, data: { roles: auth.roleList(), licensed: hasFeature("rbac") } };
  const accountRoute = /^users\/([^/]+)$/.exec(path);
  if (accountRoute && method === "PATCH") {
    const actor = auth.resolveSession(req)!;
    const unavailable = requireFeature("rbac");
    if (unavailable) throw new TeamAuthError(unavailable, 403);
    if (!actor.permissions.includes("users.manage")) throw new TeamAuthError("Your role does not include the users.manage permission.", 403);
    const parsed = z.object({ role: z.string().min(1).max(64).optional(), scope: z.unknown().optional() }).strict().safeParse(await readBody());
    if (!parsed.success || (parsed.data.role === undefined && parsed.data.scope === undefined)) throw new TeamAuthError("Send a role, a scope, or both.", 400);
    const userId = decodeURIComponent(accountRoute[1]!);
    const change = auth.setAccess(userId, parsed.data, actor);
    const who = auditActor({ engineRequest: false, teamEnabled: true, displayName: actor.displayName });
    if (change.before.role !== change.after.role) audit({ actor: who, action: "user.role_changed", subject: userId, detail: { id: userId, old: change.before.role, new: change.after.role, source: "admin" } });
    const describe = (scope: { repos?: string[]; businessUnits?: string[] } | null) => scope ? [...(scope.repos ?? []), ...(scope.businessUnits ?? []).map(unit => `unit:${unit}`)].join(", ") || "none" : "none";
    if (describe(change.before.scope) !== describe(change.after.scope)) audit({ actor: who, action: "user.scope_changed", subject: userId, detail: { id: userId, old: describe(change.before.scope), new: describe(change.after.scope), source: "admin" } });
    return { status: 200, data: { user: auth.members().find(member => member.userId === userId) } };
  }
  const tokenRoute = /^scim-tokens(?:\/([^/]+))?$/.exec(path);
  if (tokenRoute) {
    const actor = auth.resolveSession(req)!;
    // Making a token is a paid feature. Listing and revoking tokens always work, so a lapsed license never keeps one alive.
    if (method === "POST") { const unavailable = requireFeature("scim"); if (unavailable) throw new TeamAuthError(unavailable, 403); }
    if (!actor.permissions.includes("users.manage")) throw new TeamAuthError("Your role does not include the users.manage permission.", 403);
    const store = auth.scim;
    if (!store) throw new TeamAuthError("SCIM needs the account database.", 409);
    const who = auditActor({ engineRequest: false, teamEnabled: true, displayName: actor.displayName });
    if (!tokenRoute[1] && method === "GET") return { status: 200, data: { tokens: store.listTokens() } };
    if (!tokenRoute[1] && method === "POST") {
      const parsed = z.object({ name: z.string().trim().min(1).max(80) }).strict().safeParse(await readBody());
      if (!parsed.success) throw new TeamAuthError("Give the token a name of up to 80 characters.", 400);
      const created = store.createToken(parsed.data.name);
      audit({ actor: who, action: "scim.token.created", subject: created.record.id, detail: { id: created.record.id, name: created.record.name } });
      // The token is shown once. Only its hash is stored.
      return { status: 201, data: { token: created.token, record: created.record } };
    }
    if (tokenRoute[1] && method === "DELETE") {
      const record = store.revokeToken(decodeURIComponent(tokenRoute[1]));
      if (!record) throw new TeamAuthError("No such token.", 404);
      audit({ actor: who, action: "scim.token.revoked", subject: record.id, detail: { id: record.id, name: record.name } });
      return { status: 200, data: { record } };
    }
    throw new TeamAuthError("Method not allowed.", 405);
  }
  if (!collaboration) throw new TeamAuthError("Team resource not found.", 404);
  const session = getSessionId(req)!;
  if (path === "presence" && method === "GET") return { status: 200, data: collaboration.overview(session) };
  const resource = /^rooms\/(conversation|report|workflow)\/([A-Za-z0-9_.:-]+)\/presence$/.exec(path);
  if (resource) {
    if (method !== "POST") throw new TeamAuthError("Method not allowed.", 405);
    const kind = resource[1] as CollaborationResourceKind; const id = resource[2]!;
    if (kind === "conversation") gateway.get(id);
    else if (validateResource) await validateResource(kind, id);
    else throw new TeamAuthError("Resource presence is not configured for this engine.", 404);
    collaboration.registerRoom(kind, id, session);
    return { status: 200, data: collaboration.heartbeatRoom(kind, id, session, await readBody()) };
  }
  const match = /^conversations\/([A-Za-z0-9_.:-]+)(?:\/(presence))?$/.exec(path);
  if (!match) throw new TeamAuthError("Team resource not found.", 404);
  const id = match[1]!;
  gateway.get(id);
  if (!collaboration.hasConversation(id)) collaboration.register(id, session);
  if (!match[2] && method === "GET") return { status: 200, data: collaboration.snapshot(id, session) };
  if (match[2] === "presence" && method === "POST") return { status: 200, data: collaboration.heartbeat(id, session, await readBody()) };
  throw new TeamAuthError("Method not allowed.", 405);
}

/** SAML sign-in routes. Anonymous by nature; the response is verified, not the caller. */
async function handleSamlRequest(req: IncomingMessage, url: URL, route: string, method: string, auth: TeamAuth, readForm?: () => Promise<Record<string, string>>): Promise<Reply> {
  const client = req.socket.remoteAddress ?? "loopback";
  const denied = (error: unknown): never => {
    if (error instanceof TeamAuthError) audit({ actor: "anonymous", action: "access.login_failed", subject: "console", outcome: "denied", detail: { kind: "saml", reason: error.reason ?? "verification_failed", status: error.statusCode, client } });
    throw error;
  };
  if (route === "metadata" && method === "GET") return { status: 200, xml: await auth.samlMetadata() };
  if (route === "sso" && method === "GET") {
    try { const sso = await auth.beginSAML(client); return { status: 302, redirect: sso.url, headers: { "Set-Cookie": sso.setCookie } }; } catch (error) { return denied(error); }
  }
  if (route === "acs" && method === "POST") {
    if (!readForm) throw new TeamAuthError("SAML sign-in is not available on this engine.", 404);
    try { return { status: 303, redirect: (await auth.samlAcs(await readForm())).redirect }; } catch (error) { return denied(error); }
  }
  if (route === "complete" && method === "GET") {
    try {
      const login = auth.samlComplete(url.searchParams.get("ticket"), req);
      auditSignIn(login.user, "saml", client);
      return { status: 302, redirect: login.redirect, headers: { "Set-Cookie": login.setCookies } };
    } catch (error) { return denied(error); }
  }
  throw new TeamAuthError("Team resource not found.", 404);
}

export function assertTeamConsoleMutation(req: IncomingMessage, id: string, auth: TeamAuth, collaboration: CollaborationService | undefined, gateway: ConsoleGateway): void {
  if (!auth.enabled) return;
  gateway.get(id);
  const session = getSessionId(req);
  if (!session || !collaboration) throw new TeamAuthError("Sign in to this workspace.");
  if (!collaboration.hasConversation(id)) collaboration.register(id, session);
  collaboration.assertWriter(id, session);
}
