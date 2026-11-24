// A signed-in account whose role is not "owner" must not reach an owner-only route, whatever permissions its role holds
// and however the session was made (password, OIDC, SAML group role). The permission table decides what a licensed role can
// call; the handlers that are owner-only stay owner-only.
import type { IncomingMessage } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TeamUserTable, closeAuditLog } from "@0/engine/storage";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { FindingsAccessTokenStore, handleFindingsAccessTokenRequest } from "./findings-access-tokens.js";
import { configureAudit } from "./audit.js";
import { privilegedRouteDenial } from "./privileged-routes.js";
import { TeamAuth, hashTeamPassword, type TeamConfig } from "./team-auth.js";
import { authorizeTeamApi, handleTeamRequest } from "./team-web.js";
import { handleTeamSetupRequest, TeamSetupService } from "./team-setup.js";
import { applyTestLicense } from "./__fixtures__/test-license.js";

const origin = "http://127.0.0.1:48123";
let dir: string; let hash: string; let restore: (() => void) | undefined;
const opened: TeamAuth[] = [];
beforeAll(async () => { hash = await hashTeamPassword("test-only-password"); });
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "0-owner-only-")); configureAudit(join(dir, "data.db")); });
afterEach(() => { restore?.(); restore = undefined; for (const auth of opened.splice(0)) auth.closeStore(); closeAuditLog(); configureAudit(null); rmSync(dir, { recursive: true, force: true }); });

// Roles that hold a lot, but are not owner. "ops-lead" can change settings; "admin-lite" can also manage users.
const config = (): TeamConfig => ({
  workspace: { id: "owner-only", name: "Owner only" },
  users: [
    { id: "owner", name: "Owner", role: "owner", passwordHash: hash },
    { id: "lead", name: "Lead", role: "ops-lead", samlNameId: "lead@corp.test" },
    { id: "adminlite", name: "Admin lite", role: "admin-lite", samlNameId: "adminlite@corp.test" },
    { id: "viewer", name: "Viewer", role: "viewer", samlNameId: "viewer@corp.test" },
  ],
  roles: {
    "ops-lead": { permissions: ["workspace.read", "findings.read", "findings.triage", "threads.run", "settings.write"] },
    "admin-lite": { permissions: ["workspace.read", "findings.read", "findings.triage", "threads.run", "settings.write", "audit.read", "users.manage"] },
  },
});
function start() {
  const auth = new TeamAuth({ origin, config: config() }); opened.push(auth);
  auth.attachStore(new TeamUserTable(join(dir, "data.db")));
  return auth;
}
const req = (method: string, cookie?: string): IncomingMessage => ({ method, headers: { ...(cookie ? { cookie } : {}) }, socket: { remoteAddress: "127.0.0.1" } } as IncomingMessage);
/** A session as a SAML sign-in makes it: the account, and the role the identity provider's groups gave it for this session. */
function samlSession(auth: TeamAuth, userId: string, sessionRole?: string): string {
  const made = (auth as unknown as { issueSession(id: string, role?: string): { setCookie: string } }).issueSession(userId, sessionRole);
  return made.setCookie.split(";")[0]!;
}
async function ownerCookie(auth: TeamAuth): Promise<string> { return (await auth.login({ userId: "owner", password: "test-only-password" }, "owner")).setCookie.split(";")[0]!; }

const NOT_OWNER: Array<[string, string, string | undefined]> = [
  ["a custom role with settings.write", "lead", undefined],
  ["a custom role with settings.write and users.manage", "adminlite", undefined],
  ["a viewer given the ops-lead role by a SAML group", "viewer", "ops-lead"],
  ["a viewer given the admin-lite role by a SAML group", "viewer", "admin-lite"],
];

describe.each([["licensed with rbac", ["rbac", "saml", "scim"]], ["without a license", []]] as const)("owner-only routes, %s", (_label, features) => {
  beforeEach(() => { if (features.length) restore = applyTestLicense([...features]); });

  it.each(NOT_OWNER)("never gives %s the owner role", (_name, userId, sessionRole) => {
    const auth = start();
    const identity = auth.resolveSession(req("GET", samlSession(auth, userId, sessionRole)))!;
    expect(identity.role).not.toBe("owner");
    expect(auth.resolveSession(req("GET", samlSession(auth, "owner")))!.role).toBe("owner");
  });

  it.each(NOT_OWNER)("%s: findings API keys cannot be listed, created or revoked", async (_name, userId, sessionRole) => {
    const auth = start();
    const store = new FindingsAccessTokenStore({ workspaceId: "owner-only", stateDir: join(dir, "keys") });
    const made = store.create({ name: "ci" }, "owner").credential.id;
    const cookie = samlSession(auth, userId, sessionRole);
    const call = (method: string, path: string, body?: unknown) => handleFindingsAccessTokenRequest(req(method, cookie), new URL(path, origin), auth, store, async () => body);
    await expect(call("GET", "/api/findings-access")).rejects.toMatchObject({ statusCode: 403 });
    await expect(call("POST", "/api/findings-access", { name: "mine" })).rejects.toMatchObject({ statusCode: 403 });
    await expect(call("DELETE", `/api/findings-access/${made}`)).rejects.toMatchObject({ statusCode: 403 });
    expect(store.list()).toHaveLength(1); expect(store.list()[0]!.revokedAt).toBeNull();
    // The owner can.
    const ownerCall = async (method: string, path: string) => handleFindingsAccessTokenRequest(req(method, await ownerCookie(auth)), new URL(path, origin), auth, store, async () => undefined);
    expect((await ownerCall("GET", "/api/findings-access"))!.status).toBe(200);
  });

  it.each(NOT_OWNER)("%s: operator routes that need the owner are refused", (_name, userId, sessionRole) => {
    const auth = start();
    const who = auth.resolveSession(req("GET", samlSession(auth, userId, sessionRole)))!;
    for (const [method, path] of [["PATCH", "/api/console/settings"], ["POST", "/api/console/connections"], ["POST", "/api/console/extensions/install"], ["POST", "/api/console/update/apply"], ["POST", "/api/console/github/connect"], ["PUT", "/api/console/instructions/global"]] as const) {
      expect(privilegedRouteDenial(path, method, { engineRequest: false, teamEnabled: true, role: who.role }), `${method} ${path}`).toMatchObject({ status: 403 });
    }
    expect(privilegedRouteDenial("/api/console/settings", "PATCH", { engineRequest: false, teamEnabled: true, role: "owner" })).toBeNull();
  });

  it("an account without users.manage cannot make SCIM tokens or change roles or add accounts, whatever else it holds", async () => {
    const auth = start();
    const call = (cookie: string, method: string, path: string, body?: unknown) => handleTeamRequest(req(method, cookie), new URL(`/api/team/${path}`, origin), auth, {} as never, {} as never, async () => body);
    const lead = samlSession(auth, "lead"); const viewerAsLead = samlSession(auth, "viewer", "ops-lead");
    for (const cookie of [lead, viewerAsLead]) {
      await expect(call(cookie, "POST", "scim-tokens", { name: "x" })).rejects.toMatchObject({ statusCode: 403 });
      await expect(call(cookie, "GET", "scim-tokens")).rejects.toMatchObject({ statusCode: 403 });
      await expect(call(cookie, "DELETE", "scim-tokens/00000000-0000-0000-0000-000000000000")).rejects.toMatchObject({ statusCode: 403 });
      await expect(call(cookie, "PATCH", "users/viewer", { role: "owner" })).rejects.toMatchObject({ statusCode: 403 });
    }
    expect(auth.lookupUser("viewer")?.roleName).toBe("viewer");
    const service = new TeamSetupService({ workspacePath: dir, stateRoot: dir, origin: () => origin, currentAuth: () => auth, activate: async () => undefined });
    await expect(handleTeamSetupRequest({ method: "POST", headers: { cookie: lead } }, new URL("/api/team/users", origin), service, async () => ({ userId: "new", displayName: "New", password: "a-long-enough-password", role: "viewer" }))).rejects.toMatchObject({ statusCode: 403 });
  });

  it("an account that holds users.manage but is not owner is still not the owner for the owner-only handlers", async () => {
    const auth = start();
    const store = new FindingsAccessTokenStore({ workspaceId: "owner-only", stateDir: join(dir, "keys2") });
    const cookie = samlSession(auth, "adminlite");
    await expect(handleFindingsAccessTokenRequest(req("GET", cookie), new URL("/api/findings-access", origin), auth, store, async () => undefined)).rejects.toMatchObject({ statusCode: 403 });
  });
});

describe("the permission table is the only decision for a licensed role", () => {
  it("lets ops-lead call what its permissions name and nothing the table refuses", () => {
    restore = applyTestLicense(["rbac"]);
    const auth = start();
    const cookie = samlSession(auth, "viewer", "ops-lead");
    const allowed = (method: string, path: string) => { try { authorizeTeamApi(auth, req(method, cookie), path); return true; } catch { return false; } };
    expect(allowed("PATCH", "/api/console/settings")).toBe(true); // settings.write
    expect(allowed("POST", "/api/console/sessions")).toBe(true); // threads.run
    expect(allowed("GET", "/api/console/audit-log")).toBe(false); // no audit.read
    expect(allowed("GET", "/api/brand-new-route")).toBe(false); // no rule
  });
});
