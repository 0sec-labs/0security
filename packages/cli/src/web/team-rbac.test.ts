import type { IncomingMessage } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TeamUserTable, closeAuditLog, listAudit } from "@0/engine/storage";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { TeamAuth, hashTeamPassword, type TeamConfig } from "./team-auth.js";
import { authorizeTeamApi, handleTeamRequest } from "./team-web.js";
import { handleAuditLogRequest, configureAudit } from "./audit.js";
import { scopeDashboardBody, scopeFilterFor } from "./findings-scope.js";
import { applyTestLicense, makeTestLicense } from "./__fixtures__/test-license.js";
import type { CollaborationService } from "./collaboration.js";
import type { ConsoleGateway } from "./console-gateway.js";

const origin = "http://127.0.0.1:48123";
let dir: string; let hash: string; let restore: (() => void) | undefined;
const opened: TeamAuth[] = [];
beforeAll(async () => { hash = await hashTeamPassword("test-only-password"); });
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "0-team-rbac-")); });
afterEach(() => { restore?.(); restore = undefined; for (const auth of opened.splice(0)) auth.closeStore(); closeAuditLog(); configureAudit(null); rmSync(dir, { recursive: true, force: true }); });

function config(extra: Partial<TeamConfig> = {}, roles: string[] = ["owner", "editor", "viewer", "triager", "auditor", "payments-lead", "legacy-power"]): TeamConfig {
  return {
    workspace: { id: "rbac-team", name: "RBAC" },
    users: roles.map(role => ({ id: role, name: role, role, passwordHash: hash })),
    roles: {
      "payments-lead": { permissions: ["workspace.read", "findings.read", "findings.triage"], scope: { businessUnits: ["payments"] } },
      "legacy-power": { permissions: ["workspace.read", "findings.read", "settings.write", "users.manage"] },
    },
    businessUnits: { payments: ["acme/pay-*"] },
    ...extra,
  };
}
function start(cfg: TeamConfig = config()) {
  const auth = new TeamAuth({ origin, config: cfg }); opened.push(auth);
  auth.attachStore(new TeamUserTable(join(dir, "data.db")));
  return auth;
}
function req(method: string, cookie?: string): IncomingMessage { return { method, headers: { ...(cookie ? { cookie } : {}) }, socket: { remoteAddress: "127.0.0.1" } } as IncomingMessage; }
async function cookiesFor(auth: TeamAuth, ids: string[]): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const id of ids) out[id] = (await auth.login({ userId: id, password: "test-only-password" }, id)).setCookie.split(";")[0]!;
  return out;
}
function decision(auth: TeamAuth, cookie: string, method: string, path: string): "allow" | number {
  try { authorizeTeamApi(auth, req(method, cookie), path); return "allow"; } catch (error) { return (error as { statusCode: number }).statusCode; }
}

// Routes the three-role table in team-web.ts has an opinion about, plus neighbours. The audit log is judged by its handler.
const SAMPLE_ROUTES: Array<[string, string]> = [
  ["GET", "/api/dashboard"], ["GET", "/api/scans"], ["GET", "/api/scans/s1"], ["GET", "/api/scans/s1/findings"], ["GET", "/api/events/recent"],
  ["GET", "/api/finding-family/abc"], ["POST", "/api/finding-family/abc/triage"], ["POST", "/api/finding-family/abc/workflow"],
  ["GET", "/api/findings/export"], ["POST", "/api/findings/f1/impact-assessment"], ["DELETE", "/api/findings/f1/impact-assessment"],
  ["GET", "/api/work"], ["GET", "/api/work/w1"], ["POST", "/api/work"],
  ["GET", "/api/skills"], ["POST", "/api/skills"], ["DELETE", "/api/skills/x"], ["POST", "/api/skills/mounts"], ["DELETE", "/api/skills/mounts/m"],
  ["GET", "/api/engagements"], ["POST", "/api/engagements"], ["POST", "/api/engagements/e1/report"],
  ["GET", "/api/workers/hosts"], ["POST", "/api/workers/deploy"], ["POST", "/api/workers/w/stop"], ["POST", "/api/control/reset-database"], ["POST", "/api/control/repair-worker"],
  ["POST", "/api/workflow-engine/call"], ["GET", "/api/backends"], ["POST", "/api/backends"], ["GET", "/api/backends/local/proxy/api/dashboard"], ["POST", "/api/backends/local/proxy/api/x"],
  ["GET", "/api/findings-access"], ["POST", "/api/findings-access"], ["DELETE", "/api/findings-access/00000000-0000-0000-0000-000000000000"],
  ["GET", "/api/console/sessions"], ["POST", "/api/console/sessions"], ["DELETE", "/api/console/sessions/s1"], ["POST", "/api/console/sessions/s1/messages"],
  ["GET", "/api/console/saved"], ["POST", "/api/console/saved/s1/resume"], ["POST", "/api/console/saved/s1/archive"], ["DELETE", "/api/console/saved/s1"],
  ["GET", "/api/console/workflow-definitions"], ["POST", "/api/console/workflow-definitions"], ["POST", "/api/console/workflow-definitions/w1/run"],
  ["GET", "/api/console/workflow-executions/x"], ["POST", "/api/console/workflow-triggers"],
  ["GET", "/api/console/sentinels"], ["POST", "/api/console/sentinels"], ["PATCH", "/api/console/sentinels/s1"], ["GET", "/api/console/sentinel-presets"],
  ["GET", "/api/console/settings"], ["PATCH", "/api/console/settings"], ["POST", "/api/console/settings/reset"],
  ["GET", "/api/console/connections"], ["POST", "/api/console/connections"], ["PATCH", "/api/console/connections/c1"],
  ["GET", "/api/console/models"], ["PATCH", "/api/console/models/preference"], ["GET", "/api/console/providers"], ["POST", "/api/console/providers/p/device-auth"],
  ["GET", "/api/console/extensions"], ["POST", "/api/console/extensions/install"], ["POST", "/api/console/extensions/connectors/github/connect"],
  ["GET", "/api/console/github"], ["POST", "/api/console/github/connect"], ["POST", "/api/console/github/webhook/secret"],
  ["GET", "/api/console/skills/catalog"], ["POST", "/api/console/skills/catalog/install"], ["POST", "/api/console/skills/catalog/remove"],
  ["GET", "/api/console/project"], ["POST", "/api/console/project/choose-directory"], ["POST", "/api/console/project/directories"],
  ["GET", "/api/console/checks"], ["POST", "/api/console/checks"], ["GET", "/api/console/doctor"], ["GET", "/api/console/tools"], ["GET", "/api/console/execution"],
  ["GET", "/api/console/instructions/global"], ["PUT", "/api/console/instructions/global"], ["POST", "/api/console/self-edit/start"], ["POST", "/api/console/update/apply"],
  ["GET", "/api/console/update-status"], ["POST", "/api/console/diagnostics/report"], ["POST", "/api/console/feedback"], ["GET", "/api/console/repositories"],
  ["POST", "/api/console/remote-sessions"], ["POST", "/api/console/provider-relays/x"], ["GET", "/api/console/search"],
];

describe("permission table matches the three fixed roles", () => {
  it("decides every sample route the same way the regex table does", async () => {
    const free = start();
    const cookies = await cookiesFor(free, ["owner", "editor", "viewer"]);
    const before = new Map<string, "allow" | number>();
    for (const role of ["owner", "editor", "viewer"]) for (const [method, path] of SAMPLE_ROUTES) before.set(`${role} ${method} ${path}`, decision(free, cookies[role]!, method, path));
    restore = applyTestLicense(["rbac"]);
    const different: string[] = [];
    for (const role of ["owner", "editor", "viewer"]) for (const [method, path] of SAMPLE_ROUTES) {
      const key = `${role} ${method} ${path}`; const now = decision(free, cookies[role]!, method, path);
      if (now !== before.get(key)) different.push(`${key}: regex ${String(before.get(key))}, table ${String(now)}`);
    }
    expect(different).toEqual([]);
    // The sample is not trivially all-allow or all-deny.
    expect([...before.values()].filter(value => value === "allow").length).toBeGreaterThan(60);
    expect([...before.values()].filter(value => value === 403).length).toBeGreaterThan(60);
  });

  it("keeps the audit log owner-only for the three fixed roles", async () => {
    const free = start(); restore = applyTestLicense(["rbac"]);
    const identities = await Promise.all(["owner", "editor", "viewer"].map(async id => { const c = await cookiesFor(free, [id]); return free.resolveSession(req("GET", c[id])!)!; }));
    const status = identities.map(user => handleAuditLogRequest("audit-log", "GET", new URLSearchParams(), { teamEnabled: true, role: user.role, permissions: user.permissions })!.status);
    expect(status).toEqual([200, 403, 403]);
  });
});

describe("licensed roles", () => {
  it("lets a triager triage but not run threads, and an auditor read findings and the audit log only", async () => {
    restore = applyTestLicense(["rbac"]);
    const auth = start(); const c = await cookiesFor(auth, ["triager", "auditor", "viewer"]);
    expect(decision(auth, c.triager!, "POST", "/api/finding-family/x/triage")).toBe("allow");
    expect(decision(auth, c.triager!, "POST", "/api/console/sessions")).toBe(403);
    expect(decision(auth, c.triager!, "GET", "/api/console/sessions")).toBe("allow");
    expect(decision(auth, c.viewer!, "POST", "/api/finding-family/x/triage")).toBe(403);
    expect(decision(auth, c.auditor!, "GET", "/api/dashboard")).toBe("allow");
    expect(decision(auth, c.auditor!, "GET", "/api/console/audit-log")).toBe("allow");
    for (const [method, path] of [["GET", "/api/console/sessions"], ["GET", "/api/console/settings"], ["POST", "/api/finding-family/x/triage"], ["POST", "/api/console/sessions"], ["GET", "/api/skills"]] as const) expect(decision(auth, c.auditor!, method, path), `${method} ${path}`).toBe(403);
    const auditor = auth.resolveSession(req("GET", c.auditor))!;
    expect(handleAuditLogRequest("audit-log", "GET", new URLSearchParams(), { teamEnabled: true, role: auditor.role, permissions: auditor.permissions })!.status).toBe(200);
    expect(handleAuditLogRequest("audit-log", "GET", new URLSearchParams(), { teamEnabled: true, role: "viewer", permissions: auth.resolveSession(req("GET", c.viewer))!.permissions })!.status).toBe(403);
  });

  it("refuses a route that has no permission rule, for every role including the owner", async () => {
    restore = applyTestLicense(["rbac"]);
    const auth = start(); const c = await cookiesFor(auth, ["owner"]);
    expect(decision(auth, c.owner!, "GET", "/api/brand-new-route")).toBe(403);
    expect(decision(auth, c.owner!, "POST", "/api/console/brand-new-area")).toBe(403);
    expect(() => authorizeTeamApi(auth, req("GET", c.owner), "/api/brand-new-route")).toThrow("no permission rule");
  });

  it("applies a custom role and its business-unit scope", async () => {
    restore = applyTestLicense(["rbac"]);
    const auth = start(); const c = await cookiesFor(auth, ["payments-lead"]);
    const identity = auth.resolveSession(req("GET", c["payments-lead"]))!;
    expect(identity).toMatchObject({ roleName: "payments-lead", role: "viewer", scope: ["acme/pay-*"] });
    expect(decision(auth, c["payments-lead"]!, "POST", "/api/finding-family/x/triage")).toBe("allow");
    expect(decision(auth, c["payments-lead"]!, "PATCH", "/api/console/settings")).toBe(403);
    const filter = scopeFilterFor(identity)!;
    expect(filter("https://github.com/acme/pay-api")).toBe(true);
    expect(filter("https://github.com/acme/web")).toBe(false);
    const body = scopeDashboardBody({
      scans: [{ id: "a", target: "https://github.com/acme/pay-api" }, { id: "b", target: "https://github.com/acme/web" }],
      cases: [{ target: "https://github.com/acme/pay-api" }, { target: "https://github.com/acme/web" }],
      groups: [{ latest: { scanId: "a" } }, { latest: { scanId: "b" } }, { latest: {} }], workers: [1, 2],
    }, filter);
    // A family that also occurs in a scan outside the scope is hidden: its counts and scan ids would reveal that scan.
    const mixed = scopeDashboardBody({
      scans: [{ id: "a", target: "https://github.com/acme/pay-api" }, { id: "b", target: "https://github.com/acme/web" }], cases: [],
      groups: [{ latest: { scanId: "a" }, sourceScanIds: ["a"] }, { latest: { scanId: "a" }, sourceScanIds: ["a", "b"] }, { latest: { scanId: "a" }, sourceScanIds: ["a", "older-unknown"] }], workers: [],
    }, filter);
    expect(mixed.groups).toHaveLength(1);
    expect(body.scans.map(scan => scan.id)).toEqual(["a"]); expect(body.cases).toHaveLength(1); expect(body.groups).toHaveLength(1); expect(body.workers).toEqual([]);
  });

  it("rejects roles and groups that do not exist when the configuration is read", () => {
    expect(() => start(config({ roles: { owner: { permissions: [] } } }))).toThrow("built-in");
    expect(() => start(config({ users: [{ id: "x", name: "x", role: "nope", passwordHash: hash }] }))).toThrow("unknown role");
    expect(() => start(config({ oidc: { issuer: "https://idp.example", clientId: "c", redirectUri: `${origin}/api/team/auth/callback`, groupRoles: { g: "nope" } } }))).toThrow("unknown role");
  });
});

describe("without a license", () => {
  it("treats other roles as the nearest of the three, never as owner, and keeps the scope", async () => {
    const auth = start(); const c = await cookiesFor(auth, ["triager", "auditor", "payments-lead", "legacy-power"]);
    const who = (id: string) => auth.resolveSession(req("GET", c[id]))!;
    expect(who("triager")).toMatchObject({ roleName: "triager", role: "viewer" });
    expect(who("auditor")).toMatchObject({ roleName: "auditor", role: "viewer" });
    expect(who("legacy-power")).toMatchObject({ roleName: "legacy-power", role: "editor" });
    expect(who("legacy-power").permissions).not.toContain("settings.write");
    expect(who("payments-lead").scope).toEqual(["acme/pay-*"]);
    expect(decision(auth, c.triager!, "POST", "/api/finding-family/x/triage")).toBe(403);
    expect(decision(auth, c["legacy-power"]!, "PATCH", "/api/console/settings")).toBe(403);
    expect(decision(auth, c.auditor!, "GET", "/api/console/sessions")).toBe("allow");
    expect(() => auth.addMember({ id: "n", name: "n", role: "triager", passwordHash: hash })).toThrow("enterprise license");
  });

  it("falls back after the grace period ends and never raises anyone", async () => {
    const day = 86_400_000; const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");
    restore = applyTestLicense(["rbac"], { issuedAt: iso(Date.now() - 100 * day), expires: iso(Date.now() - 40 * day) });
    const auth = start(); const c = await cookiesFor(auth, ["triager", "owner"]);
    expect(auth.resolveSession(req("GET", c.triager))).toMatchObject({ role: "viewer" });
    expect(decision(auth, c.triager!, "POST", "/api/finding-family/x/triage")).toBe(403);
    expect(decision(auth, c.owner!, "GET", "/api/brand-new-route")).toBe("allow");
  });

  it("keeps the table in force during the 30 days of grace", async () => {
    const day = 86_400_000; const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");
    restore = applyTestLicense(["rbac"], { issuedAt: iso(Date.now() - 100 * day), expires: iso(Date.now() - 5 * day) });
    const auth = start(); const c = await cookiesFor(auth, ["owner"]);
    expect(decision(auth, c.owner!, "GET", "/api/brand-new-route")).toBe(403);
  });

  it("is not unlocked by a license for another feature", async () => {
    restore = applyTestLicense(["scim"]);
    const auth = start(); const c = await cookiesFor(auth, ["owner"]);
    expect(decision(auth, c.owner!, "GET", "/api/brand-new-route")).toBe("allow");
  });
});

describe("role and scope changes", () => {
  const gateway = {} as ConsoleGateway; const collaboration = {} as CollaborationService;
  async function patch(auth: TeamAuth, cookie: string, user: string, body: unknown) {
    return handleTeamRequest(req("PATCH", cookie), new URL(`/api/team/users/${encodeURIComponent(user)}`, origin), auth, collaboration, gateway, async () => body);
  }

  it("lets an owner change a role, takes effect at once, and writes an audit entry", async () => {
    restore = applyTestLicense(["rbac"]);
    const dbPath = join(dir, "data.db"); configureAudit(dbPath);
    const auth = start(); const c = await cookiesFor(auth, ["owner", "viewer"]);
    expect(decision(auth, c.viewer!, "POST", "/api/finding-family/x/triage")).toBe(403);
    const reply = await patch(auth, c.owner!, "viewer", { role: "triager" });
    expect(reply).toMatchObject({ status: 200, data: { user: { userId: "viewer", role: "triager" } } });
    expect(decision(auth, c.viewer!, "POST", "/api/finding-family/x/triage")).toBe("allow");
    auth.closeStore();
    expect(start().lookupUser("viewer")?.roleName).toBe("triager");
    const events = listAudit({}, { dbPath }).events.filter(event => event.action === "user.role_changed");
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ subject: "viewer", actor: "operator owner (browser)", detail: { id: "viewer", old: "viewer", new: "triager", source: "admin" } });
  });

  it("sets and clears a scope, with audit entries", async () => {
    restore = applyTestLicense(["rbac"]);
    const dbPath = join(dir, "data.db"); configureAudit(dbPath);
    const auth = start(); const c = await cookiesFor(auth, ["owner", "triager"]);
    await patch(auth, c.owner!, "triager", { scope: { repos: ["acme/web"] } });
    expect(auth.resolveSession(req("GET", c.triager))!.scope).toEqual(["acme/web"]);
    await patch(auth, c.owner!, "triager", { scope: { businessUnits: ["payments"] } });
    expect(auth.resolveSession(req("GET", c.triager))!.scope).toEqual(["acme/pay-*"]);
    await expect(patch(auth, c.owner!, "triager", { scope: { businessUnits: ["ghost"] } })).rejects.toMatchObject({ statusCode: 400 });
    await patch(auth, c.owner!, "triager", { scope: null });
    expect(auth.resolveSession(req("GET", c.triager))!.scope).toBeNull();
    const events = listAudit({}, { dbPath }).events.filter(event => event.action === "user.scope_changed").map(event => event.detail);
    expect(events.map(detail => detail.new)).toEqual(["none", "unit:payments", "acme/web"]);
  });

  it("refuses everyone without users.manage, unknown accounts and roles, and removing the last manager", async () => {
    restore = applyTestLicense(["rbac"]);
    const auth = start(config({}, ["owner", "editor", "viewer"])); const c = await cookiesFor(auth, ["owner", "editor"]);
    await expect(patch(auth, c.editor!, "editor", { role: "owner" })).rejects.toMatchObject({ statusCode: 403 });
    await expect(patch(auth, c.owner!, "ghost", { role: "viewer" })).rejects.toMatchObject({ statusCode: 404 });
    await expect(patch(auth, c.owner!, "editor", { role: "wizard" })).rejects.toMatchObject({ statusCode: 400 });
    await expect(patch(auth, c.owner!, "editor", {})).rejects.toMatchObject({ statusCode: 400 });
    await expect(patch(auth, c.owner!, "owner", { role: "viewer" })).rejects.toMatchObject({ statusCode: 409, message: expect.stringContaining("at least one") });
    await patch(auth, c.owner!, "editor", { role: "owner" });
    await expect(patch(auth, c.owner!, "owner", { role: "viewer" })).resolves.toMatchObject({ status: 200 });
  });

  it("is a paid feature: no license, no change", async () => {
    const auth = start(); const c = await cookiesFor(auth, ["owner", "viewer"]);
    await expect(patch(auth, c.owner!, "viewer", { role: "editor" })).rejects.toMatchObject({ statusCode: 403, message: expect.stringContaining("enterprise license") });
    expect(auth.lookupUser("viewer")?.role).toBe("viewer");
  });

  it("lists roles and tells the browser whether they can be used", async () => {
    const auth = start(); const c = await cookiesFor(auth, ["viewer"]);
    const list = async () => (await handleTeamRequest(req("GET", c.viewer), new URL("/api/team/roles", origin), auth, collaboration, gateway, async () => undefined))!.data as { licensed: boolean; roles: Array<{ name: string; assignable: boolean }> };
    const free = await list();
    expect(free.licensed).toBe(false);
    expect(free.roles.filter(role => role.assignable).map(role => role.name)).toEqual(["owner", "editor", "viewer"]);
    restore = applyTestLicense(["rbac"]);
    const paid = await list();
    expect(paid.licensed).toBe(true); expect(paid.roles.every(role => role.assignable)).toBe(true);
    expect(paid.roles.map(role => role.name)).toEqual(["owner", "editor", "viewer", "triager", "auditor", "payments-lead", "legacy-power"]);
  });
});

describe("test license", () => {
  it("is signed with a throwaway key", () => {
    const one = makeTestLicense(["rbac"]); const two = makeTestLicense(["rbac"]);
    expect(Object.values(one.publicKeys)[0]).not.toBe(Object.values(two.publicKeys)[0]);
  });
});
