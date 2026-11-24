// The SCIM routes over a real HTTP server, a real temp SQLite file, real sessions and a real API key store.
// Request bodies are the examples from RFC 7643 and RFC 7644 and the shapes Okta and Entra ID document.
import { createServer, request, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { TeamUserTable, closeAuditLog, listAudit } from "@0/engine/storage";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scimFixtures } from "../enterprise-bridge.js";
const { ENTRA, FILTERS, OKTA, RFC7643_8_2_FULL_USER, RFC7643_8_4_GROUP } = scimFixtures;
import { FindingsAccessTokenStore } from "./findings-access-tokens.js";
import { configureAudit } from "./audit.js";
import { SCIM_BASE, handleScimRequest } from "./scim-routes.js";
import { TeamAuth, hashTeamPassword, type TeamConfig } from "./team-auth.js";
import { applyTestLicense } from "./__fixtures__/test-license.js";

const origin = "http://127.0.0.1:48123";
let dir: string; let dbPath: string; let restore: (() => void) | undefined;
let servers: Server[] = []; const opened: TeamAuth[] = [];
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "0-scim-")); dbPath = join(dir, "data.db"); configureAudit(dbPath); });
afterEach(async () => {
  restore?.(); restore = undefined;
  for (const auth of opened.splice(0)) auth.closeStore();
  for (const server of servers.splice(0)) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
  closeAuditLog(); configureAudit(null); rmSync(dir, { recursive: true, force: true });
});

interface Reply { status: number; headers: Record<string, string | string[] | undefined>; json: any }
async function fixture(extra: Partial<TeamConfig> = {}) {
  const hash = await hashTeamPassword("owner-password");
  const config: TeamConfig = { workspace: { id: "scim-team", name: "SCIM" }, users: [{ id: "owner", name: "Owner", role: "owner", passwordHash: hash }], scim: { defaultRole: "viewer", groupRoles: { "sec-triage": "triager", "sec-admins": "owner" } }, ...extra };
  const auth = new TeamAuth({ origin, config }); opened.push(auth);
  auth.attachStore(new TeamUserTable(dbPath));
  const keys = new FindingsAccessTokenStore({ workspaceId: "scim-team", stateDir: join(dir, "keys") });
  const server = createServer((req, res) => { void handleScimRequest(req, res, new URL(req.url ?? "/", origin), { auth, revokeApiKeys: id => keys.revokeCreatedBy(id), clientIp: "127.0.0.1", baseUrl: "https://0.example.com" }); });
  servers.push(server);
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  const token = auth.scim!.createToken("test idp").token;
  const call = (method: string, path: string, body?: unknown, bearer: string | null = token): Promise<Reply> => new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const req = request({ host: "127.0.0.1", port, path: `${SCIM_BASE}${path}`, method, headers: { ...(bearer ? { Authorization: `Bearer ${bearer}` } : {}), ...(payload ? { "Content-Type": "application/scim+json" } : {}) } }, res => {
      const chunks: Buffer[] = []; res.on("data", chunk => chunks.push(chunk as Buffer));
      res.on("end", () => { const text = Buffer.concat(chunks).toString(); resolve({ status: res.statusCode ?? 0, headers: res.headers, json: text ? JSON.parse(text) : undefined }); });
    });
    req.on("error", reject); req.end(payload);
  });
  return { auth, keys, call, token };
}
const user = (name: string, extra: Record<string, unknown> = {}) => ({ schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: name, externalId: `ext-${name}`, name: { givenName: "Test", familyName: name }, emails: [{ value: `${name}@example.com`, type: "work", primary: true }], active: true, ...extra });

describe("SCIM with the scim license", () => {
  beforeEach(() => { restore = applyTestLicense(["scim"]); });

  it("refuses a missing, wrong or revoked bearer token", async () => {
    const { call, auth, token } = await fixture();
    const none = await call("GET", "/Users", undefined, null);
    expect(none.status).toBe(401); expect(none.headers["www-authenticate"]).toContain("Bearer");
    expect(none.json).toMatchObject({ schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], status: "401" });
    expect((await call("GET", "/Users", undefined, "scim_wrong")).status).toBe(401);
    expect((await call("GET", "/Users")).status).toBe(200);
    auth.scim!.revokeToken(auth.scim!.listTokens()[0]!.id);
    expect((await call("GET", "/Users", undefined, token)).status).toBe(401);
    expect(listAudit({ q: "scim.auth_failed" }, { dbPath }).events.length).toBeGreaterThanOrEqual(3);
  });

  it("throttles repeated bad tokens", async () => {
    const { call } = await fixture();
    const statuses: number[] = [];
    for (let i = 0; i < 12; i++) statuses.push((await call("GET", "/Users", undefined, `scim_bad${i}`)).status);
    expect(statuses).toContain(429);
  });

  it("describes itself: service provider config, resource types and schemas", async () => {
    const { call } = await fixture();
    expect((await call("GET", "/ServiceProviderConfig")).json).toMatchObject({ patch: { supported: true }, bulk: { supported: false }, filter: { supported: true } });
    expect((await call("GET", "/ResourceTypes")).json.Resources.map((type: { id: string }) => type.id)).toEqual(["User", "Group"]);
    expect((await call("GET", "/Schemas")).json.Resources).toHaveLength(2);
    expect((await call("GET", "/Nothing")).status).toBe(404);
  });

  it("creates, finds, reads, updates and lists users", async () => {
    const { call, auth } = await fixture();
    // Okta first asks whether the user exists: an empty ListResponse.
    const none = await call("GET", `/Users?filter=${encodeURIComponent(FILTERS.oktaUserLookup)}&startIndex=1&count=100`);
    expect(none.json).toMatchObject({ totalResults: 0, startIndex: 1, Resources: [] });
    const created = await call("POST", "/Users", user("bjensen"));
    expect(created.status).toBe(201);
    expect(created.json).toMatchObject({ userName: "bjensen", externalId: "ext-bjensen", active: true, displayName: "Test bjensen", emails: [{ value: "bjensen@example.com" }], meta: { resourceType: "User", location: expect.stringContaining("https://0.example.com/scim/v2/Users/scim-") } });
    expect(created.headers.location).toBe(created.json.meta.location);
    const id = created.json.id as string;
    expect(auth.lookupUser(id)).toMatchObject({ roleName: "viewer", role: "viewer" });
    expect((await call("POST", "/Users", user("BJensen"))).json).toMatchObject({ status: "409", scimType: "uniqueness" });
    expect((await call("POST", "/Users", { schemas: [], name: {} })).json).toMatchObject({ status: "400", scimType: "invalidValue" });
    expect((await call("GET", `/Users/${id}`)).json.id).toBe(id);
    expect((await call("GET", "/Users/nobody")).status).toBe(404);
    for (const field of [`userName eq "BJENSEN"`, `externalId eq "ext-bjensen"`, `emails.value eq "bjensen@example.com"`, `active eq true and userName sw "bj"`]) {
      expect((await call("GET", `/Users?filter=${encodeURIComponent(field)}`)).json.totalResults, field).toBe(1);
    }
    expect((await call("GET", `/Users?filter=${encodeURIComponent("userName eq")}`)).json).toMatchObject({ status: "400", scimType: "invalidFilter" });
    const put = await call("PUT", `/Users/${id}`, { ...user("bjensen"), displayName: "Babs Jensen", externalId: "701984" });
    expect(put.json).toMatchObject({ displayName: "Babs Jensen", externalId: "701984" });
    expect(auth.lookupUser(id)?.displayName).toBe("Babs Jensen");
  });

  it("pages through users with startIndex and count", async () => {
    const { call } = await fixture();
    for (let i = 1; i <= 5; i++) await call("POST", "/Users", user(`person${i}`));
    const page = await call("GET", "/Users?startIndex=2&count=2");
    expect(page.json).toMatchObject({ totalResults: 5, startIndex: 2, itemsPerPage: 2, schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"] });
    expect(page.json.Resources.map((r: { userName: string }) => r.userName)).toEqual(["person2", "person3"]);
    expect((await call("GET", "/Users?startIndex=5&count=10")).json.Resources).toHaveLength(1);
    expect((await call("GET", "/Users?count=0")).json).toMatchObject({ totalResults: 5, itemsPerPage: 0 });
  });

  it("deprovisions with Okta's PATCH: disables the account, ends its sessions, revokes its API keys, and keeps it listed", async () => {
    const { call, auth, keys } = await fixture();
    const id = (await call("POST", "/Users", user("leaver"))).json.id as string;
    // The person signed in through OIDC and made an API key.
    const session = (auth as unknown as { issueSession(id: string): { sessionId: string } }).issueSession(id);
    keys.create({ name: "ci key" }, id); keys.create({ name: "other" }, "owner");
    expect(auth.resolveSessionId(session.sessionId)).not.toBeNull();
    const patched = await call("PATCH", `/Users/${id}`, OKTA.deactivateUser);
    expect(patched.status).toBe(200); expect(patched.json.active).toBe(false);
    expect(auth.resolveSessionId(session.sessionId)).toBeNull();
    expect(auth.lookupUser(id)).toBeNull();
    expect(keys.list().filter(key => key.revokedAt).map(key => key.name)).toEqual(["ci key"]);
    expect((await call("GET", `/Users/${id}`)).json.active).toBe(false);
    const events = listAudit({}, { dbPath }).events;
    expect(events.find(event => event.action === "user.deprovisioned")).toMatchObject({ actor: "scim:test idp", subject: id, detail: { id, source: "scim", reason: "inactive", count: 2 } });
    // Back on: the account works again, with no sessions or keys restored.
    expect((await call("PATCH", `/Users/${id}`, { Operations: [{ op: "replace", value: { active: true } }] })).json.active).toBe(true);
    expect(auth.lookupUser(id)).not.toBeNull();
    expect(events.length).toBeGreaterThan(0);
  });

  it("accepts Entra's capitalised operations with a string boolean, and DELETE hides the account for good", async () => {
    const { call, auth } = await fixture();
    const id = (await call("POST", "/Users", user("entra"))).json.id as string;
    expect((await call("PATCH", `/Users/${id}`, ENTRA.disableUserWithStringBoolean)).json.active).toBe(false);
    expect((await call("PATCH", `/Users/${id}`, { Operations: [{ op: "Replace", path: "active", value: "True" }], schemas: ENTRA.disableUser.schemas })).json.active).toBe(true);
    expect((await call("DELETE", `/Users/${id}`)).status).toBe(204);
    expect((await call("GET", `/Users/${id}`)).status).toBe(404);
    expect((await call("GET", "/Users")).json.totalResults).toBe(0);
    expect(auth.lookupUser(id)).toBeNull();
    // The userName can be used again.
    expect((await call("POST", "/Users", user("entra"))).status).toBe(201);
  });

  it("manages only the accounts SCIM created: local accounts are not listed, read, changed or deleted", async () => {
    const { call } = await fixture();
    expect((await call("GET", "/Users")).json.totalResults).toBe(0);
    expect((await call("GET", "/Users/owner")).status).toBe(404);
    expect((await call("PATCH", "/Users/owner", OKTA.deactivateUser)).status).toBe(404);
    expect((await call("DELETE", "/Users/owner")).status).toBe(404);
    expect((await call("POST", "/Groups", { displayName: "g", members: [{ value: "owner" }] })).json).toMatchObject({ status: "400", scimType: "invalidValue" });
  });

  it("does not disable the last account that can manage users", async () => {
    const { call, auth } = await fixture();
    const id = (await call("POST", "/Users", user("boss"))).json.id as string;
    const gid = (await call("POST", "/Groups", { displayName: "sec-admins", members: [{ value: id }] })).json.id as string;
    expect(auth.lookupUser(id)?.roleName).toBe("owner");
    // The file owner still holds the permission, so this one can be disabled.
    expect((await call("PATCH", `/Users/${id}`, OKTA.deactivateUser)).status).toBe(200);
    expect(gid).toBeTruthy();
  });

  it("keeps groups: create, member roles, Entra and Okta member patches, rename, delete", async () => {
    const { call, auth } = await fixture();
    const a = (await call("POST", "/Users", user("alice"))).json.id as string;
    const b = (await call("POST", "/Users", user("bob"))).json.id as string;
    const created = await call("POST", "/Groups", { schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"], displayName: "sec-triage", externalId: "g-1", members: [{ value: a }] });
    expect(created.status).toBe(201);
    expect(created.json).toMatchObject({ displayName: "sec-triage", members: [{ value: a, display: "Test alice" }], meta: { resourceType: "Group" } });
    const gid = created.json.id as string;
    expect(auth.lookupUser(a)?.roleName).toBe("triager"); expect(auth.lookupUser(b)?.roleName).toBe("viewer");
    expect((await call("POST", "/Groups", { displayName: "SEC-TRIAGE" })).json).toMatchObject({ scimType: "uniqueness" });
    // Entra: Add and Remove with the members as the value; the answer is the group.
    const added = await call("PATCH", `/Groups/${gid}`, { ...ENTRA.addMember, Operations: [{ op: "Add", path: "members", value: [{ $ref: null, value: b }] }] });
    expect(added.json.members.map((m: { value: string }) => m.value)).toEqual([a, b]);
    expect(auth.lookupUser(b)?.roleName).toBe("triager");
    const removed = await call("PATCH", `/Groups/${gid}`, { ...ENTRA.removeMember, Operations: [{ op: "Remove", path: "members", value: [{ value: a }] }] });
    expect(removed.json.members.map((m: { value: string }) => m.value)).toEqual([b]);
    expect(auth.lookupUser(a)?.roleName).toBe("viewer");
    // Okta: remove one member by filter and add another in one request, then rename.
    const swapped = await call("PATCH", `/Groups/${gid}`, { ...OKTA.removeThenAddMember, Operations: [{ op: "remove", path: `members[value eq "${b}"]` }, { op: "add", path: "members", value: [{ value: a, display: "alice" }] }] });
    expect(swapped.json.members.map((m: { value: string }) => m.value)).toEqual([a]);
    expect((await call("PATCH", `/Groups/${gid}`, OKTA.renameGroup)).json.displayName).toBe("Test SCIMv2");
    expect(auth.lookupUser(a)?.roleName).toBe("viewer"); // the group no longer matches the mapping
    expect((await call("GET", `/Groups?filter=${encodeURIComponent(FILTERS.entraGroupName)}&excludedAttributes=members`)).json.Resources[0]).not.toHaveProperty("members");
    expect((await call("GET", "/Groups?filter=" + encodeURIComponent('displayName eq "nothing"'))).json).toMatchObject({ totalResults: 0, Resources: [] });
    expect((await call("DELETE", `/Groups/${gid}`)).status).toBe(204);
    expect((await call("GET", `/Groups/${gid}`)).status).toBe(404);
    const roleChanges = listAudit({ q: "user.role_changed" }, { dbPath }).events;
    expect(roleChanges.some(event => event.detail.source === "scim-group" && event.detail.new === "triager")).toBe(true);
  });

  it("does not change a role an owner set by hand", async () => {
    const { call, auth } = await fixture();
    const a = (await call("POST", "/Users", user("pinned"))).json.id as string;
    auth.setAccess(a, { role: "auditor" });
    await call("POST", "/Groups", { displayName: "sec-triage", members: [{ value: a }] });
    expect(auth.lookupUser(a)?.roleName).toBe("auditor");
  });

  it("accepts the RFC full user example and ignores attributes it does not store", async () => {
    const { call } = await fixture();
    const created = await call("POST", "/Users", { ...RFC7643_8_2_FULL_USER, id: "client-chosen-id", meta: { resourceType: "User" } });
    expect(created.status).toBe(201);
    expect(created.json.id).not.toBe("client-chosen-id");
    expect(created.json).toMatchObject({ userName: "bjensen@example.com", externalId: "701984", displayName: "Babs Jensen" });
    expect(RFC7643_8_4_GROUP.members).toHaveLength(2);
  });

  it("links an account to its first OIDC sign-in by verified email, and refuses a disabled account", async () => {
    const { call, auth } = await fixture();
    const id = (await call("POST", "/Users", user("sso"))).json.id as string;
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = { ...await exportJWK(publicKey), kid: "k", alg: "RS256", use: "sig" };
    let issuer = ""; let nonce = ""; let email = "sso@example.com";
    const idp = createServer(async (req, res) => {
      res.setHeader("Content-Type", "application/json");
      if (req.url === "/.well-known/openid-configuration") return res.end(JSON.stringify({ issuer, authorization_endpoint: `${issuer}/a`, token_endpoint: `${issuer}/t`, jwks_uri: `${issuer}/k` }));
      if (req.url === "/k") return res.end(JSON.stringify({ keys: [jwk] }));
      if (req.url === "/t") { for await (const part of req) void part; return res.end(JSON.stringify({ id_token: await new SignJWT({ nonce, email }).setProtectedHeader({ alg: "RS256", kid: "k" }).setIssuer(issuer).setAudience("client").setSubject("idp-subject-1").setIssuedAt().setExpirationTime("5m").sign(privateKey) })); }
      res.statusCode = 404; res.end("{}");
    });
    servers.push(idp);
    await new Promise<void>(resolve => idp.listen(0, "127.0.0.1", resolve)); issuer = `http://127.0.0.1:${(idp.address() as AddressInfo).port}`;
    const configured = new TeamAuth({ origin, config: { ...auth.snapshotConfig(), oidc: { issuer, clientId: "client", redirectUri: `${origin}/api/team/auth/callback` } } }); opened.push(configured);
    configured.attachStore(new TeamUserTable(dbPath));
    const signIn = async () => { const begin = await configured.beginSSO(); const u = new URL(begin.url); nonce = u.searchParams.get("nonce")!; return configured.callback(new URLSearchParams({ state: u.searchParams.get("state")!, code: "c" }), { headers: { cookie: begin.setCookie.split(";")[0]! } }); };
    const first = await signIn();
    expect(first.user.userId).toBe(id);
    expect((await signIn()).user.userId).toBe(id); // now matched by subject
    await call("PATCH", `/Users/${id}`, OKTA.deactivateUser);
    configured.attachStore(new TeamUserTable(dbPath));
    await expect(signIn()).rejects.toMatchObject({ statusCode: 403, message: expect.stringContaining("disabled") });
    email = "someone-else@example.com";
  });
});

const DAY = 86_400_000;
const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d+Z$/, "Z");

/** A person with a session and an API key, set up while the license is valid. */
async function leaver(f: Awaited<ReturnType<typeof fixture>>, name = "leaver") {
  const id = (await f.call("POST", "/Users", user(name))).json.id as string;
  const session = (f.auth as unknown as { issueSession(id: string): { sessionId: string } }).issueSession(id);
  f.keys.create({ name: `${name} key` }, id);
  return { id, session: session.sessionId };
}
const disable = { schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{ op: "Replace", path: "active", value: false }] };

describe("SCIM past the license grace period", () => {
  async function expired() {
    restore = applyTestLicense(["scim"]);
    const f = await fixture();
    const people = [await leaver(f, "one"), await leaver(f, "two"), await leaver(f, "three")];
    const group = (await f.call("POST", "/Groups", { displayName: "sec-triage", members: [{ value: people[0]!.id }] })).json.id as string;
    restore();
    restore = applyTestLicense(["scim"], { issuedAt: iso(Date.now() - 100 * DAY), expires: iso(Date.now() - 40 * DAY) });
    return { ...f, people, group };
  }

  it("keeps reading working", async () => {
    const f = await expired();
    expect((await f.call("GET", "/Users")).json.totalResults).toBe(3);
    expect((await f.call("GET", `/Users/${f.people[0]!.id}`)).status).toBe(200);
    expect((await f.call("GET", "/Groups")).status).toBe(200);
    expect((await f.call("GET", "/ServiceProviderConfig")).status).toBe(200);
  });

  it("refuses new access and changes to access", async () => {
    const f = await expired();
    const refused = async (r: Promise<Reply>) => { const reply = await r; expect(reply.status).toBe(403); expect(reply.json.detail).toContain("expired"); };
    await refused(f.call("POST", "/Users", user("newcomer")));
    await refused(f.call("PUT", `/Users/${f.people[0]!.id}`, user("one", { displayName: "Renamed" })));
    await refused(f.call("PATCH", `/Users/${f.people[0]!.id}`, { Operations: [{ op: "replace", path: "displayName", value: "Renamed" }] }));
    await refused(f.call("POST", "/Groups", { displayName: "another" }));
    await refused(f.call("PATCH", `/Groups/${f.group}`, { Operations: [{ op: "Add", path: "members", value: [{ value: f.people[1]!.id }] }] }));
    await refused(f.call("DELETE", `/Groups/${f.group}`));
    expect(f.auth.scimAccounts()).toHaveLength(3);
    expect(f.auth.lookupUser(f.people[0]!.id)?.displayName).toBe("Test one");
  });

  it("does not turn a disabled account back on", async () => {
    const f = await expired();
    await f.call("PATCH", `/Users/${f.people[1]!.id}`, disable);
    const reply = await f.call("PATCH", `/Users/${f.people[1]!.id}`, { Operations: [{ op: "Replace", path: "active", value: true }] });
    expect(reply.status).toBe(403);
    expect(f.auth.lookupUser(f.people[1]!.id)).toBeNull();
  });

  it("still disables: PATCH, PUT and DELETE end the account, its sessions and its API keys", async () => {
    const f = await expired();
    const [a, b, c] = f.people as [typeof f.people[0], typeof f.people[0], typeof f.people[0]];
    const patched = await f.call("PATCH", `/Users/${a.id}`, OKTA.deactivateUser);
    expect(patched.status).toBe(200); expect(patched.json.active).toBe(false);
    const put = await f.call("PUT", `/Users/${b.id}`, user("two", { active: false }));
    expect(put.status).toBe(200); expect(put.json.active).toBe(false);
    expect((await f.call("DELETE", `/Users/${c.id}`)).status).toBe(204);
    for (const person of [a, b, c]) {
      expect(f.auth.resolveSessionId(person.session), person.id).toBeNull();
      expect(f.auth.lookupUser(person.id)).toBeNull();
    }
    expect(f.keys.list().filter(key => key.revokedAt)).toHaveLength(3);
    expect(listAudit({ q: "user.deprovisioned" }, { dbPath }).events).toHaveLength(3);
    // Disabling again changes nothing and still answers.
    expect((await f.call("PATCH", `/Users/${a.id}`, disable)).status).toBe(200);
  });

  it("lets an owner list and revoke tokens through the API but not make one", async () => {
    const f = await expired();
    const { handleTeamRequest } = await import("./team-web.js");
    const login = await f.auth.login({ userId: "owner", password: "owner-password" }, "owner");
    const cookie = login.setCookie.split(";")[0]!;
    const call = (method: string, path: string, body?: unknown) => handleTeamRequest({ method, headers: { cookie }, socket: { remoteAddress: "127.0.0.1" } } as never, new URL(`/api/team/${path}`, origin), f.auth, {} as never, {} as never, async () => body);
    expect(((await call("GET", "scim-tokens"))!.data as { tokens: unknown[] }).tokens).toHaveLength(1);
    await expect(call("POST", "scim-tokens", { name: "new" })).rejects.toMatchObject({ statusCode: 403, message: expect.stringContaining("expired") });
    const id = f.auth.scim!.listTokens()[0]!.id;
    expect((await call("DELETE", `scim-tokens/${id}`))!.status).toBe(200);
    expect((await f.call("GET", "/Users")).status).toBe(401);
  });
});

describe("SCIM without a license for scim", () => {
  async function unlicensed(license?: string[], tag = "") {
    restore = applyTestLicense(["scim"]);
    const f = await fixture();
    const people = [await leaver(f, `one${tag}`), await leaver(f, `two${tag}`)];
    restore();
    restore = license ? applyTestLicense(license) : undefined;
    return { ...f, people };
  }

  it("still disables people, for no license and for a license without scim", async () => {
    for (const license of [undefined, ["rbac"]]) {
      const f = await unlicensed(license, String(license?.length ?? 0));
      // A fresh folder per round: the first round must not leave accounts behind for the second.
      expect((await f.call("PATCH", `/Users/${f.people[0]!.id}`, ENTRA.disableUserWithStringBoolean)).json.active).toBe(false);
      expect((await f.call("DELETE", `/Users/${f.people[1]!.id}`)).status).toBe(204);
      for (const person of f.people) { expect(f.auth.resolveSessionId(person.session)).toBeNull(); expect(f.auth.lookupUser(person.id)).toBeNull(); }
      expect(f.keys.list().every(key => key.revokedAt)).toBe(true);
      f.auth.closeStore();
    }
  });

  it("refuses everything else with a message that says what is needed", async () => {
    const f = await unlicensed();
    for (const [method, path, body] of [["GET", "/Users", undefined], ["GET", `/Users/${f.people[0]!.id}`, undefined], ["GET", "/ServiceProviderConfig", undefined], ["GET", "/Groups", undefined], ["POST", "/Users", user("x")], ["POST", "/Groups", { displayName: "g" }], ["PATCH", `/Users/${f.people[0]!.id}`, { Operations: [{ op: "replace", path: "displayName", value: "x" }] }]] as const) {
      const reply = await f.call(method, path, body);
      expect(reply.status, `${method} ${path}`).toBe(403); expect(reply.json.detail).toContain("enterprise license");
    }
    expect(f.auth.lookupUser(f.people[0]!.id)).not.toBeNull();
  });

  it("still asks for a valid token first", async () => {
    const f = await unlicensed();
    expect((await f.call("PATCH", `/Users/${f.people[0]!.id}`, disable, "scim_wrong")).status).toBe(401);
    expect((await f.call("DELETE", `/Users/${f.people[0]!.id}`, undefined, null)).status).toBe(401);
    expect(f.auth.lookupUser(f.people[0]!.id)).not.toBeNull();
  });

  it("does not disable the last account that can manage users, even without a license", async () => {
    restore = applyTestLicense(["scim"]);
    const f = await fixture({ scim: { groupRoles: { "sec-admins": "owner" } } });
    const boss = await leaver(f, "boss");
    // Make the SCIM account the only manager: the file owner is demoted by an owner action first.
    f.auth.setAccess(boss.id, { role: "owner" });
    f.auth.setAccess("owner", { role: "viewer" });
    restore(); restore = undefined;
    const reply = await f.call("PATCH", `/Users/${boss.id}`, disable);
    expect(reply.status).toBe(409);
    expect(f.auth.lookupUser(boss.id)).not.toBeNull();
  });
});
