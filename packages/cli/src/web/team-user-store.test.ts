import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { TeamUserTable } from "@0/engine/storage";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { FREE_MEMBER_LIMIT, TeamAuth, hashTeamPassword, type TeamConfig } from "./team-auth.js";
import { applyTestLicense } from "./__fixtures__/test-license.js";

const origin = "http://127.0.0.1:48123";
let dir: string; let dbPath: string; let hash: string;
const opened: TeamAuth[] = [];
beforeAll(async () => { hash = await hashTeamPassword("correct horse battery"); });
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "0-team-store-")); dbPath = join(dir, "data.db"); });
afterEach(async () => {
  for (const auth of opened.splice(0)) auth.closeStore();
  if (server) { const active = server; server = undefined; active.closeAllConnections(); await new Promise<void>(resolve => active.close(() => resolve())); }
  rmSync(dir, { recursive: true, force: true });
});
function config(users?: TeamConfig["users"]): TeamConfig {
  return { workspace: { id: "team", name: "Team" }, users: users ?? [{ id: "ada", name: "Ada", role: "owner", passwordHash: hash }, { id: "alex", name: "Alex", role: "viewer", passwordHash: hash }] };
}
/** One "server start": a fresh TeamAuth over the same database file. */
function start(cfg: TeamConfig = config()) {
  const auth = new TeamAuth({ origin, config: cfg }); opened.push(auth);
  const result = auth.attachStore(new TeamUserTable(dbPath));
  return { auth, ...result };
}

describe("team user store", () => {
  it("imports the users of the team file once and keeps them across restarts", async () => {
    const first = start();
    expect(first.imported).toBe(2); expect(first.total).toBe(2);
    expect((await first.auth.login({ userId: "ada", password: "correct horse battery" })).user.role).toBe("owner");
    first.auth.closeStore();
    const second = start();
    expect(second.imported).toBe(0); expect(second.total).toBe(2);
    expect(second.auth.members().map(user => user.userId).sort()).toEqual(["ada", "alex"]);
  });

  it("lets the database win over the file, and adds users that are new in the file", () => {
    start().auth.closeStore();
    const edited = config([{ id: "ada", name: "Ada", role: "viewer", passwordHash: hash }, { id: "alex", name: "Alex", role: "viewer", passwordHash: hash }, { id: "bo", name: "Bo", role: "editor", passwordHash: hash }]);
    const { auth, imported } = start(edited);
    expect(imported).toBe(1);
    expect(auth.lookupUser("ada")?.role).toBe("owner");
    expect(auth.lookupUser("bo")?.role).toBe("editor");
  });

  it("stores a teammate added at run time, so it survives a restart", async () => {
    const { auth } = start();
    auth.addMember({ id: "cy", name: "Cy", role: "editor", passwordHash: hash });
    auth.closeStore();
    const again = start().auth;
    expect(again.lookupUser("cy")).toMatchObject({ displayName: "Cy", role: "editor" });
    expect((await again.login({ userId: "cy", password: "correct horse battery" })).user.userId).toBe("cy");
    expect(() => again.addMember({ id: "cy", name: "Other", role: "viewer", passwordHash: hash })).toThrow("already exists");
  });

  it("stops at the free limit and lifts it with the rbac license", () => {
    const table = new TeamUserTable(dbPath);
    table.importMissing(Array.from({ length: FREE_MEMBER_LIMIT }, (_, i) => ({ id: `bulk-${i}`, name: `Bulk ${i}`, role: "viewer", passwordHash: null, oidcSub: null, source: "local" as const })));
    table.close();
    const { auth } = start();
    expect(auth.memberCount()).toBe(FREE_MEMBER_LIMIT + 2);
    expect(auth.atMemberLimit()).toBe(true);
    expect(() => auth.addMember({ id: "late", name: "Late", role: "viewer", passwordHash: hash })).toThrow("member limit");
    const restore = applyTestLicense(["rbac"]);
    try {
      expect(auth.atMemberLimit()).toBe(false);
      expect(auth.addMember({ id: "late", name: "Late", role: "viewer", passwordHash: hash }).userId).toBe("late");
    } finally { restore(); }
    expect(auth.atMemberLimit()).toBe(true);
  });

  it("holds 3,000 users: loads fast, signs in, and looks users up in constant time", async () => {
    const restore = applyTestLicense(["rbac"]);
    try {
      const table = new TeamUserTable(dbPath);
      const rows = Array.from({ length: 3000 }, (_, i) => ({ id: `user-${i}`, name: `User ${i}`, role: i % 10 === 0 ? "editor" : "viewer", passwordHash: i === 2999 ? hash : null, oidcSub: `sub-${i}`, source: "oidc" as const }));
      const loadStart = performance.now();
      expect(table.importMissing(rows)).toHaveLength(3000);
      const insertMs = performance.now() - loadStart;
      table.close();
      const bootStart = performance.now();
      const { auth, total } = start();
      const bootMs = performance.now() - bootStart;
      expect(total).toBe(3002);
      expect(auth.atMemberLimit()).toBe(false);
      const lookupStart = performance.now();
      for (let i = 0; i < 3000; i++) expect(auth.lookupUser(`user-${i}`)?.displayName).toBe(`User ${i}`);
      const lookupMs = performance.now() - lookupStart;
      expect((await auth.login({ userId: "user-2999", password: "correct horse battery" })).user.userId).toBe("user-2999");
      // Generous ceilings so a slow CI machine stays green; real numbers are far lower.
      expect(insertMs).toBeLessThan(20_000); expect(bootMs).toBeLessThan(10_000); expect(lookupMs).toBeLessThan(2_000);
    } finally { restore(); }
  }, 60_000);
});

let server: Server | undefined;
async function provider(claims: Record<string, unknown>) {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = { ...await exportJWK(publicKey), kid: "k", alg: "RS256", use: "sig" };
  let issuer = ""; let nonce = ""; let subject = "new-person";
  server = createServer(async (req, res) => {
    res.setHeader("Content-Type", "application/json");
    if (req.url === "/.well-known/openid-configuration") return res.end(JSON.stringify({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/keys` }));
    if (req.url === "/keys") return res.end(JSON.stringify({ keys: [jwk] }));
    if (req.url === "/token") {
      for await (const part of req) void part;
      return res.end(JSON.stringify({ id_token: await new SignJWT({ nonce, ...claims }).setProtectedHeader({ alg: "RS256", kid: "k" }).setIssuer(issuer).setAudience("client").setSubject(subject).setIssuedAt().setExpirationTime("5m").sign(privateKey) }));
    }
    res.statusCode = 404; res.end("{}");
  });
  await new Promise<void>(resolve => server!.listen(0, "127.0.0.1", resolve)); issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { issuer, setNonce(value: string) { nonce = value; }, setSubject(value: string) { subject = value; } };
}
async function ssoSignIn(auth: TeamAuth, mock: { setNonce(value: string): void }) {
  const begin = await auth.beginSSO(); const url = new URL(begin.url); mock.setNonce(url.searchParams.get("nonce")!);
  return auth.callback(new URLSearchParams({ state: url.searchParams.get("state")!, code: "c" }), { headers: { cookie: begin.setCookie.split(";")[0]! } });
}

describe("OIDC sign-in creates accounts on first use (jit)", () => {
  async function setup(jit: boolean, claims: Record<string, unknown> = { name: "Newcomer" }) {
    const mock = await provider(claims);
    const cfg = config(); cfg.users[1]!.oidcSub = "known-sub";
    cfg.oidc = { issuer: mock.issuer, clientId: "client", redirectUri: `${origin}/api/team/auth/callback`, ...(jit ? { jit: { role: "viewer" as const } } : {}) };
    return { mock, cfg };
  }

  it("keeps working for a pre-linked user with no license and no jit setting", async () => {
    const { mock, cfg } = await setup(false); mock.setSubject("known-sub");
    const { auth } = start(cfg);
    expect((await ssoSignIn(auth, mock)).user).toMatchObject({ userId: "alex", role: "viewer" });
  });

  it("refuses an unknown user without a license, even when jit is set, and stores nothing", async () => {
    const { mock, cfg } = await setup(true);
    const { auth } = start(cfg);
    await expect(ssoSignIn(auth, mock)).rejects.toMatchObject({ statusCode: 403, message: expect.stringContaining("enterprise license") });
    expect(auth.memberCount()).toBe(2);
  });

  it("refuses an unknown user when jit is not set, even with a license", async () => {
    const restore = applyTestLicense(["rbac"]);
    try {
      const { mock, cfg } = await setup(false);
      const { auth } = start(cfg);
      await expect(ssoSignIn(auth, mock)).rejects.toMatchObject({ statusCode: 403, message: "This SSO account is not a workspace member" });
    } finally { restore(); }
  });

  it("creates the account on first sign-in with a license, reuses it afterwards, and keeps it after a restart", async () => {
    const restore = applyTestLicense(["rbac"]);
    try {
      const { mock, cfg } = await setup(true, { name: "New\u0007comer", email: "n@example.com" });
      const { auth } = start(cfg);
      const first = await ssoSignIn(auth, mock);
      expect(first.provisioned).toBe(true);
      expect(first.user).toMatchObject({ userId: "oidc:new-person", displayName: "Newcomer", role: "viewer" });
      const second = await ssoSignIn(auth, mock);
      expect(second.provisioned).toBe(false); expect(second.user.userId).toBe("oidc:new-person");
      expect(auth.memberCount()).toBe(3);
      auth.closeStore();
      const again = start(cfg).auth;
      expect(again.lookupUser("oidc:new-person")?.role).toBe("viewer");
      // No password: the account can only sign in through SSO.
      await expect(again.login({ userId: "oidc:new-person", password: "x" })).rejects.toMatchObject({ statusCode: 401 });
    } finally { restore(); }
  });

  it("does not let a jit account take over a local account ID", async () => {
    const restore = applyTestLicense(["rbac"]);
    try {
      const { mock, cfg } = await setup(true); mock.setSubject("ada");
      const { auth } = start(cfg);
      const result = await ssoSignIn(auth, mock);
      expect(result.user.userId).toBe("oidc:ada"); expect(result.user.role).toBe("viewer");
      expect(auth.lookupUser("ada")?.role).toBe("owner");
    } finally { restore(); }
  });

  it("rejects a jit role of owner in the configuration", () => {
    const cfg = config(); cfg.oidc = { issuer: "https://idp.example", clientId: "c", redirectUri: `${origin}/api/team/auth/callback`, jit: { role: "owner" as never } };
    expect(() => new TeamAuth({ origin, config: cfg })).toThrow();
  });
});
