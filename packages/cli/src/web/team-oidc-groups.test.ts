import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { TeamUserTable } from "@0/engine/storage";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { TeamAuth, type TeamConfig } from "./team-auth.js";
import { applyTestLicense } from "./__fixtures__/test-license.js";

const origin = "http://127.0.0.1:48123";
let dir: string; let server: Server | undefined; let restore: (() => void) | undefined;
const opened: TeamAuth[] = [];
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "0-oidc-groups-")); });
afterEach(async () => {
  restore?.(); restore = undefined;
  for (const auth of opened.splice(0)) auth.closeStore();
  if (server) { const active = server; server = undefined; active.closeAllConnections(); await new Promise<void>(resolve => active.close(() => resolve())); }
  rmSync(dir, { recursive: true, force: true });
});

async function provider() {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const jwk = { ...await exportJWK(publicKey), kid: "k", alg: "RS256", use: "sig" };
  let issuer = ""; let nonce = ""; let subject = "person-1"; let claims: Record<string, unknown> = {};
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
  return { issuer, nonce: (value: string) => { nonce = value; }, subject: (value: string) => { subject = value; }, claims: (value: Record<string, unknown>) => { claims = value; } };
}

async function fixture(oidc: Partial<NonNullable<TeamConfig["oidc"]>> = {}) {
  const mock = await provider();
  const cfg: TeamConfig = {
    workspace: { id: "groups", name: "Groups" },
    users: [{ id: "boss", name: "Boss", role: "owner", oidcSub: "boss-sub" }],
    oidc: { issuer: mock.issuer, clientId: "client", redirectUri: `${origin}/api/team/auth/callback`, jit: { role: "viewer" }, groupRoles: { "sec-admins": "owner", "sec-triage": "triager", "sec-audit": "auditor" }, ...oidc },
  };
  const start = () => { const auth = new TeamAuth({ origin, config: cfg }); opened.push(auth); auth.attachStore(new TeamUserTable(join(dir, "data.db"))); return auth; };
  const signIn = async (auth: TeamAuth) => {
    const begin = await auth.beginSSO(); const url = new URL(begin.url); mock.nonce(url.searchParams.get("nonce")!);
    return auth.callback(new URLSearchParams({ state: url.searchParams.get("state")!, code: "c" }), { headers: { cookie: begin.setCookie.split(";")[0]! } });
  };
  return { mock, cfg, start, signIn };
}

describe("OIDC group to role mapping", () => {
  it("gives a new user the role of the first mapped group, then follows the groups at each sign-in", async () => {
    restore = applyTestLicense(["rbac"]);
    const { mock, start, signIn } = await fixture();
    const auth = start();
    mock.claims({ name: "Pat", groups: ["everyone", "sec-triage"] });
    const first = await signIn(auth);
    expect(first.provisioned).toBe(true); expect(first.user).toMatchObject({ roleName: "triager", role: "viewer" });
    expect(first).not.toHaveProperty("roleChange");

    mock.claims({ name: "Pat", groups: ["sec-audit"] });
    const second = await signIn(auth);
    expect(second.user.roleName).toBe("auditor");
    expect(second.roleChange).toEqual({ userId: "oidc:person-1", old: "triager", new: "auditor", source: "oidc-group" });

    // Leaving every mapped group falls back to the jit role.
    mock.claims({ name: "Pat", groups: ["everyone"] });
    expect((await signIn(auth)).user.roleName).toBe("viewer");

    // The mapping order is the operator's order, not the order of the claim.
    mock.claims({ name: "Pat", groups: ["sec-audit", "sec-admins", "sec-triage"] });
    expect((await signIn(auth)).user.roleName).toBe("owner");
    auth.closeStore();
    expect(start().lookupUser("oidc:person-1")?.roleName).toBe("owner");
  });

  it("never changes an account an administrator set or the file lists", async () => {
    restore = applyTestLicense(["rbac"]);
    const { mock, start, signIn } = await fixture();
    const auth = start();
    mock.subject("boss-sub"); mock.claims({ groups: ["sec-audit"] });
    const boss = await signIn(auth);
    expect(boss.user.roleName).toBe("owner"); expect(boss).not.toHaveProperty("roleChange");

    mock.subject("person-2"); mock.claims({ groups: ["sec-triage"] });
    await signIn(auth);
    auth.setAccess("oidc:person-2", { role: "editor" });
    mock.claims({ groups: ["sec-audit"] });
    const pinned = await signIn(auth);
    expect(pinned.user.roleName).toBe("editor"); expect(pinned).not.toHaveProperty("roleChange");
  });

  it("reads the claim named in groupsClaim and accepts a single group name", async () => {
    restore = applyTestLicense(["rbac"]);
    const { mock, start, signIn } = await fixture({ groupsClaim: "roles" });
    const auth = start();
    mock.claims({ groups: ["sec-admins"], roles: "sec-audit" });
    expect((await signIn(auth)).user.roleName).toBe("auditor");
  });

  it("does nothing without the license: the mapping is ignored and unknown users are refused", async () => {
    const { mock, start, signIn } = await fixture();
    const auth = start();
    mock.subject("boss-sub"); mock.claims({ groups: ["sec-audit"] });
    expect((await signIn(auth)).user.roleName).toBe("owner");
    mock.subject("stranger");
    await expect(signIn(auth)).rejects.toMatchObject({ statusCode: 403 });
    expect(auth.memberCount()).toBe(1);
  });
});
