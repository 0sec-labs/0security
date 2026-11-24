import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { beforeEach, describe, expect, it, vi } from "vitest";

// The signature, audience, replay and XML checks live in enterprise/ and are tested there with real signed
// documents. These tests cover the glue: license gate, browser binding, member lookup, role mapping, routes.
const mocks = vi.hoisted(() => ({
  denial: null as string | null,
  identity: { nameId: "alex@corp.test", issuer: "https://idp.test", assertionId: "_a1", attributes: {} as Record<string, string[]> },
  begun: [] as string[],
  counter: 0,
}));
vi.mock("../enterprise-bridge.js", async importOriginal => ({
  ...(await importOriginal<typeof import("../enterprise-bridge.js")>()),
  samlLicenseDenial: () => mocks.denial,
  samlLicensed: () => mocks.denial === null,
  parseIdpMetadata: (xml: string) => ({ entityId: "https://idp.test", ssoUrl: "https://idp.test/sso", certificates: [], xml }),
  SamlError: class SamlError extends Error { constructor(readonly reason: string, message: string, readonly statusCode = 401) { super(message); } },
  SamlServiceProvider: class FakeProvider {
    private readonly pending = new Map<string, string>();
    async begin(binding: string) { const relayState = `state-${++mocks.counter}-${"x".repeat(16)}`; this.pending.set(relayState, binding); mocks.begun.push(binding); return { url: `https://idp.test/sso?RelayState=${relayState}`, relayState }; }
    async consume(form: { RelayState?: unknown }) {
      const binding = typeof form.RelayState === "string" ? this.pending.get(form.RelayState) : undefined;
      this.pending.delete(String(form.RelayState));
      if (binding === undefined) { const { SamlError } = await import("../enterprise-bridge.js"); throw new SamlError("unknown-relay-state", "no"); }
      return { identity: mocks.identity, binding };
    }
    metadataXml() { return "<EntityDescriptor/>"; }
  },
}));

import { TeamAuth, TeamAuthError, hashTeamPassword, type TeamConfig } from "./team-auth.js";
import { isCrossSiteSignInReturn, isSamlAcsPost, isTeamSsoRoute } from "./team-sso-routes.js";
import { authorizeWebRequest, readForm } from "./dashboard-http.js";
import { ServerModeGuard } from "./server-mode.js";
import { roleFromGroups } from "./team-saml.js";
import { handleTeamRequest } from "./team-web.js";

const origin = "https://0.example.com";
const acsUrl = `${origin}/api/team/auth/saml/acs`;
const dir = mkdtempSync(join(tmpdir(), "saml-glue-"));
const metadataFile = join(dir, "idp.xml");
writeFileSync(metadataFile, "<idp/>");
let passwordHash: string;
beforeEach(async () => { passwordHash ??= await hashTeamPassword("correct horse battery"); mocks.denial = null; mocks.begun.length = 0; mocks.identity = { nameId: "alex@corp.test", issuer: "https://idp.test", assertionId: "_a1", attributes: {} }; });

function config(saml: Record<string, unknown> = {}, users?: TeamConfig["users"]): TeamConfig {
  return {
    workspace: { id: "team", name: "Team" },
    users: users ?? [{ id: "alex", name: "Alex", role: "viewer", passwordHash, samlNameId: "alex@corp.test" }, { id: "sam", name: "Sam", role: "editor", samlNameId: "sam@corp.test" }],
    saml: { entityId: `${origin}/saml`, acsUrl, metadataFile, ...saml },
  } as TeamConfig;
}
const cookieOf = (setCookie: string) => setCookie.split(";")[0]!;
const req = (cookie?: string) => ({ headers: { cookie } });
const ticketOf = (redirect: string) => new URL(redirect, origin).searchParams.get("ticket");

const relayOf = (url: string) => new URL(url).searchParams.get("RelayState")!;
async function signIn(auth: TeamAuth) {
  const begin = await auth.beginSAML();
  const acs = await auth.samlAcs({ SAMLResponse: "x", RelayState: relayOf(begin.url) });
  return { begin, acs, cookie: cookieOf(begin.setCookie), relay: relayOf(begin.url) };
}

describe("SAML team config", () => {
  it("is optional and does not change OIDC or password sign-in", () => {
    const auth = new TeamAuth({ origin, config: { workspace: { id: "t", name: "T" }, users: [{ id: "a", name: "A", role: "owner", passwordHash }] } });
    expect(auth.status(req())).toEqual({ enabled: true, workspace: { id: "t", name: "T" }, user: null, sso: false });
  });
  it("validates the ACS URL, metadata source and group mapping", () => {
    expect(() => new TeamAuth({ origin, config: config({ acsUrl: "https://evil.example.com/api/team/auth/saml/acs" }) })).toThrow(/engine origin/);
    expect(() => new TeamAuth({ origin, config: config({ acsUrl: `${origin}/other` }) })).toThrow(/acsUrl must be/);
    expect(() => new TeamAuth({ origin, config: config({ metadataFile: undefined }) })).toThrow(/exactly one/);
    expect(() => new TeamAuth({ origin, config: config({ metadataUrl: "https://idp.test/m" }) })).toThrow(/exactly one/);
    expect(() => new TeamAuth({ origin, config: config({ metadataFile: undefined, metadataUrl: "http://idp.test/m" }) })).toThrow(/HTTPS/);
    expect(() => new TeamAuth({ origin, config: config({ metadataFile: "relative.xml" }) })).toThrow(/absolute/);
    expect(() => new TeamAuth({ origin, config: config({ groupAttribute: "groups" }) })).toThrow(/go together/);
    expect(() => new TeamAuth({ origin, config: config({}, [{ id: "a", name: "A", role: "owner", samlNameId: "x" }, { id: "b", name: "B", role: "owner", samlNameId: "x" }]) })).toThrow(/unique/);
    expect(new TeamAuth({ origin, config: config({ metadataFile: undefined, metadataUrl: "https://idp.test/m" }) }).status(req())).toMatchObject({ saml: true });
  });
});

describe("license gate", () => {
  it("refuses every SAML step without a license, and still lists the option only when configured", async () => {
    mocks.denial = "SAML sign-in needs an enterprise license.";
    const auth = new TeamAuth({ origin, config: config() });
    await expect(auth.beginSAML()).rejects.toMatchObject({ statusCode: 403, reason: "not_licensed" });
    await expect(auth.samlAcs({ SAMLResponse: "x", RelayState: "y" })).rejects.toMatchObject({ statusCode: 403 });
    await expect(auth.samlMetadata()).rejects.toMatchObject({ statusCode: 403 });
    expect(mocks.begun).toEqual([]);
  });
  it("answers 404 when SAML is not configured", async () => {
    const auth = new TeamAuth({ origin, config: { workspace: { id: "t", name: "T" }, users: [{ id: "a", name: "A", role: "owner", passwordHash }] } });
    expect(() => auth.beginSAML()).toThrow("SAML sign-in is not configured");
  });
  it("serves the SP metadata when licensed", async () => {
    expect(await new TeamAuth({ origin, config: config() }).samlMetadata()).toBe("<EntityDescriptor/>");
  });
});

describe("sign-in flow", () => {
  it("signs a configured member in with their own role", async () => {
    const auth = new TeamAuth({ origin, config: config() });
    const { begin, acs, cookie } = await signIn(auth);
    expect(begin.setCookie).toContain("zero_team_saml=");
    expect(begin.setCookie).toContain("SameSite=Lax");
    expect(begin.setCookie).toContain("; Secure");
    expect(acs.redirect).toMatch(/^\/api\/team\/auth\/saml\/complete\?ticket=/);
    const done = auth.samlComplete(ticketOf(acs.redirect), req(cookie));
    expect(done.user).toMatchObject({ userId: "alex", role: "viewer" });
    expect(done.redirect).toBe("/");
    expect(auth.resolveSessionId(done.sessionId)).toMatchObject({ userId: "alex", role: "viewer" });
  });

  it("does not sign in a browser other than the one that began the flow", async () => {
    const auth = new TeamAuth({ origin, config: config() });
    const { acs } = await signIn(auth);
    expect(() => auth.samlComplete(ticketOf(acs.redirect), req())).toThrow(TeamAuthError);
    const second = await signIn(auth);
    expect(() => auth.samlComplete(ticketOf(second.acs.redirect), req("zero_team_saml=attacker-cookie"))).toThrow(/Invalid or expired/);
    const third = await signIn(auth);
    expect(() => auth.samlComplete(ticketOf(third.acs.redirect), req(`${third.cookie}; zero_team_saml=other`))).toThrow(/Invalid or expired/);
  });

  it("spends the ticket and the sign-in", async () => {
    const auth = new TeamAuth({ origin, config: config() });
    const { acs, cookie, relay } = await signIn(auth);
    auth.samlComplete(ticketOf(acs.redirect), req(cookie));
    expect(() => auth.samlComplete(ticketOf(acs.redirect), req(cookie))).toThrow(/Invalid or expired/);
    await expect(auth.samlAcs({ SAMLResponse: "x", RelayState: relay })).rejects.toMatchObject({ statusCode: 401, reason: "unknown-relay-state" });
    const again = await signIn(auth);
    await expect(auth.samlAcs({ SAMLResponse: "x", RelayState: again.relay })).rejects.toMatchObject({ statusCode: 401 });
  });

  it("expires the ticket", async () => {
    let now = 1_000;
    const auth = new TeamAuth({ origin, config: config(), now: () => now });
    const { acs, cookie } = await signIn(auth);
    now += 61_000;
    expect(() => auth.samlComplete(ticketOf(acs.redirect), req(cookie))).toThrow(/Invalid or expired/);
  });

  it("refuses a NameID that is not a configured member, and never reveals why a response failed", async () => {
    const auth = new TeamAuth({ origin, config: config() });
    mocks.identity = { ...mocks.identity, nameId: "stranger@corp.test" };
    const begin = await auth.beginSAML();
    await expect(auth.samlAcs({ SAMLResponse: "x", RelayState: relayOf(begin.url) })).rejects.toMatchObject({ statusCode: 403, reason: "not_a_member" });
    await expect(auth.samlAcs({ SAMLResponse: "x", RelayState: "forged" })).rejects.toMatchObject({ statusCode: 401, message: "SAML sign-in failed", reason: "unknown-relay-state" });
  });

  it("matches the NameID exactly, not by case or prefix", async () => {
    const auth = new TeamAuth({ origin, config: config() });
    for (const nameId of ["ALEX@corp.test", "alex@corp.test.evil", "alex@corp.tes", " alex@corp.test"]) {
      mocks.identity = { ...mocks.identity, nameId };
      const begin = await auth.beginSAML();
      await expect(auth.samlAcs({ SAMLResponse: "x", RelayState: relayOf(begin.url) })).rejects.toMatchObject({ reason: "not_a_member" });
    }
  });
});

describe("group to role mapping", () => {
  const mapped = { groupAttribute: "groups", groupRoles: { "sec-owners": "owner", "sec-editors": "editor", "sec-viewers": "viewer" } };
  it("takes the highest mapped role and applies it to the session", async () => {
    const auth = new TeamAuth({ origin, config: config(mapped) });
    mocks.identity = { ...mocks.identity, attributes: { groups: ["everyone", "sec-viewers", "sec-owners"] } };
    const { acs, cookie } = await signIn(auth);
    const done = auth.samlComplete(ticketOf(acs.redirect), req(cookie));
    expect(done.user.role).toBe("owner");
    expect(auth.resolveSession(req(cookieOf(done.setCookie)))).toMatchObject({ userId: "alex", role: "owner" });
  });
  it("can lower a role below the configured one", async () => {
    const auth = new TeamAuth({ origin, config: config(mapped) });
    mocks.identity = { ...mocks.identity, nameId: "sam@corp.test", attributes: { groups: ["sec-viewers"] } };
    const { acs, cookie } = await signIn(auth);
    expect(auth.samlComplete(ticketOf(acs.redirect), req(cookie)).user.role).toBe("viewer");
  });
  it("refuses a member whose groups map to nothing", async () => {
    const auth = new TeamAuth({ origin, config: config(mapped) });
    mocks.identity = { ...mocks.identity, attributes: { groups: ["everyone"] } };
    const begin = await auth.beginSAML();
    await expect(auth.samlAcs({ SAMLResponse: "x", RelayState: relayOf(begin.url) })).rejects.toMatchObject({ statusCode: 403, reason: "no_mapped_group" });
  });
  it("ignores inherited object keys and roles outside the three", () => {
    expect(roleFromGroups(["__proto__", "constructor", "toString"], { "sec-owners": "owner" })).toBeUndefined();
    expect(roleFromGroups(["a"], { a: "viewer" })).toBe("viewer");
    expect(() => new TeamAuth({ origin, config: config({ groupAttribute: "g", groupRoles: { a: "admin" } }) })).toThrow();
  });
});

describe("routes and request guards", () => {
  it("lists the anonymous sign-in routes exactly", () => {
    expect(isTeamSsoRoute("POST", "/api/team/auth/saml/acs")).toBe(true);
    expect(isTeamSsoRoute("GET", "/api/team/auth/saml/acs")).toBe(false);
    for (const p of ["sso", "complete", "metadata"]) expect(isTeamSsoRoute("GET", `/api/team/auth/saml/${p}`)).toBe(true);
    expect(isTeamSsoRoute("POST", "/api/team/auth/saml/sso")).toBe(false);
    expect(isTeamSsoRoute("POST", "/api/team/auth/login")).toBe(false);
    expect(isTeamSsoRoute("GET", "/api/team/auth/saml/acs/extra")).toBe(false);
    expect(isTeamSsoRoute("GET", "/api/team/auth/callback")).toBe(true);
    expect(isSamlAcsPost("POST", "/api/team/auth/saml/acs?x=1")).toBe(true);
    expect(isSamlAcsPost("POST", "/api/team/auth/saml/acs/")).toBe(false);
    expect(isCrossSiteSignInReturn("GET", "/api/team/auth/saml/complete?ticket=t")).toBe(true);
    expect(isCrossSiteSignInReturn("POST", "/api/team/auth/login")).toBe(false);
  });

  const fake = (init: { method: string; url: string; headers: Record<string, string> }) => ({ ...init, socket: { remoteAddress: "203.0.113.9" } }) as never;
  it("lets the identity provider post to the ACS from its own origin, and nothing else", () => {
    const headers = { host: "127.0.0.1:48123", origin: "https://idp.test", "sec-fetch-site": "cross-site" };
    expect(() => authorizeWebRequest(fake({ method: "POST", url: "/api/team/auth/saml/acs", headers }), "http://127.0.0.1:48123")).not.toThrow();
    expect(() => authorizeWebRequest(fake({ method: "POST", url: "/api/team/auth/login", headers }), "http://127.0.0.1:48123")).toThrow(/Cross-origin/);
    expect(() => authorizeWebRequest(fake({ method: "POST", url: "/api/console/sessions", headers: { ...headers, origin: "null" } }), "http://127.0.0.1:48123")).toThrow(/Cross-origin/);
    expect(() => authorizeWebRequest(fake({ method: "GET", url: "/api/team/auth/saml/acs", headers }), "http://127.0.0.1:48123")).toThrow();
    expect(() => authorizeWebRequest(fake({ method: "GET", url: "/api/team/auth/saml/complete?ticket=t", headers: { host: "127.0.0.1:48123", "sec-fetch-site": "cross-site" } }), "http://127.0.0.1:48123")).not.toThrow();
  });
  it("applies the same rule in server mode", () => {
    const guard = new ServerModeGuard({ allowedHosts: ["0.example.com"], trustedProxies: [], publicUrl: origin });
    const headers = { host: "0.example.com", origin: "https://idp.test", "sec-fetch-site": "cross-site" };
    expect(() => guard.authorize(fake({ method: "POST", url: "/api/team/auth/saml/acs", headers }))).not.toThrow();
    expect(() => guard.authorize(fake({ method: "POST", url: "/api/team/auth/login", headers }))).toThrow(/Cross-origin/);
    expect(() => guard.authorize(fake({ method: "POST", url: "/api/team/auth/saml/acs", headers: { ...headers, host: "evil.example.net" } }))).toThrow(/not allowed/);
  });

  it("reads only a single-use, size-capped form", async () => {
    const post = (body: string, type = "application/x-www-form-urlencoded") => Object.assign(Readable.from([Buffer.from(body)]), { headers: { "content-type": type } }) as never;
    expect(await readForm(post("SAMLResponse=abc%3D&RelayState=r"))).toEqual({ SAMLResponse: "abc=", RelayState: "r" });
    await expect(readForm(post("a=1&a=2"))).rejects.toMatchObject({ statusCode: 400 });
    await expect(readForm(post("{}", "application/json"))).rejects.toMatchObject({ statusCode: 415 });
    await expect(readForm(post("a=" + "x".repeat(50)), 10)).rejects.toMatchObject({ statusCode: 413 });
    await expect(readForm(post(Array.from({ length: 9 }, (_, i) => `f${i}=1`).join("&")))).rejects.toMatchObject({ statusCode: 400, message: "Too many form fields." });
    await expect(readForm(post("&".repeat(700_000)))).rejects.toMatchObject({ statusCode: 400 });
    expect(await readForm(post(`${"k".repeat(65)}=1&RelayState=r`))).toEqual({ RelayState: "r" });
  });
});

describe("team routes", () => {
  const call = (auth: TeamAuth, method: string, path: string, headers: Record<string, string> = {}, form?: Record<string, string>) =>
    handleTeamRequest({ method, headers, socket: { remoteAddress: "203.0.113.9" } } as never, new URL(path, origin), auth, undefined, undefined as never, async () => ({}), undefined, form ? async () => form : undefined);
  it("serves metadata, redirects to the identity provider, and finishes with a session cookie", async () => {
    const auth = new TeamAuth({ origin, config: config() });
    expect(await call(auth, "GET", "/api/team/auth/saml/metadata")).toEqual({ status: 200, xml: "<EntityDescriptor/>" });
    const sso = await call(auth, "GET", "/api/team/auth/saml/sso");
    expect(sso).toMatchObject({ status: 302, redirect: expect.stringMatching(/^https:\/\/idp\.test\/sso\?RelayState=/) });
    const cookie = cookieOf((sso!.headers as Record<string, string>)["Set-Cookie"]!);
    const acs = await call(auth, "POST", "/api/team/auth/saml/acs", {}, { SAMLResponse: "x", RelayState: relayOf(sso!.redirect!) });
    expect(acs).toMatchObject({ status: 303, redirect: expect.stringMatching(/^\/api\/team\/auth\/saml\/complete\?ticket=/) });
    const done = await call(auth, "GET", acs!.redirect!, { cookie });
    expect(done).toMatchObject({ status: 302, redirect: "/" });
    expect((done!.headers as Record<string, string[]>)["Set-Cookie"]).toHaveLength(2);
  });
  it("answers 404 for unknown SAML routes and wrong methods", async () => {
    const auth = new TeamAuth({ origin, config: config() });
    await expect(call(auth, "GET", "/api/team/auth/saml/acs")).rejects.toMatchObject({ statusCode: 404 });
    await expect(call(auth, "POST", "/api/team/auth/saml/sso")).rejects.toMatchObject({ statusCode: 404 });
    await expect(call(auth, "POST", "/api/team/auth/saml/acs")).rejects.toMatchObject({ statusCode: 404 });
  });
});
