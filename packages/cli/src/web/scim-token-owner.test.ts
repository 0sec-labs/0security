// SCIM tokens provision accounts and set their roles, so only the workspace owner may make, list or revoke them.
// A role that holds users.manage (or every permission) is not enough.
import type { IncomingMessage } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TeamUserTable, closeAuditLog, listAudit } from "@0/engine/storage";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { configureAudit } from "./audit.js";
import { TeamAuth, hashTeamPassword, type TeamConfig } from "./team-auth.js";
import { handleTeamRequest } from "./team-web.js";
import { applyTestLicense } from "./__fixtures__/test-license.js";

const origin = "http://127.0.0.1:48123";
let dir: string; let dbPath: string; let hash: string; let restore: (() => void) | undefined;
const opened: TeamAuth[] = [];
beforeAll(async () => { hash = await hashTeamPassword("test-only-password"); });
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "0-scim-owner-")); dbPath = join(dir, "data.db"); configureAudit(dbPath); });
afterEach(() => { restore?.(); restore = undefined; for (const auth of opened.splice(0)) auth.closeStore(); closeAuditLog(); configureAudit(null); rmSync(dir, { recursive: true, force: true }); });

const ALL = ["workspace.read", "findings.read", "findings.triage", "threads.run", "settings.write", "audit.read", "users.manage"];
const config = (): TeamConfig => ({
  workspace: { id: "scim-owner", name: "SCIM owner" },
  users: [
    { id: "owner", name: "Owner", role: "owner", passwordHash: hash },
    { id: "manager", name: "Manager", role: "user-manager", passwordHash: hash },
    { id: "almost", name: "Almost owner", role: "almost-owner", passwordHash: hash },
    { id: "editor", name: "Editor", role: "editor", passwordHash: hash },
  ],
  roles: { "user-manager": { permissions: ["workspace.read", "users.manage"] }, "almost-owner": { permissions: ALL } },
});
async function start() {
  const auth = new TeamAuth({ origin, config: config() }); opened.push(auth);
  auth.attachStore(new TeamUserTable(dbPath));
  const cookies: Record<string, string> = {};
  for (const id of ["owner", "manager", "almost", "editor"]) cookies[id] = (await auth.login({ userId: id, password: "test-only-password" }, id)).setCookie.split(";")[0]!;
  const call = (who: string, method: string, path: string, body?: unknown) =>
    handleTeamRequest({ method, headers: { cookie: cookies[who] }, socket: { remoteAddress: "127.0.0.1" } } as IncomingMessage, new URL(`/api/team/${path}`, origin), auth, {} as never, {} as never, async () => body);
  return { auth, call };
}

describe.each([["licensed with scim", ["scim", "rbac"]], ["without a license", []]] as const)("SCIM token routes, %s", (_label, features) => {
  beforeEach(() => { if (features.length) restore = applyTestLicense([...features]); });

  it.each(["manager", "almost", "editor"])("%s cannot create, list or revoke a token", async who => {
    const { auth, call } = await start();
    const existing = auth.scim!.createToken("okta");
    await expect(call(who, "POST", "scim-tokens", { name: "mine" })).rejects.toMatchObject({ statusCode: 403, message: expect.stringContaining("owners") });
    await expect(call(who, "GET", "scim-tokens")).rejects.toMatchObject({ statusCode: 403 });
    await expect(call(who, "DELETE", `scim-tokens/${existing.record.id}`)).rejects.toMatchObject({ statusCode: 403 });
    // Nothing changed: still one token, still active, no audit entry for it.
    expect(auth.scim!.listTokens()).toHaveLength(1);
    expect(auth.scim!.verifyToken(existing.token)).not.toBeNull();
    expect(listAudit({ q: "scim.token" }, { dbPath }).events).toHaveLength(0);
  });

  it("a non-owner is refused before the license is mentioned, and gets nothing about tokens", async () => {
    const { call } = await start();
    const refused = await call("manager", "GET", "scim-tokens").catch(error => error as Error);
    expect((refused as Error).message).not.toMatch(/license|token [a-z]/i);
  });
});

describe("the owner", () => {
  it("makes, lists and revokes tokens with the scim license, and each step is audited", async () => {
    restore = applyTestLicense(["scim"]);
    const { auth, call } = await start();
    const made = await call("owner", "POST", "scim-tokens", { name: "okta" });
    expect(made).toMatchObject({ status: 201, data: { token: expect.stringMatching(/^scim_/), record: { name: "okta" } } });
    const listed = (await call("owner", "GET", "scim-tokens"))!.data as { tokens: Array<{ id: string }>; unavailable: string | null };
    expect(listed.unavailable).toBeNull();
    expect(listed.tokens).toHaveLength(1);
    expect(JSON.stringify(listed)).not.toContain((made!.data as { token: string }).token);
    const id = listed.tokens[0]!.id;
    expect((await call("owner", "DELETE", `scim-tokens/${id}`))!.status).toBe(200);
    expect(auth.scim!.verifyToken((made!.data as { token: string }).token)).toBeNull();
    expect(listAudit({ q: "scim.token" }, { dbPath }).events.map(event => event.action).sort()).toEqual(["scim.token.created", "scim.token.revoked"]);
  });

  it("still needs the scim license to make a token, and can always list and revoke", async () => {
    const { auth, call } = await start();
    await expect(call("owner", "POST", "scim-tokens", { name: "okta" })).rejects.toMatchObject({ statusCode: 403, message: expect.stringContaining("license") });
    const old = auth.scim!.createToken("old");
    const listed = await call("owner", "GET", "scim-tokens");
    expect(listed!.status).toBe(200);
    // The list says why a new token cannot be made: the license URL and both variable names, and no token.
    const notice = (listed!.data as { unavailable: string }).unavailable;
    expect(notice).toContain("ZERO_LICENSE");
    expect(notice).toContain("ZERO_LICENSE_FILE");
    expect(notice).toMatch(/https:\/\//);
    expect(JSON.stringify(listed!.data)).not.toContain(old.token);
    expect((await call("owner", "DELETE", `scim-tokens/${old.record.id}`))!.status).toBe(200);
  });
});
