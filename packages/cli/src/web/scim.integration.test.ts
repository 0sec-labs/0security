// Spawns the real CLI in server mode with team sign-in and checks that SCIM is wired in front of the sign-in gate:
// an owner makes a token in the browser API, an identity provider uses it, a person is provisioned and deprovisioned.
// The license is a throwaway one signed in the test. The production key is not involved.
import { spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { hashTeamPassword } from "./team-auth.js";
import { makeTestLicense, writeLicenseShim } from "./__fixtures__/test-license.js";

vi.setConfig({ testTimeout: 60_000 });
const entry = fileURLToPath(new URL("../index.ts", import.meta.url));
const cwd = fileURLToPath(new URL("../..", import.meta.url));
const enterpriseEntry = fileURLToPath(new URL("../../../../enterprise/dist/index.js", import.meta.url));
const PASSWORD = "scim-integration-password";

interface Reply { status: number; text: string; headers: Record<string, string | string[] | undefined>; json: () => any }
function call(port: number, path: string, init: { method?: string; headers?: Record<string, string>; body?: unknown } = {}): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const body = init.body === undefined ? undefined : JSON.stringify(init.body);
    const req = request({ host: "127.0.0.1", port, path, method: init.method ?? "GET", headers: { Host: `localhost:${port}`, Origin: `http://localhost:${port}`, ...(body ? { "Content-Type": "application/json" } : {}), ...init.headers } }, res => {
      const chunks: Buffer[] = []; res.on("data", c => chunks.push(c as Buffer));
      res.on("end", () => { const text = Buffer.concat(chunks).toString(); resolve({ status: res.statusCode ?? 0, text, headers: res.headers, json: () => JSON.parse(text) as unknown }); });
    });
    req.on("error", reject); req.end(body);
  });
}

const children: ChildProcess[] = [];
afterAll(() => { for (const child of children) child.kill("SIGKILL"); });

async function startServer(port: number, license: ReturnType<typeof makeTestLicense>) {
  const home = mkdtempSync(join(tmpdir(), "zero-scim-http-"));
  const assets = join(home, "assets"); mkdirSync(assets);
  writeFileSync(join(assets, "index.html"), "<!doctype html><html><head><title>t</title></head><body>app</body></html>");
  const teamConfig = join(home, "team.json");
  writeFileSync(teamConfig, JSON.stringify({ workspace: { id: `scim-http-${port}`, name: "SCIM HTTP" }, users: [{ id: "owner", name: "Owner", role: "owner", passwordHash: await hashTeamPassword(PASSWORD) }], scim: { groupRoles: { "sec-triage": "triager" } } }), { mode: 0o600 });
  let output = "";
  // The child trusts the throwaway key through a loader hook in this test's own temp folder, never through the environment.
  const shim = writeLicenseShim(join(home, "shim"), license.publicKeys, enterpriseEntry);
  const child = spawn(process.execPath, ["--import", "tsx", ...shim, entry, "web", "--port", String(port), "--host", "127.0.0.1", "--server-mode", "--asset-dir", assets, "--no-open", "--team-config", teamConfig, "--db-path", join(home, "data.db")],
    { cwd, env: { ...process.env, HOME: home, ZERO_NO_TELEMETRY: "1", ZERO_ALLOWED_HOSTS: "localhost", ZERO_LICENSE: "", ZERO_LICENSE_FILE: "", ...license.env } });
  children.push(child);
  child.stdout!.on("data", d => { output += String(d); }); child.stderr!.on("data", d => { output += String(d); });
  const deadline = Date.now() + 90_000;
  while (!output.includes("ZERO_DASHBOARD_READY") && Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`server exited early: ${output}`);
    await new Promise(r => setTimeout(r, 100));
  }
  const login = await call(port, "/_access/login", { method: "POST", body: { userId: "owner", password: PASSWORD } });
  if (login.status !== 200) throw new Error(`owner login failed: ${login.status} ${login.text}`);
  const cookie = String(login.headers["set-cookie"]).split(";")[0]!;
  const page = await call(port, "/chats", { headers: { Cookie: cookie } });
  const control = /name="0-control-token" content="([^"]+)"/.exec(page.text)?.[1];
  if (!control) throw new Error(`no control token: ${output}`);
  const owner = (path: string, init: { method?: string; body?: unknown } = {}) => call(port, path, { ...init, headers: { Cookie: cookie, "x-0-control-token": control } });
  return { owner, log: () => output };
}

describe("real server, scim license", () => {
  let server: Awaited<ReturnType<typeof startServer>>; const port = 48981;
  beforeAll(async () => { server = await startServer(port, makeTestLicense(["rbac", "scim"])); }, 120_000);

  it("answers an identity provider with its own token, in front of the sign-in gate", async () => {
    // No token: a SCIM error, not the login page and not a redirect.
    const anonymous = await call(port, "/scim/v2/Users");
    expect(anonymous.status).toBe(401); expect(anonymous.headers["content-type"]).toContain("application/scim+json"); expect(anonymous.json().schemas).toEqual(["urn:ietf:params:scim:api:messages:2.0:Error"]);
    // A browser session is not a SCIM credential.
    expect((await server.owner("/scim/v2/Users")).status).toBe(401);

    const made = await server.owner("/api/team/scim-tokens", { method: "POST", body: { name: "okta" } });
    expect(made.status).toBe(201);
    const token = made.json().token as string;
    expect((await server.owner("/api/team/scim-tokens")).text).not.toContain(token);
    const idp = (path: string, init: { method?: string; body?: unknown } = {}) => call(port, `/scim/v2${path}`, { ...init, headers: { Authorization: `Bearer ${token}` } });

    const created = await idp("/Users", { method: "POST", body: { schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"], userName: "pat@example.com", name: { givenName: "Pat", familyName: "Lee" }, active: true } });
    expect(created.status).toBe(201);
    const id = created.json().id as string;
    expect((await idp(`/Users?filter=${encodeURIComponent('userName eq "pat@example.com"')}`)).json().totalResults).toBe(1);
    const group = await idp("/Groups", { method: "POST", body: { displayName: "sec-triage", members: [{ value: id }] } });
    expect(group.status).toBe(201);
    const members = (await server.owner("/api/team/users")).json().users as Array<{ userId: string; role: string }>;
    expect(members.find(member => member.userId === id)?.role).toBe("triager");

    const disabled = await idp(`/Users/${id}`, { method: "PATCH", body: { schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], Operations: [{ op: "Replace", path: "active", value: "False" }] } });
    expect(disabled.json().active).toBe(false);
    const log = (await server.owner("/api/console/audit-log?q=user.deprovisioned")).json() as { events: Array<{ action: string; actor: string }> };
    expect(log.events[0]).toMatchObject({ action: "user.deprovisioned", actor: "scim:okta" });

    // Revoking the token locks the identity provider out.
    const tokenId = ((await server.owner("/api/team/scim-tokens")).json().tokens as Array<{ id: string }>)[0]!.id;
    expect((await server.owner(`/api/team/scim-tokens/${tokenId}`, { method: "DELETE" })).status).toBe(200);
    expect((await idp("/Users")).status).toBe(401);
  });
});

describe("real server, no scim license", () => {
  let server: Awaited<ReturnType<typeof startServer>>; const port = 48982;
  beforeAll(async () => { server = await startServer(port, makeTestLicense(["rbac"])); }, 120_000);

  it("refuses SCIM and token creation with a message that says what is needed", async () => {
    const made = await server.owner("/api/team/scim-tokens", { method: "POST", body: { name: "okta" } });
    expect(made.status).toBe(403); expect(made.text).toContain("does not include");
    // A caller still has to present a valid token before the license is even mentioned.
    const denied = await call(port, "/scim/v2/Users", { headers: { Authorization: "Bearer scim_anything" } });
    expect(denied.status).toBe(401);
  });
});
