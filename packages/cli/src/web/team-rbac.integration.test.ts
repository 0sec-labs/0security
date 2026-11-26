// Spawns the real CLI in team mode over a real temp SQLite file, signs in as each role and calls the real HTTP routes.
// The license is a throwaway one signed in the test with a key made in the test. The production key is not involved.
import { spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { osecDB } from "@0/engine/storage";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

vi.setConfig({ testTimeout: 60_000 });
import { hashTeamPassword } from "./team-auth.js";
import { makeTestLicense, writeLicenseShim } from "./__fixtures__/test-license.js";

const entry = fileURLToPath(new URL("../index.ts", import.meta.url));
const cwd = fileURLToPath(new URL("../..", import.meta.url));
const enterpriseEntry = fileURLToPath(new URL("../../../../enterprise/dist/index.js", import.meta.url));
const PASSWORD = "integration-password-1";

interface Reply { status: number; text: string; json: () => any }
function call(port: number, path: string, init: { method?: string; headers?: Record<string, string>; body?: unknown } = {}): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const body = init.body === undefined ? undefined : JSON.stringify(init.body);
    const req = request({ host: "127.0.0.1", port, path, method: init.method ?? "GET", headers: { Host: `127.0.0.1:${port}`, Origin: `http://127.0.0.1:${port}`, ...(body ? { "Content-Type": "application/json" } : {}), ...init.headers } }, res => {
      const chunks: Buffer[] = []; res.on("data", c => chunks.push(c as Buffer));
      res.on("end", () => { const text = Buffer.concat(chunks).toString(); resolve({ status: res.statusCode ?? 0, text, json: () => JSON.parse(text) as unknown, ...(res.headers["set-cookie"] ? { cookie: String(res.headers["set-cookie"]).split(";")[0] } : {}) } as Reply & { cookie?: string }); });
    });
    req.on("error", reject); req.end(body);
  });
}

interface Running { child: ChildProcess; port: number; log: () => string; as: (user: string) => Promise<(path: string, init?: { method?: string; body?: unknown }) => Promise<Reply>> }
const running: Running[] = [];
afterAll(() => { for (const server of running) server.child.kill("SIGKILL"); });

async function startServer(port: number, license?: ReturnType<typeof makeTestLicense>): Promise<Running> {
  const home = mkdtempSync(join(tmpdir(), "zero-rbac-http-"));
  const assets = join(home, "assets"); mkdirSync(assets);
  writeFileSync(join(assets, "index.html"), "<!doctype html><html><head><title>t</title></head><body>app</body></html>");
  const hash = await hashTeamPassword(PASSWORD);
  const users = [["owner", "owner"], ["viewer", "viewer"], ["triager", "triager"], ["auditor", "auditor"], ["scoped", "payments-triager"]].map(([id, role]) => ({ id, name: id, role, passwordHash: hash }));
  const teamConfig = join(home, "team.json");
  writeFileSync(teamConfig, JSON.stringify({
    workspace: { id: `rbac-http-${port}`, name: "RBAC HTTP" }, users,
    roles: { "payments-triager": { permissions: ["findings.read", "findings.triage"], scope: { businessUnits: ["payments"] } } },
    businessUnits: { payments: ["acme/pay-*"] },
  }), { mode: 0o600 });
  const dbPath = join(home, "data.db");
  const db = new osecDB(dbPath);
  const finding = (id: string) => ({ id, templateId: "t", title: id, description: "d", severity: "high", category: "denial-of-service", status: "discovered", evidence: { request: "a", response: "b" }, timestamp: Date.now() });
  for (const target of ["https://github.com/acme/pay-api", "https://github.com/acme/web"]) {
    const scanId = db.createScan({ target, depth: "full" } as unknown as Parameters<typeof db.createScan>[0]);
    db.saveFinding(scanId, finding(`finding-${target.split("/").pop()}`) as unknown as Parameters<typeof db.saveFinding>[1]);
  }
  db.close();
  let output = "";
  // The child trusts the throwaway key through a loader hook in this test's own temp folder, never through the environment.
  const shim = license ? writeLicenseShim(join(home, "shim"), license.publicKeys, enterpriseEntry) : [];
  const child = spawn(process.execPath, ["--import", "tsx", ...shim, entry, "web", "--port", String(port), "--host", "127.0.0.1", "--asset-dir", assets, "--no-open", "--team-config", teamConfig, "--db-path", dbPath], { cwd, env: { ...process.env, HOME: home, DO_NOT_TRACK: "1", ZERO_LICENSE: "", ZERO_LICENSE_FILE: "", ...(license?.env ?? {}) } });
  child.stdout!.on("data", d => { output += String(d); }); child.stderr!.on("data", d => { output += String(d); });
  const deadline = Date.now() + 90_000;
  while (!output.includes("ZERO_DASHBOARD_READY") && Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`server exited early: ${output}`);
    await new Promise(r => setTimeout(r, 100));
  }
  const page = await call(port, "/");
  const control = /name="0-control-token" content="([^"]+)"/.exec(page.text)?.[1];
  if (!control) throw new Error(`no control token in the page: ${output}`);
  const server: Running = {
    child, port, log: () => output,
    async as(user) {
      const login = await call(port, "/api/team/auth/login", { method: "POST", headers: { "x-0-control-token": control }, body: { userId: user, password: PASSWORD } }) as Reply & { cookie?: string };
      if (login.status !== 200) throw new Error(`login as ${user} failed: ${login.status} ${login.text}`);
      return (path, init = {}) => call(port, path, { ...init, headers: { Cookie: login.cookie!, "x-0-control-token": control } });
    },
  };
  running.push(server);
  return server;
}

describe("real server, licensed", () => {
  let server: Running;
  beforeAll(async () => { server = await startServer(48971, makeTestLicense(["rbac"])); }, 120_000);

  it("enforces the permission of each role on the real routes", async () => {
    const viewer = await server.as("viewer"); const triager = await server.as("triager"); const auditor = await server.as("auditor"); const owner = await server.as("owner");
    expect((await viewer("/api/dashboard")).status).toBe(200);
    expect((await viewer("/api/finding-family/nothing/triage", { method: "POST", body: { triageStatus: "accepted" } })).status).toBe(403);
    // A triager gets past the permission check (the family does not exist, so the handler answers, not the gate).
    const triage = await triager("/api/finding-family/nothing/triage", { method: "POST", body: { triageStatus: "accepted" } });
    expect(triage.status).not.toBe(403); expect(triage.status).not.toBe(401);
    expect((await triager("/api/console/sessions", { method: "POST", body: {} })).status).toBe(403);
    expect((await triager("/api/console/settings", { method: "PATCH", body: {} })).status).toBe(403);
    // The auditor reads findings and the audit log and nothing else.
    expect((await auditor("/api/dashboard")).status).toBe(200);
    expect((await auditor("/api/console/audit-log")).status).toBe(200);
    for (const path of ["/api/console/sessions", "/api/console/settings", "/api/skills", "/api/work"]) expect((await auditor(path)).status, path).toBe(403);
    expect((await viewer("/api/console/audit-log")).status).toBe(403);
    // The owner reads the audit log, and a route with no rule is refused even for the owner.
    expect((await owner("/api/console/audit-log")).status).toBe(200);
    const unknown = await owner("/api/brand-new-route");
    expect(unknown.status).toBe(403); expect(unknown.text).toContain("no permission rule");
  });

  it("needs a signed-in account for every route", async () => {
    const page = await call(server.port, "/");
    const control = /name="0-control-token" content="([^"]+)"/.exec(page.text)![1]!;
    for (const path of ["/api/dashboard", "/api/console/audit-log", "/api/team/roles", "/api/brand-new-route"]) expect((await call(server.port, path, { headers: { "x-0-control-token": control } })).status, path).toBe(401);
  });

  it("changes a role over HTTP, applies it at once and records it in the audit log the auditor reads", async () => {
    const owner = await server.as("owner"); const viewer = await server.as("viewer"); const auditor = await server.as("auditor");
    expect((await viewer("/api/finding-family/nothing/triage", { method: "POST", body: { triageStatus: "accepted" } })).status).toBe(403);
    expect((await viewer("/api/team/users/viewer", { method: "PATCH", body: { role: "owner" } })).status).toBe(403);
    const changed = await owner("/api/team/users/viewer", { method: "PATCH", body: { role: "triager" } });
    expect(changed.status).toBe(200); expect(changed.json().user).toMatchObject({ userId: "viewer", role: "triager" });
    expect((await viewer("/api/finding-family/nothing/triage", { method: "POST", body: { triageStatus: "accepted" } })).status).not.toBe(403);
    const log = (await auditor("/api/console/audit-log?q=user.role_changed")).json() as { events: Array<{ action: string; subject: string; actor: string; detail: Record<string, unknown> }> };
    const entry = log.events.find(event => event.action === "user.role_changed");
    expect(entry).toMatchObject({ subject: "viewer", actor: "operator owner (browser)", detail: { old: "viewer", new: "triager", source: "admin" } });
    const roles = (await owner("/api/team/roles")).json() as { licensed: boolean; roles: Array<{ name: string }> };
    expect(roles.licensed).toBe(true); expect(roles.roles.map(role => role.name)).toContain("auditor");
    await owner("/api/team/users/viewer", { method: "PATCH", body: { role: "viewer" } });
  });

  it("shows a scoped account only the findings of its repositories", async () => {
    const scoped = await server.as("scoped"); const owner = await server.as("owner"); const auditor = await server.as("auditor");
    const all = (await owner("/api/dashboard")).json() as { scans: Array<{ target: string }>; groups: unknown[] };
    expect(all.scans.map(scan => scan.target).sort()).toEqual(["https://github.com/acme/pay-api", "https://github.com/acme/web"]);
    const mine = (await scoped("/api/dashboard")).json() as { scans: Array<{ id: string; target: string }>; groups: unknown[]; workers: unknown[] };
    expect(mine.scans.map(scan => scan.target)).toEqual(["https://github.com/acme/pay-api"]);
    expect(mine.groups).toHaveLength(1); expect(all.groups).toHaveLength(2);
    expect(((await scoped("/api/scans")).json() as { scans: unknown[] }).scans).toHaveLength(1);
    const other = all.scans.find(scan => scan.target.endsWith("/web")) as unknown as { id: string };
    const own = mine.scans[0]!;
    expect((await scoped(`/api/scans/${encodeURIComponent(own.id)}`)).status).toBe(200);
    expect((await scoped(`/api/scans/${encodeURIComponent(other.id)}`)).status).toBe(404);
    expect((await scoped(`/api/scans/${encodeURIComponent(other.id)}/findings`)).status).toBe(404);
    expect((await scoped("/api/findings/export")).status).toBe(403);
    expect((await scoped("/api/work")).status).toBe(403);
    // The event stream is not filtered by repository, so a scoped account never gets it.
    expect((await scoped("/api/v1/presentation/events")).status).toBe(403);
    // Rewriting /api/backends/local/proxy/... to a local route must not bypass RBAC or repository scope checks.
    expect((await scoped("/api/backends/local/proxy/api/findings/export")).status).toBe(403);
    expect((await scoped("/api/backends/local/proxy/api/work")).status).toBe(403);
    expect((await scoped("/api/backends/local/proxy/api/v1/presentation/events")).status).toBe(403);
    expect((await auditor("/api/backends/local/proxy/api/work")).status).toBe(403);
  });
});

describe("real server, no license", () => {
  let server: Running;
  beforeAll(async () => { server = await startServer(48972); }, 120_000);

  it("keeps the three fixed roles and refuses the paid ones", async () => {
    const owner = await server.as("owner"); const triager = await server.as("triager"); const auditor = await server.as("auditor");
    // Other roles count as the nearest free role: read-only.
    expect((await triager("/api/finding-family/nothing/triage", { method: "POST", body: { triageStatus: "accepted" } })).status).toBe(403);
    expect((await auditor("/api/console/sessions")).status).toBe(200);
    expect((await auditor("/api/console/audit-log")).status).toBe(403);
    expect((await owner("/api/console/audit-log")).status).toBe(200);
    // No table: a route nobody listed is not refused by the permission check.
    expect((await owner("/api/brand-new-route")).status).toBe(404);
    const change = await owner("/api/team/users/triager", { method: "PATCH", body: { role: "editor" } });
    expect(change.status).toBe(403); expect(change.text).toContain("enterprise license");
    expect((await owner("/api/team/roles")).json().licensed).toBe(false);
  });

  it("keeps a scope in force without a license", async () => {
    const scoped = await server.as("scoped");
    const mine = (await scoped("/api/dashboard")).json() as { scans: Array<{ target: string }> };
    expect(mine.scans.map(scan => scan.target)).toEqual(["https://github.com/acme/pay-api"]);
    expect((await scoped("/api/findings/export")).status).toBe(403);
    expect((await scoped("/api/backends/local/proxy/api/findings/export")).status).toBe(403);
  });
});
