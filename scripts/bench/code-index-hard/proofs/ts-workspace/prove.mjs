#!/usr/bin/env node
// Proof that every planted bug in fixtures/ts-workspace is real and reachable, and that the decoys and the generated
// filler modules deny what they should. Runs the real Express 5 app in-process (no model, no network).
//   node scripts/bench/code-index-hard/proofs/ts-workspace/prove.mjs
// Needs esbuild and express from the repo's pnpm store (pnpm install at the repo root). Output: one line per case.
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../../../..");
const fixture = resolve(here, "../../fixtures/ts-workspace");

function findExpress() {
  if (process.env.EXPRESS_DIR) return process.env.EXPRESS_DIR;
  const store = join(repoRoot, "node_modules/.pnpm");
  const hit = existsSync(store) ? readdirSync(store).find((n) => /^express@5\./.test(n)) : undefined;
  return hit ? join(store, hit, "node_modules/express") : undefined;
}
const expressDir = findExpress();
if (!expressDir || !existsSync(expressDir)) { console.error("express 5 not found in node_modules/.pnpm (run pnpm install) and EXPRESS_DIR is not set"); process.exit(2); }
const esbuild = await import("esbuild");

const work = mkdtempSync(join(tmpdir(), "tw-proof-"));
const uploads = join(work, "site", "uploads");
process.env.UPLOAD_ROOT = uploads;
mkdirSync(join(work, "node_modules"), { recursive: true });
symlinkSync(expressDir, join(work, "node_modules", "express"));
writeFileSync(join(work, "entry.ts"), `export { createApp } from ${JSON.stringify(join(fixture, "src/app"))};\nexport { seed } from ${JSON.stringify(join(fixture, "src/seed"))};\n`);
await esbuild.build({ entryPoints: [join(work, "entry.ts")], outfile: join(work, "bundle.mjs"), bundle: true, platform: "node", format: "esm", external: ["express"], logLevel: "error" });
const { createApp, seed } = await import(pathToFileURL(join(work, "bundle.mjs")).href);
seed();
const server = createApp().listen(0);
const base = `http://127.0.0.1:${server.address().port}`;

async function call(who, method, path, { body, headers = {} } = {}) {
  const h = { ...headers };
  if (who) h.authorization = `Bearer ${tokens[who]}`;
  if (body !== undefined) h["content-type"] = "application/json";
  const res = await fetch(base + path, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { /* text */ }
  return { status: res.status, text, json };
}
const tokens = {};
for (const [name, pass] of [["alice", "pw-alice"], ["bob", "pw-bob"], ["carol", "pw-carol"], ["dave", "pw-dave"], ["root", "pw-root"]]) {
  tokens[name] = (await call(null, "POST", "/api/auth/login", { body: { email: `${name}@${name === "alice" || name === "bob" ? "acme" : name === "root" ? "platform" : "globex"}.test`, passcode: pass } })).json.token;
}

const results = [];
let failed = 0;
const record = (id, kind, ok, detail) => { results.push({ id, kind, ok }); if (!ok) failed++; console.log(`${ok ? "PASS" : "FAIL"} ${kind.padEnd(8)} ${id}${ok ? "" : `  -> ${detail}`}`); };
const check = (id, ok, detail) => record(id, "CHECK", ok, detail);
const exploit = (id, ok, detail) => record(id, "EXPLOIT", ok, detail);
const denies = (id, r, allowed = [401, 403, 404]) => record(id, "DENIED", allowed.includes(r.status), `status ${r.status}`);

// Attackers: dave (member of globex) and carol (manager of globex) against acme data; the same-org member is bob.

// tw-task-history
{
  const r = await call("dave", "GET", "/api/tasks/tsk_a2/history");
  exploit("tw-task-history: another organisation's task history", r.status === 200 && r.text.includes("term sheet"), `status ${r.status}`);
  for (const sub of ["", "/comments", "/attachments", "/watchers", "/subtasks", "/time"]) denies(`tw-task-history sibling GET /api/tasks/tsk_a2${sub}`, await call("dave", "GET", `/api/tasks/tsk_a2${sub}`));
}
// tw-invoice-pdf
{
  const r = await call("dave", "GET", "/api/invoices/inv_a1/pdf");
  exploit("tw-invoice-pdf: another organisation's invoice document", r.status === 200 && r.text.includes("margin 38 percent"), `status ${r.status}`);
  denies("tw-invoice-pdf sibling GET /api/invoices/inv_a1", await call("dave", "GET", "/api/invoices/inv_a1"));
  denies("tw-invoice-pdf sibling GET /api/invoices/inv_a1/lines", await call("dave", "GET", "/api/invoices/inv_a1/lines"));
}
// tw-webhook-deliveries
{
  const r = await call("bob", "GET", "/api/webhooks/whk_a1/deliveries");
  exploit("tw-webhook-deliveries: member reads the webhook auth token", r.status === 200 && r.text.includes("Bearer acme-hook-token-9f3a"), `status ${r.status}`);
  denies("tw-webhook-deliveries sibling POST rotate as member", await call("bob", "POST", "/api/webhooks/whk_a1/rotate"));
  denies("tw-webhook-deliveries other organisation's deliveries", await call("dave", "GET", "/api/webhooks/whk_a1/deliveries"));
  const list = await call("bob", "GET", "/api/webhooks");
  check("tw-d-webhook-list: summaries without the token", list.status === 200 && !list.text.includes("acme-hook-token"), list.text.slice(0, 80));
}
// tw-public-export
{
  const r = await call(null, "GET", "/public/boards/acme-roadmap/export");
  exploit("tw-public-export: anonymous reads private tasks", r.status === 200 && r.text.includes("term sheet draft"), `status ${r.status}`);
  const view = await call(null, "GET", "/public/boards/acme-roadmap");
  check("tw-d-board-public: view shows only public tasks", view.status === 200 && !view.text.includes("Acquisition") && view.text.includes("Launch checklist"), view.text.slice(0, 80));
  denies("tw-d-board-public: unpublished board export", await call(null, "GET", "/public/boards/globex-fleet/export"));
  denies("tw-d-internal-export: no service token", await call(null, "GET", "/api/internal/exports/prj_acme"));
  check("tw-d-internal-export: service token works", (await call(null, "GET", "/api/internal/exports/prj_acme", { headers: { "x-service-token": "svc-dev-token" } })).status === 200, "");
  denies("tw-d-project-export: other organisation", await call("dave", "GET", "/api/projects/prj_acme/export"));
}
// tw-billing-org-header
{
  const plan = await call("carol", "GET", "/api/billing/plan", { headers: { "x-org-id": "org_acme" } });
  const inv = await call("carol", "GET", "/api/billing/invoices", { headers: { "x-org-id": "org_acme" } });
  exploit("tw-billing-org-header: another organisation's plan and card", plan.status === 200 && plan.text.includes("4242"), `status ${plan.status}`);
  exploit("tw-billing-org-header: another organisation's invoices", inv.status === 200 && inv.text.includes("ACM-0042"), `status ${inv.status}`);
  denies("tw-billing-org-header sibling: same header on a resolveOrg route", await call("carol", "GET", "/api/labels", { headers: { "x-org-id": "org_acme" } }), [403]);
  const usage = await call("carol", "GET", "/api/billing/usage", { headers: { "x-org-id": "org_acme" } });
  check("tw-d-billing-usage: ignores the header", usage.status === 200 && usage.json.seats === 8, usage.text);
}
// tw-attachment-filename
{
  const r = await call("dave", "POST", "/api/tasks/tsk_g2/attachments", { body: { filename: "../../../pwned.txt", content: "owned" } });
  exploit("tw-attachment-filename: write outside the upload root", r.status === 201 && existsSync(join(work, "site", "pwned.txt")), `status ${r.status}`);
  const ok = await call("dave", "POST", "/api/tasks/tsk_g2/attachments", { body: { filename: "<b>notes</b>.txt", content: "fine" } });
  check("tw-d-comment-display / cleanName still strips markup", ok.status === 201 && !/[<>]/.test(ok.json.filename), ok.text);
  denies("tw-d-attachment-download: other organisation", await call("alice", "GET", `/api/attachments/${ok.json.id}/download`));
}
// tw-search-comments
{
  const r = await call("dave", "GET", "/api/search?q=escrow");
  exploit("tw-search-comments: another organisation's comments", r.status === 200 && r.json.comments.length === 1, r.text);
  const t = await call("dave", "GET", "/api/search?q=Acquisition");
  check("tw-d-search-scoped: tasks stay scoped", t.status === 200 && t.json.tasks.length === 0, t.text);
}
// tw-comment-author
{
  const r = await call("dave", "POST", "/api/tasks/tsk_g2/comments", { body: { authorId: "usr_carol", body: "approved by carol" } });
  exploit("tw-comment-author: post as another user", r.status === 201 && r.json.authorId === "usr_carol", r.text);
  const own = await call("dave", "POST", "/api/tasks/tsk_g2/comments", { body: { body: "plain" } });
  check("tw-comment-author control: default author is the caller", own.status === 201 && own.json.authorId === "usr_dave", own.text);
  denies("tw-d-integration-comment: no service token", await call(null, "POST", "/api/internal/integrations/slack/comments", { body: { taskId: "tsk_a1", authorEmail: "alice@acme.test", text: "x" } }));
  const wrong = await call(null, "POST", "/api/internal/integrations/slack/comments", { body: { taskId: "tsk_a1", authorEmail: "dave@globex.test", text: "x" }, headers: { "x-service-token": "svc-dev-token" } });
  denies("tw-d-integration-comment: author of another organisation", wrong, [400]);
}
// tw-task-move
{
  denies("tw-task-move sibling: create in another organisation's project", await call("dave", "POST", "/api/tasks", { body: { projectId: "prj_acme", title: "x" } }));
  const r = await call("dave", "POST", "/api/tasks/tsk_g2/move", { body: { projectId: "prj_acme" } });
  const seen = await call("alice", "GET", "/api/projects/prj_acme/tasks");
  exploit("tw-task-move: task lands in another organisation's project", r.status === 200 && r.json.orgId === "org_acme" && seen.text.includes("tsk_g2"), r.text);
}
// decoys without a planted twin
{
  const share = await call("alice", "POST", "/api/invoices/inv_a1/share");
  const pub = await call(null, "GET", `/public/invoices/${share.json?.token}`);
  check("tw-d-public-invoice: own link opens its invoice", pub.status === 200 && pub.json.number === "ACM-0042" && !pub.text.includes("margin"), pub.text.slice(0, 80));
  denies("tw-d-public-invoice: tampered token", await call(null, "GET", `/public/invoices/${share.json?.token}x`));
  denies("tw-d-invoice-share: member cannot issue", await call("bob", "POST", "/api/invoices/inv_a1/share"));
  denies("tw-d-internal-invoice: no service token", await call(null, "GET", "/api/internal/invoices/inv_a1"));
  denies("tw-d-ops-flags: member", await call("dave", "GET", "/api/ops/flags"));
  denies("tw-d-ops-flags: upper-case path, inline check holds", await call("dave", "GET", "/API/OPS/flags"));
  const reg = await call(null, "POST", "/api/auth/register", { body: { name: "Eve", email: "eve@evil.test", passcode: "x", orgName: "Evil", role: "admin" } });
  const me = await call(null, "GET", "/api/me", { headers: { authorization: `Bearer ${reg.json.token}` } });
  check("tw-d-register: role from the body is ignored", me.json?.role === "manager", me.text);
  const upd = await call("dave", "PUT", "/api/me", { body: { name: "Dave <b>D</b>", role: "admin" } });
  check("tw-d-me-update: self only, role untouched", upd.status === 200 && (await call("dave", "GET", "/api/me")).json.role === "member", upd.text);
  denies("tw-d-task-require: cross-organisation task update", await call("carol", "PUT", "/api/tasks/tsk_a1", { body: { title: "x" } }));
}
// tw-security-case (last: it promotes dave)
{
  denies("tw-security-case control: /api/admin/users as member", await call("dave", "GET", "/api/admin/users"));
  const list = await call("dave", "GET", "/API/ADMIN/users");
  exploit("tw-security-case: admin user list through an upper-case path", list.status === 200 && list.text.includes("usr_root"), `status ${list.status}`);
  const promote = await call("dave", "PUT", "/Api/Admin/users/usr_dave/role", { body: { role: "admin" } });
  const me = await call("dave", "GET", "/api/me");
  exploit("tw-security-case: self promotion to admin", promote.status === 200 && me.json.role === "admin", promote.text);
}
// every generated filler route denies the cross-organisation manager and the same-organisation non-owner
{
  const manifest = JSON.parse(readFileSync(join(here, "filler-routes.json"), "utf8"));
  let bad = 0;
  for (const m of manifest) {
    const cross = await call("carol", m.method, m.path, m.body === undefined ? {} : { body: m.body });
    const member = await call("bob", m.method, m.path, m.body === undefined ? {} : { body: m.body });
    if (!m.crossOrgManager.includes(cross.status) || !m.sameOrgMember.includes(member.status)) { bad++; console.log(`FAIL FILLER   ${m.method} ${m.path}: cross ${cross.status} (want ${m.crossOrgManager}), member ${member.status} (want ${m.sameOrgMember})`); }
  }
  check(`filler sweep: ${manifest.length} routes in ${new Set(manifest.map((m) => m.module)).size} modules deny a cross-organisation manager and a same-organisation non-owner`, bad === 0, `${bad} unexpected`);
  const lists = await Promise.all([...new Set(manifest.map((m) => m.path.split("/")[2]))].map((p) => call("carol", "GET", `/api/${p}`)));
  check("filler sweep: no list leaks the other organisation's records", lists.every((r) => r.status === 200 && !r.text.includes("org_acme")), "a list contained org_acme rows");
}

server.close();
rmSync(work, { recursive: true, force: true });
const exploits = results.filter((r) => r.kind === "EXPLOIT");
console.log(`\n${results.length} checks, ${failed} failed; ${exploits.filter((r) => r.ok).length}/${exploits.length} exploit checks succeeded`);
process.exit(failed ? 1 : 0);
