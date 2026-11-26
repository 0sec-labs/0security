#!/usr/bin/env node
// Proof for the variants-tenant fixture. Bundles the fixture with esbuild (into the OS temp dir), runs the real Express 5
// app in-process and checks over HTTP that: the seed route denies cross-org reads, each of the 8 siblings hands org A's
// data to a user of org B, every look-alike denies or returns only permitted data, and every ordinary CRUD route
// denies cross-org access. Exit code is non-zero on any failure.
import { createHmac } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { makeClient, runCases } from "./lib.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const fixtureDir = resolve(here, "../../variants/variants-tenant");
const manifest = JSON.parse(readFileSync(join(here, "manifest.json"), "utf8"));

function findUp(start, rel) {
  for (let dir = start; ; dir = dirname(dir)) {
    const hit = join(dir, rel);
    if (existsSync(hit)) return hit;
    if (dirname(dir) === dir) return null;
  }
}

const pnpmDir = findUp(here, "node_modules/.pnpm");
const expressDir = pnpmDir && readdirSync(pnpmDir).filter((d) => /^express@5\./.test(d)).sort().map((d) => join(pnpmDir, d, "node_modules/express"))[0];
if (!expressDir || !existsSync(expressDir)) {
  console.error("express 5 not found in node_modules/.pnpm (run pnpm install at the repo root)");
  process.exit(2);
}
const esbuildEntry = findUp(here, "node_modules/esbuild/lib/main.js");
if (!esbuildEntry) {
  console.error("esbuild not found in node_modules (run pnpm install at the repo root)");
  process.exit(2);
}
const esbuild = createRequire(esbuildEntry)(esbuildEntry);
const expressEntry = createRequire(join(expressDir, "package.json")).resolve(expressDir);

const secrets = {
  TENANTLY_TOKEN_SECRET: "proof-token-secret",
  TENANTLY_SHARE_SECRET: "proof-share-secret",
  TENANTLY_WEBHOOK_SECRET: "proof-webhook-secret",
  TENANTLY_SERVICE_TOKEN: "proof-service-token",
  TENANTLY_SEED_PASSWORD: "proof-password",
};
Object.assign(process.env, secrets);

const work = mkdtempSync(join(tmpdir(), "variants-tenant-proof-"));
let server;
let failures = 1;
try {
  const outfile = join(work, "app.mjs");
  await esbuild.build({
    entryPoints: [join(fixtureDir, "src/app.ts")],
    outfile,
    bundle: true,
    platform: "node",
    format: "esm",
    logLevel: "silent",
    plugins: [{ name: "express-5", setup: (b) => b.onResolve({ filter: /^express$/ }, () => ({ path: expressEntry, external: true })) }],
  });
  const { createApp } = await import(pathToFileURL(outfile).href);
  server = createApp().listen(0);
  await new Promise((r) => server.once("listening", r));
  const base = "http://127.0.0.1:" + server.address().port;
  const http = makeClient(base);

  const login = async (email) => {
    const res = await http("POST", "/api/auth/login", { body: { email, password: secrets.TENANTLY_SEED_PASSWORD } });
    if (res.status !== 200) throw new Error("login failed for " + email);
    return res.json.token;
  };
  const alice = await login("alice@alpha.example"); // org A admin
  const bob = await login("bob@beta.example"); // org B member
  const bea = await login("bea@beta.example"); // org B admin

  const hmac = (data) => createHmac("sha256", secrets.TENANTLY_WEBHOOK_SECRET).update(data).digest("hex");
  const poll = async (path, token) => {
    for (let i = 0; i < 50; i++) {
      const res = await http("GET", path, { token });
      if (res.json?.status === "done" || res.json?.status === "failed") return res;
      await new Promise((r) => setTimeout(r, 10));
    }
    throw new Error("job did not finish");
  };
  const realtime = async (token, channel) => {
    const opened = await http("POST", "/rt/sessions", { token });
    const sid = opened.json.sessionId;
    await http("POST", "/rt/sessions/" + sid + "/messages", { token, body: { type: "subscribe", channel } });
    return (await http("GET", "/rt/sessions/" + sid + "/events", { token })).json.events;
  };
  const gql = (token, query) => http("POST", "/graphql", { token, body: { query } });
  const has = (value, needle) => JSON.stringify(value ?? "").includes(needle);

  const cases = [];
  const add = (group, name, fn) => cases.push({ group, name, fn });
  const ok = (cond, msg) => { if (!cond) throw new Error(msg); };

  // control: the data is real and the owner can read it
  add("control", "org A reads its own invoice", async () => {
    const r = await http("GET", "/api/invoices/inv_a1", { token: alice });
    ok(r.status === 200 && r.json.number === "INV-A-1001", "owner could not read inv_a1");
  });

  // seed
  add("seed", "GET /api/invoices/:id denies org B reading org A's invoice", async () => {
    const r = await http("GET", "/api/invoices/inv_a1", { token: bob });
    ok(r.status === 404 && !has(r.json, "INV-A-1001"), "cross-org invoice read was not denied: " + r.status);
  });

  // siblings
  add("sibling", "vt-contract-service: GET /api/contracts/:id returns org A's contract", async () => {
    const r = await http("GET", "/api/contracts/con_a1", { token: bob });
    ok(r.status === 200 && r.json.title === "Master services agreement", "contract not returned: " + r.status);
  });
  add("sibling", "vt-contract-service: GET /api/contracts/:id/summary returns org A's terms", async () => {
    const r = await http("GET", "/api/contracts/con_a1/summary", { token: bob });
    ok(r.status === 200 && has(r.json.terms, "12 percent uplift"), "contract summary not returned: " + r.status);
  });
  add("sibling", "vt-quote-pdf: GET /api/quotes/:id/pdf renders org A's quote", async () => {
    const r = await http("GET", "/api/quotes/quo_a1/pdf", { token: bob });
    ok(r.status === 200 && r.text.includes("Warehouse automation phase 2") && r.text.includes("Floor price is 14000"), "quote pdf not returned: " + r.status);
  });
  add("sibling", "vt-reminder-job: reminder job mails org A's invoice to a chosen address", async () => {
    const queued = await http("POST", "/api/reminders", { token: bob, body: { invoiceId: "inv_a1", to: "bob@beta.example" } });
    ok(queued.status === 202, "job not accepted: " + queued.status);
    const done = await poll("/api/reminders/jobs/" + queued.json.jobId, bob);
    ok(done.json.status === "done" && has(done.json.result?.subject, "INV-A-1001") && has(done.json.result?.body, "Harbor Logistics") && has(done.json.result?.body, "4200"), "job result lacks org A data: " + JSON.stringify(done.json));
  });
  add("sibling", "vt-graphql-subscription: subscription(id) returns org A's subscription", async () => {
    const r = await gql(bob, '{ subscription(id: "sub_a1") { id seats monthlyAmount paymentMethodLast4 } }');
    ok(r.status === 200 && r.json.data.subscription?.paymentMethodLast4 === "4242" && r.json.data.subscription.seats === 25, "graphql did not return sub_a1: " + r.text);
  });
  add("sibling", "vt-ws-ticket-subscribe: subscribe ticket:<id> delivers org A's ticket", async () => {
    const events = await realtime(bob, "ticket:tkt_a1");
    const snap = events.find((e) => e.type === "snapshot");
    ok(snap && snap.data.ticket.subject === "Refund dispute on the March order" && has(snap.data.comments, "Carrier photos requested"), "no snapshot of tkt_a1: " + JSON.stringify(events));
  });
  add("sibling", "vt-import-product: import preview returns org A's product price and cost", async () => {
    const csv = "customerId,productId,quantity\ncus_b1,prd_a1,3\n";
    const r = await http("POST", "/api/imports/orders/preview", { token: bob, body: { csv } });
    const row = r.json?.rows?.[0];
    ok(r.status === 200 && row && row.name === "Pallet jack" && row.unitCost === 280 && row.unitPrice === 450, "preview lacks prd_a1: " + r.text);
  });
  add("sibling", "vt-report-shipment: cost report returns org A's shipment margin", async () => {
    const r = await http("GET", "/api/reports/shipments/shp_a1/costs", { token: bob });
    ok(r.status === 200 && r.json.carrier === "Fastline" && r.json.cost === 182.4 && r.json.margin > 57, "shipment cost report not returned: " + r.status);
  });
  add("sibling", "vt-payment-webhook: replayed timestamp signature settles org A's invoice", async () => {
    const before = await http("GET", "/api/invoices/inv_a1", { token: alice });
    ok(before.json.status === "open", "inv_a1 was not open before the call");
    const ts = String(Math.floor(Date.now() / 1000));
    const headers = { "x-pay-timestamp": ts, "x-pay-signature": hmac(ts) };
    const body = { event: "payment.settled", accountId: "acct_beta", invoiceId: "inv_a1", reference: "replayed" };
    const r = await http("POST", "/integrations/payments", { headers, body });
    ok(r.status === 200 && r.json.invoice?.number === "INV-A-1001", "webhook did not return inv_a1: " + r.text);
    const after = await http("GET", "/api/invoices/inv_a1", { token: alice });
    ok(after.json.status === "paid" && after.json.paidReference === "replayed", "inv_a1 was not modified");
  });

  // look-alikes
  const denied = (path, token, label) =>
    add("decoy", label, async () => {
      const r = await http("GET", path, { token });
      ok(r.status === 404 || r.status === 401 || r.status === 403, "not denied: " + r.status + " " + r.text);
    });
  denied("/api/payments/pay_a1", bob, "vt-decoy-payments-inline: inline orgId comparison denies");
  denied("/api/credit-notes/cn_a1", bob, "vt-decoy-credit-notes: assertSameOrg denies");
  denied("/api/refunds/rfd_a1", bob, "vt-decoy-refunds-policy: policy object denies");
  add("decoy", "vt-decoy-invoice-void: assertSameOrg denies a cross-org void", async () => {
    const r = await http("POST", "/api/invoices/inv_a1/void", { token: bea });
    ok(r.status === 404, "void not denied: " + r.status);
    const inv = await http("GET", "/api/invoices/inv_a1", { token: alice });
    ok(inv.json.status !== "void", "invoice was voided");
  });
  add("decoy", "vt-decoy-invoice-share: share token cannot be minted for org A's invoice", async () => {
    const r = await http("POST", "/api/invoices/inv_a1/share", { token: bob });
    ok(r.status === 404 && !r.json?.token, "share token minted: " + r.status);
  });
  add("decoy", "vt-decoy-internal-invoice: service token required, user bearer rejected", async () => {
    const anon = await http("GET", "/api/internal/invoices/inv_a1", {});
    const user = await http("GET", "/api/internal/invoices/inv_a1", { token: bob });
    const wrong = await http("GET", "/api/internal/invoices/inv_a1", { headers: { "x-service-token": "nope" } });
    ok(anon.status === 401 && user.status === 401 && wrong.status === 401, "internal route reachable without the service token");
    const good = await http("GET", "/api/internal/invoices/inv_a1", { headers: { "x-service-token": secrets.TENANTLY_SERVICE_TOKEN } });
    ok(good.status === 200, "service token did not work: " + good.status);
  });
  add("decoy", "vt-decoy-public-invoice: share link works only for its own invoice and signature", async () => {
    const minted = await http("POST", "/api/invoices/inv_a1/share", { token: alice });
    const token = minted.json.token;
    const own = await http("GET", "/public/invoices/inv_a1?token=" + encodeURIComponent(token));
    ok(own.status === 200 && own.json.number === "INV-A-1001" && !("lines" in own.json), "valid link should show the permitted summary: " + own.status);
    const other = await http("GET", "/public/invoices/inv_b1?token=" + encodeURIComponent(token));
    const forged = await http("GET", "/public/invoices/inv_a1?token=" + encodeURIComponent(token.split(".")[0] + ".00"));
    const none = await http("GET", "/public/invoices/inv_a1");
    ok(other.status === 404 && forged.status === 404 && none.status === 404, "link accepted for the wrong invoice or signature");
  });
  add("decoy", "vt-decoy-reference: global currency/plan lookup returns only reference data", async () => {
    const cur = await http("GET", "/api/reference/currencies/eur", { token: bob });
    const plan = await http("GET", "/api/reference/plans/plan_pro", { token: bob });
    ok(cur.status === 200 && cur.json.id === "EUR" && plan.status === 200 && !("orgId" in plan.json), "reference lookup failed");
  });
  add("decoy", "vt-decoy-me: /api/me returns only the caller's own record", async () => {
    const r = await http("GET", "/api/me", { token: bob });
    ok(r.status === 200 && r.json.id === "usr_bob" && r.json.orgId === "org_b" && !has(r.json, "passwordHash"), "unexpected /api/me body");
  });
  add("decoy", "vt-decoy-renewal-job: job re-validates org and fails for org A's contract", async () => {
    const queued = await http("POST", "/api/contracts/con_a1/renewal-notice", { token: bob });
    const done = await poll("/api/reminders/jobs/" + queued.json.jobId, bob);
    ok(done.json.status === "failed" && !has(done.json, "Master services agreement"), "renewal job did not deny: " + JSON.stringify(done.json));
    const own = await http("POST", "/api/contracts/con_b1/renewal-notice", { token: bob });
    const ownDone = await poll("/api/reminders/jobs/" + own.json.jobId, bob);
    ok(ownDone.json.status === "done" && ownDone.json.result.title === "Studio retainer", "own renewal should work");
  });
  add("decoy", "vt-decoy-graphql-customer: loader returns null for org A's customer, data for own", async () => {
    const other = await gql(bob, '{ customer(id: "cus_a1") { id name email } }');
    ok(other.status === 200 && other.json.data.customer === null, "customer leaked through graphql: " + other.text);
    const own = await gql(bob, '{ customer(id: "cus_b1") { id name } }');
    ok(own.json.data.customer?.name === "Pine Studio", "own customer not returned");
  });
  add("decoy", "vt-decoy-ws-team: membership check denies team:<id> of org A", async () => {
    const other = await realtime(bob, "team:team_a1");
    ok(other.length === 1 && other[0].type === "error" && !has(other, "Collections"), "team subscribe not denied: " + JSON.stringify(other));
    const own = await realtime(bob, "team:team_b1");
    ok(own[0].type === "snapshot" && own[0].data.team.name === "Studio", "own team subscribe failed");
  });
  add("decoy", "vt-decoy-import-customer: customer ids of org A are rejected by the import", async () => {
    const csv = "customerId,productId,quantity\ncus_a1,prd_b1,1\n";
    const r = await http("POST", "/api/imports/orders/preview", { token: bob, body: { csv } });
    ok(r.json.rows.length === 0 && r.json.problems.length === 1 && !has(r.json, "Harbor"), "foreign customer accepted: " + r.text);
  });
  add("decoy", "vt-decoy-contract-for-org: PUT /api/contracts/:id denies org B", async () => {
    const r = await http("PUT", "/api/contracts/con_a1", { token: bob, body: { title: "changed" } });
    const check = await http("GET", "/api/contracts/con_a1", { token: alice });
    ok(r.status === 404 && check.json.title === "Master services agreement", "contract update not denied: " + r.status);
  });
  denied("/api/quotes/quo_a1", bob, "vt-decoy-quote-get: GET /api/quotes/:id denies org B");
  denied("/api/reports/shipments/shp_a1/timeline", bob, "vt-decoy-shipment-timeline: timeline denies org B");
  add("decoy", "vt-decoy-carrier-webhook: body-bound signature and org-scoped lookup deny org A's shipment", async () => {
    const ts = String(Math.floor(Date.now() / 1000));
    const send = (shipmentId) => {
      const body = { accountId: "car_beta", shipmentId, status: "delivered" };
      return http("POST", "/integrations/carrier", { headers: { "x-carrier-timestamp": ts, "x-carrier-signature": hmac(ts + "." + JSON.stringify(body)) }, body });
    };
    const foreign = await send("shp_a1");
    const own = await send("shp_b1");
    const check = await http("GET", "/api/shipments/shp_a1", { token: alice });
    ok(foreign.status === 404 && own.status === 200 && check.json.status === "in_transit", "carrier webhook scoping failed");
    const replay = await http("POST", "/integrations/carrier", { headers: { "x-carrier-timestamp": ts, "x-carrier-signature": hmac(ts) }, body: { accountId: "car_beta", shipmentId: "shp_a1", status: "lost" } });
    ok(replay.status === 401, "timestamp-only signature accepted by the carrier webhook");
  });

  // sweep over ordinary routes
  for (const route of manifest.routes) {
    add("sweep", route.name + ": org B is denied " + route.methods.join("/") + " on " + route.id, async () => {
      for (const method of route.methods) {
        const r = await http(method, route.path + "/" + route.id, { token: bea, body: method === "PUT" ? { name: "x", title: "x", label: "x", description: "x", code: "x", url: "x", sku: "x", subject: "x" } : undefined });
        ok(r.status === 404, method + " returned " + r.status);
      }
      const anon = await http("GET", route.path + "/" + route.id, {});
      ok(anon.status === 401, "anonymous request returned " + anon.status);
      const own = await http("GET", route.path + "/" + route.id, { token: alice });
      ok(own.status === 200, "owner read returned " + own.status);
    });
  }

  failures = await runCases(cases);
} finally {
  server?.close();
  rmSync(work, { recursive: true, force: true });
}
process.exit(failures ? 1 : 0);
