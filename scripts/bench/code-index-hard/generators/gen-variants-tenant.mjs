#!/usr/bin/env node
// Generates the "variants-tenant" fixture: a multi-tenant billing/CRM API (TypeScript, Express 5) in which one tenant
// isolation fix was applied at a single route and eight siblings remain in other modules and layers.
// Deterministic: running it twice yields byte-identical output. Writes the fixture (with answer.json) and the sweep
// manifest used by the proof (proofs/variants-tenant/manifest.json).
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { scoreFindings, validateAnswer } from "../../match.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const hardDir = resolve(here, "..");
const outDir = join(hardDir, "variants", "variants-tenant");
const proofDir = join(hardDir, "proofs", "variants-tenant");

const ts = String.raw;
const files = new Map();
const put = (path, text) => {
  if (files.has(path)) throw new Error(`duplicate file ${path}`);
  files.set(path, text.replace(/^\n/, ""));
};

// ---------------------------------------------------------------------------------------------------------------
// project files
// ---------------------------------------------------------------------------------------------------------------
put("package.json", `{
  "name": "tenantly-api",
  "version": "2.4.0",
  "private": true,
  "description": "Billing and CRM API for multi-tenant teams",
  "type": "module",
  "scripts": {
    "start": "tsx src/server.ts",
    "build": "tsc -p tsconfig.json",
    "typecheck": "tsc -p tsconfig.json --noEmit"
  },
  "dependencies": {
    "express": "^5.1.0"
  },
  "devDependencies": {
    "@types/express": "^5.0.0",
    "@types/node": "^22.0.0",
    "tsx": "^4.19.0",
    "typescript": "^5.6.0"
  }
}
`);

put("tsconfig.json", `{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "strict": true,
    "noEmit": true,
    "skipLibCheck": true,
    "esModuleInterop": true
  },
  "include": ["src"]
}
`);

put("README.md", `
# tenantly-api

Billing and CRM API. Every record belongs to an organisation (\`orgId\`); users sign in with
\`POST /api/auth/login\` and send the returned bearer token on every call.

Layout:

- \`src/routes\` HTTP routers, mounted in \`src/routes/index.ts\`
- \`src/services\` business logic shared by routes, jobs and resolvers
- \`src/repositories\` in-memory repositories (one per record type)
- \`src/jobs\` background jobs and the queue
- \`src/graphql\` the small query endpoint at \`POST /graphql\`
- \`src/ws\` realtime sessions and message handlers (HTTP bridge under \`/rt\`)
- \`src/integrations\` inbound provider webhooks

Run with \`npm start\`. Secrets come from \`TENANTLY_TOKEN_SECRET\`, \`TENANTLY_SHARE_SECRET\`,
\`TENANTLY_WEBHOOK_SECRET\` and \`TENANTLY_SERVICE_TOKEN\`.
`);

// ---------------------------------------------------------------------------------------------------------------
// lib
// ---------------------------------------------------------------------------------------------------------------
put("src/lib/config.ts", ts`
import { randomBytes } from "node:crypto";

const secret = (name: string, bytes = 32): string => process.env[name] ?? randomBytes(bytes).toString("hex");

export const config = {
  port: Number(process.env.PORT ?? 3000),
  tokenSecret: secret("TENANTLY_TOKEN_SECRET"),
  shareSecret: secret("TENANTLY_SHARE_SECRET"),
  webhookSecret: secret("TENANTLY_WEBHOOK_SECRET"),
  serviceToken: secret("TENANTLY_SERVICE_TOKEN", 24),
  tokenTtlSeconds: 3600,
  webhookToleranceSeconds: 3600,
};
`);

put("src/lib/hmac.ts", ts`
import { createHmac, timingSafeEqual } from "node:crypto";

export function hmacHex(secret: string, data: string): string {
  return createHmac("sha256", secret).update(data).digest("hex");
}

export function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}
`);

put("src/lib/token.ts", ts`
import { config } from "./config";
import { hmacHex, safeEqual } from "./hmac";

export interface TokenClaims {
  sub: string;
  exp: number;
}

export function signToken(sub: string, ttlSeconds: number = config.tokenTtlSeconds): string {
  const claims: TokenClaims = { sub, exp: Math.floor(Date.now() / 1000) + ttlSeconds };
  const body = Buffer.from(JSON.stringify(claims)).toString("base64url");
  return body + "." + hmacHex(config.tokenSecret, body);
}

export function verifyToken(token: string): TokenClaims | null {
  const [body, signature, extra] = token.split(".");
  if (!body || !signature || extra !== undefined) return null;
  if (!safeEqual(hmacHex(config.tokenSecret, body), signature)) return null;
  let claims: TokenClaims;
  try {
    claims = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (typeof claims.sub !== "string" || typeof claims.exp !== "number") return null;
  if (claims.exp < Math.floor(Date.now() / 1000)) return null;
  return claims;
}
`);

put("src/lib/shareToken.ts", ts`
import { config } from "./config";
import { hmacHex, safeEqual } from "./hmac";

export interface ShareClaims {
  inv: string;
  org: string;
  exp: number;
}

export function signShare(invoiceId: string, orgId: string, ttlSeconds: number): string {
  const claims: ShareClaims = { inv: invoiceId, org: orgId, exp: Math.floor(Date.now() / 1000) + ttlSeconds };
  const body = Buffer.from(JSON.stringify(claims)).toString("base64url");
  return body + "." + hmacHex(config.shareSecret, body);
}

export function readShare(token: string): ShareClaims | null {
  const [body, signature, extra] = token.split(".");
  if (!body || !signature || extra !== undefined) return null;
  if (!safeEqual(hmacHex(config.shareSecret, body), signature)) return null;
  try {
    const claims = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as ShareClaims;
    if (typeof claims.inv !== "string" || typeof claims.org !== "string") return null;
    if (typeof claims.exp !== "number" || claims.exp < Math.floor(Date.now() / 1000)) return null;
    return claims;
  } catch {
    return null;
  }
}
`);

put("src/lib/ids.ts", ts`
import { randomBytes } from "node:crypto";

export function newId(prefix: string): string {
  return prefix + "_" + randomBytes(5).toString("hex");
}

export function isoNow(): string {
  return new Date().toISOString();
}
`);

put("src/lib/errors.ts", ts`
export class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

export const notFound = (what: string): HttpError => new HttpError(404, what + " not found");
export const badRequest = (message: string): HttpError => new HttpError(400, message);
export const forbidden = (message = "forbidden"): HttpError => new HttpError(403, message);
`);

put("src/lib/validate.ts", ts`
import { badRequest } from "./errors";

/** Copy only the listed keys from a request body. */
export function pick<K extends string>(body: unknown, keys: readonly K[]): Partial<Record<K, any>> {
  const source = body && typeof body === "object" ? (body as Record<string, unknown>) : {};
  const out: Partial<Record<K, any>> = {};
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(source, key)) out[key] = source[key];
  }
  return out;
}

export function requireFields(data: Record<string, unknown>, keys: readonly string[]): void {
  for (const key of keys) {
    const value = data[key];
    if (value === undefined || value === null || value === "") throw badRequest("missing field " + key);
  }
}
`);

put("src/lib/policy.ts", ts`
import { notFound } from "./errors";
import type { AuthUser, OrgRecord } from "../models/base";

export function assertSameOrg(user: AuthUser, record: OrgRecord, what = "record"): void {
  if (record.orgId !== user.orgId) throw notFound(what);
}

export const refundPolicy = {
  canView(user: AuthUser, refund: OrgRecord): boolean {
    return refund.orgId === user.orgId;
  },
  canIssue(user: AuthUser, refund: OrgRecord): boolean {
    return refund.orgId === user.orgId && (user.role === "admin" || user.role === "manager");
  },
};
`);

put("src/lib/store.ts", ts`
import type { OrgRecord } from "../models/base";

export class Repo<T extends OrgRecord> {
  protected rows = new Map<string, T>();

  constructor(readonly label: string) {}

  findById(id: string): T | undefined {
    return this.rows.get(id);
  }

  findForOrg(orgId: string, id: string): T | undefined {
    const row = this.rows.get(id);
    return row && row.orgId === orgId ? row : undefined;
  }

  listForOrg(orgId: string): T[] {
    return [...this.rows.values()].filter((row) => row.orgId === orgId);
  }

  insert(row: T): T {
    this.rows.set(row.id, row);
    return row;
  }

  save(row: T): T {
    this.rows.set(row.id, row);
    return row;
  }

  remove(id: string): boolean {
    return this.rows.delete(id);
  }
}

/** Reference data shared by every organisation (no orgId). */
export class RefRepo<T extends { id: string }> {
  private rows = new Map<string, T>();

  insert(row: T): T {
    this.rows.set(row.id, row);
    return row;
  }

  findById(id: string): T | undefined {
    return this.rows.get(id);
  }

  list(): T[] {
    return [...this.rows.values()];
  }
}
`);

put("src/lib/csv.ts", ts`
export function parseCsv(text: string, maxRows = 500): Record<string, string>[] {
  const lines = text.split(/\r?\n/).filter((line) => line.trim() !== "");
  if (lines.length < 2) return [];
  const header = lines[0].split(",").map((cell) => cell.trim());
  return lines.slice(1, maxRows + 1).map((line) => {
    const cells = line.split(",").map((cell) => cell.trim());
    const row: Record<string, string> = {};
    header.forEach((name, index) => {
      row[name] = cells[index] ?? "";
    });
    return row;
  });
}
`);

put("src/lib/mailer.ts", ts`
export interface Mail {
  to: string;
  subject: string;
  body: string;
}

export const outbox: Mail[] = [];

export function sendMail(mail: Mail): void {
  outbox.push(mail);
  if (outbox.length > 1000) outbox.shift();
}
`);

put("src/lib/password.ts", ts`
import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

export function hashPassword(password: string): string {
  const salt = randomBytes(16).toString("hex");
  return salt + ":" + scryptSync(password, salt, 32).toString("hex");
}

export function checkPassword(password: string, stored: string): boolean {
  const [salt, hash] = stored.split(":");
  if (!salt || !hash) return false;
  const candidate = scryptSync(password, salt, 32);
  const expected = Buffer.from(hash, "hex");
  return candidate.length === expected.length && timingSafeEqual(candidate, expected);
}
`);

// ---------------------------------------------------------------------------------------------------------------
// middleware
// ---------------------------------------------------------------------------------------------------------------
put("src/types/express.d.ts", ts`
import type { AuthUser } from "../models/base";

declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

export {};
`);

put("src/middleware/authenticate.ts", ts`
import type { NextFunction, Request, Response } from "express";
import { verifyToken } from "../lib/token";
import { userRepo } from "../repositories/userRepo";

export function authenticate(req: Request, res: Response, next: NextFunction) {
  const match = /^Bearer (.+)$/.exec(req.headers.authorization ?? "");
  const claims = match ? verifyToken(match[1]) : null;
  if (!claims) return res.status(401).json({ error: "unauthenticated" });
  const user = userRepo.findById(claims.sub);
  if (!user || user.disabled) return res.status(401).json({ error: "unauthenticated" });
  req.user = { id: user.id, orgId: user.orgId, role: user.role };
  next();
}
`);

put("src/middleware/requireRole.ts", ts`
import type { NextFunction, Request, Response } from "express";
import type { Role } from "../models/base";

export function requireRole(...roles: Role[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user || !roles.includes(req.user.role)) return res.status(403).json({ error: "insufficient role" });
    next();
  };
}
`);

put("src/middleware/serviceToken.ts", ts`
import type { NextFunction, Request, Response } from "express";
import { config } from "../lib/config";
import { safeEqual } from "../lib/hmac";

// Internal callers (billing workers, the support console) present a shared service token.
export function serviceToken(req: Request, res: Response, next: NextFunction) {
  const presented = String(req.headers["x-service-token"] ?? "");
  if (!presented || !safeEqual(presented, config.serviceToken)) return res.status(401).json({ error: "service token required" });
  next();
}
`);

put("src/middleware/errorHandler.ts", ts`
import type { NextFunction, Request, Response } from "express";
import { HttpError } from "../lib/errors";

export function errorHandler(err: unknown, _req: Request, res: Response, _next: NextFunction) {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  res.status(500).json({ error: "internal error" });
}
`);

put("src/middleware/requestLog.ts", ts`
import type { NextFunction, Request, Response } from "express";

export const accessLog: string[] = [];

export function requestLog(req: Request, res: Response, next: NextFunction) {
  res.on("finish", () => {
    accessLog.push(req.method + " " + req.path + " " + res.statusCode);
    if (accessLog.length > 500) accessLog.shift();
  });
  next();
}
`);

// ---------------------------------------------------------------------------------------------------------------
// models
// ---------------------------------------------------------------------------------------------------------------
put("src/models/base.ts", ts`
export type Role = "admin" | "manager" | "member" | "support";

export interface OrgRecord {
  id: string;
  orgId: string;
}

export interface AuthUser {
  id: string;
  orgId: string;
  role: Role;
}

export interface User extends OrgRecord {
  email: string;
  name: string;
  role: Role;
  passwordHash: string;
  disabled: boolean;
}
`);

put("src/models/billing.ts", ts`
import type { OrgRecord } from "./base";

export interface Customer extends OrgRecord {
  name: string;
  email: string;
  billingAddress?: string;
  createdAt: string;
}

export interface InvoiceLine {
  description: string;
  qty: number;
  unitPrice: number;
}

export interface Invoice extends OrgRecord {
  customerId: string;
  number: string;
  status: "draft" | "open" | "paid" | "void";
  currency: string;
  lines: InvoiceLine[];
  total: number;
  dueDate: string;
  paidReference?: string;
  createdAt: string;
}

export interface Payment extends OrgRecord {
  invoiceId: string;
  amount: number;
  method: string;
  receivedAt: string;
}

export interface CreditNote extends OrgRecord {
  invoiceId: string;
  amount: number;
  reason: string;
}

export interface Refund extends OrgRecord {
  paymentId: string;
  amount: number;
  status: string;
}

export interface Subscription extends OrgRecord {
  customerId: string;
  planId: string;
  status: "active" | "paused" | "cancelled";
  seats: number;
  currentPeriodEnd: string;
  monthlyAmount: number;
  paymentMethodLast4: string;
}

export interface Contract extends OrgRecord {
  customerId: string;
  title: string;
  terms: string;
  value: number;
  startsOn: string;
  endsOn: string;
  status: "draft" | "active" | "expired";
}

export interface Quote extends OrgRecord {
  customerId: string;
  title: string;
  lines: InvoiceLine[];
  total: number;
  validUntil: string;
  status: "draft" | "sent" | "accepted";
  internalNotes: string;
}
`);

put("src/models/support.ts", ts`
import type { OrgRecord } from "./base";

export interface Ticket extends OrgRecord {
  customerId: string;
  subject: string;
  body: string;
  status: "open" | "pending" | "closed";
  priority: "low" | "normal" | "high";
  createdAt: string;
}

export interface TicketComment extends OrgRecord {
  ticketId: string;
  authorId: string;
  body: string;
  createdAt: string;
}

export interface Team extends OrgRecord {
  name: string;
  memberIds: string[];
}
`);

put("src/models/catalog.ts", ts`
import type { OrgRecord } from "./base";

export interface Product extends OrgRecord {
  sku: string;
  name: string;
  unitPrice: number;
  unitCost: number;
  active: boolean;
}

export interface ShipmentEvent {
  status: string;
  at: string;
}

export interface Shipment extends OrgRecord {
  orderRef: string;
  carrier: string;
  trackingNo: string;
  status: string;
  cost: number;
  billedAmount: number;
  destination: string;
  events: ShipmentEvent[];
}

export interface IntegrationAccount extends OrgRecord {
  provider: "payments" | "carrier";
  externalAccountId: string;
}

export interface Currency {
  id: string;
  name: string;
  symbol: string;
}

export interface Country {
  id: string;
  name: string;
}

export interface Plan {
  id: string;
  name: string;
  monthlyAmount: number;
  seatLimit: number;
}
`);

// ---------------------------------------------------------------------------------------------------------------
// filler entities (ordinary, correctly scoped CRUD modules)
// ---------------------------------------------------------------------------------------------------------------
const FILLERS = [
  { group: "crm", key: "contacts", path: "contacts", Type: "Contact", repo: "contactRepo", prefix: "cnt", fields: [["name", "string"], ["email", "string"], ["phone", "string"], ["title", "string"]] },
  { group: "crm", key: "deals", path: "deals", Type: "Deal", repo: "dealRepo", prefix: "dl", fields: [["title", "string"], ["amount", "number"], ["stage", "string"], ["customerId", "string"]] },
  { group: "crm", key: "leads", path: "leads", Type: "Lead", repo: "leadRepo", prefix: "ld", fields: [["name", "string"], ["email", "string"], ["source", "string"], ["score", "number"]] },
  { group: "crm", key: "campaigns", path: "campaigns", Type: "Campaign", repo: "campaignRepo", prefix: "cmp", fields: [["name", "string"], ["channel", "string"], ["budget", "number"], ["active", "boolean"]] },
  { group: "crm", key: "activities", path: "activities", Type: "Activity", repo: "activityRepo", prefix: "act", fields: [["kind", "string"], ["summary", "string"], ["dueOn", "string"]] },
  { group: "crm", key: "notes", path: "notes", Type: "Note", repo: "noteRepo", prefix: "nt", fields: [["subject", "string"], ["body", "string"]] },
  { group: "crm", key: "tags", path: "tags", Type: "Tag", repo: "tagRepo", prefix: "tg", fields: [["label", "string"], ["color", "string"]] },
  { group: "ops", key: "tasks", path: "tasks", Type: "Task", repo: "taskRepo", prefix: "tsk", fields: [["title", "string"], ["done", "boolean"], ["dueOn", "string"], ["assigneeId", "string"]] },
  { group: "ops", key: "projects", path: "projects", Type: "Project", repo: "projectRepo", prefix: "prj", fields: [["name", "string"], ["status", "string"], ["budget", "number"]] },
  { group: "ops", key: "warehouses", path: "warehouses", Type: "Warehouse", repo: "warehouseRepo", prefix: "wh", fields: [["name", "string"], ["city", "string"], ["capacity", "number"]] },
  { group: "ops", key: "suppliers", path: "suppliers", Type: "Supplier", repo: "supplierRepo", prefix: "sup", fields: [["name", "string"], ["email", "string"], ["terms", "string"]] },
  { group: "ops", key: "purchaseOrders", path: "purchase-orders", Type: "PurchaseOrder", repo: "purchaseOrderRepo", prefix: "po", fields: [["supplierId", "string"], ["reference", "string"], ["amount", "number"], ["status", "string"]] },
  { group: "ops", key: "documents", path: "documents", Type: "Document", repo: "documentRepo", prefix: "doc", fields: [["title", "string"], ["kind", "string"], ["url", "string"]] },
  { group: "ops", key: "expenses", path: "expenses", Type: "Expense", repo: "expenseRepo", prefix: "exp", fields: [["description", "string"], ["amount", "number"], ["category", "string"], ["incurredOn", "string"]] },
  { group: "finance", key: "categories", path: "categories", Type: "Category", repo: "categoryRepo", prefix: "cat", fields: [["name", "string"], ["parentId", "string"]] },
  { group: "finance", key: "coupons", path: "coupons", Type: "Coupon", repo: "couponRepo", prefix: "cpn", fields: [["code", "string"], ["percentOff", "number"], ["active", "boolean"]] },
  { group: "finance", key: "priceLists", path: "price-lists", Type: "PriceList", repo: "priceListRepo", prefix: "pl", fields: [["name", "string"], ["currency", "string"]] },
  { group: "finance", key: "taxRates", path: "tax-rates", Type: "TaxRate", repo: "taxRateRepo", prefix: "tax", fields: [["name", "string"], ["ratePercent", "number"], ["region", "string"]] },
  { group: "finance", key: "apiKeys", path: "api-keys", Type: "ApiKeyRecord", repo: "apiKeyRepo", prefix: "key", fields: [["label", "string"], ["prefix", "string"], ["scopes", "string"]] },
  { group: "finance", key: "webhookEndpoints", path: "webhook-endpoints", Type: "WebhookEndpoint", repo: "webhookEndpointRepo", prefix: "whe", fields: [["url", "string"], ["events", "string"], ["active", "boolean"]] },
];
const GROUPS = ["crm", "ops", "finance"];
const DELETE_ROLES = [['"admin"', '"manager"'], ['"admin"'], ['"admin"', '"manager"'], ['"admin"', '"manager"', '"member"'], ['"admin"']];

for (const group of GROUPS) {
  const items = FILLERS.filter((s) => s.group === group);
  const iface = (s) =>
    `export interface ${s.Type} extends OrgRecord {\n${s.fields.map(([n, t], i) => `  ${n}${i === 0 ? "" : "?"}: ${t};`).join("\n")}\n  createdAt: string;\n}\n`;
  put(`src/models/${group}.ts`, `import type { OrgRecord } from "./base";\n\n${items.map(iface).join("\n")}`);
  put(
    `src/repositories/${group}Repos.ts`,
    `import { Repo } from "../lib/store";\nimport type { ${items.map((s) => s.Type).join(", ")} } from "../models/${group}";\n\n${items.map((s) => `export const ${s.repo} = new Repo<${s.Type}>("${s.key}");`).join("\n")}\n`,
  );
}

const singular = (s) => s.Type.replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase();
const fieldList = (s) => s.fields.map(([n]) => `"${n}"`).join(", ");
const header = (s, extra = []) =>
  [
    `import { Router } from "express";`,
    ...extra,
    `import { ${s.repo} } from "../repositories/${s.group}Repos";`,
    `import type { ${s.Type} } from "../models/${s.group}";`,
    `import { requireRole } from "../middleware/requireRole";`,
    `import { pick, requireFields } from "../lib/validate";`,
    `import { newId, isoNow } from "../lib/ids";`,
  ].join("\n");
const consts = (s) => `const FIELDS = [${fieldList(s)}] as const;\nconst REQUIRED = ["${s.fields[0][0]}"] as const;\n\nexport const ${s.key}Router = Router();\n`;
const createBody = (s, ind = "  ") =>
  `${ind}const data = pick(req.body, FIELDS);\n${ind}requireFields(data, REQUIRED);\n${ind}const record = ${s.repo}.insert({ ...data, id: newId("${s.prefix}"), orgId: req.user!.orgId, createdAt: isoNow() } as ${s.Type});\n`;

function fillerRoute(s, index) {
  const roles = DELETE_ROLES[index % DELETE_ROLES.length].join(", ");
  const label = singular(s);
  const style = index % 5;
  if (style === 0) {
    return `${header(s)}

${consts(s)}
${s.key}Router.get("/", (req, res) => {
  res.json(${s.repo}.listForOrg(req.user!.orgId));
});

${s.key}Router.get("/:id", (req, res) => {
  const record = ${s.repo}.findForOrg(req.user!.orgId, req.params.id);
  if (!record) return res.status(404).json({ error: "${label} not found" });
  res.json(record);
});

${s.key}Router.post("/", (req, res) => {
${createBody(s)}  res.status(201).json(record);
});

${s.key}Router.put("/:id", (req, res) => {
  const record = ${s.repo}.findForOrg(req.user!.orgId, req.params.id);
  if (!record) return res.status(404).json({ error: "${label} not found" });
  res.json(${s.repo}.save({ ...record, ...pick(req.body, FIELDS) }));
});

${s.key}Router.delete("/:id", requireRole(${roles}), (req, res) => {
  const record = ${s.repo}.findForOrg(req.user!.orgId, req.params.id);
  if (!record) return res.status(404).json({ error: "${label} not found" });
  ${s.repo}.remove(record.id);
  res.status(204).end();
});
`;
  }
  if (style === 1) {
    return `${header(s)}

${consts(s)}
// Resolve :id once per request, inside the caller's organisation.
${s.key}Router.param("id", (req, res, next, id) => {
  const record = ${s.repo}.findForOrg(req.user!.orgId, id);
  if (!record) return res.status(404).json({ error: "${label} not found" });
  res.locals.record = record;
  next();
});

${s.key}Router.get("/", (req, res) => {
  const rows = ${s.repo}.listForOrg(req.user!.orgId);
  res.json({ count: rows.length, rows });
});

${s.key}Router.post("/", (req, res) => {
${createBody(s)}  res.status(201).json(record);
});

${s.key}Router.get("/:id", (_req, res) => {
  res.json(res.locals.record);
});

${s.key}Router.put("/:id", (req, res) => {
  const updated = ${s.repo}.save({ ...(res.locals.record as ${s.Type}), ...pick(req.body, FIELDS) });
  res.json(updated);
});

${s.key}Router.delete("/:id", requireRole(${roles}), (_req, res) => {
  ${s.repo}.remove((res.locals.record as ${s.Type}).id);
  res.status(204).end();
});
`;
  }
  if (style === 2) {
    return `${header(s, [`import type { Request } from "express";`])}

${consts(s)}
const owned = (req: Request) => ${s.repo}.findForOrg(req.user!.orgId, req.params.id as string);

${s.key}Router
  .route("/")
  .get((req, res) => {
    res.json(${s.repo}.listForOrg(req.user!.orgId));
  })
  .post((req, res) => {
${createBody(s, "    ")}    res.status(201).json(record);
  });

${s.key}Router
  .route("/:id")
  .get((req, res) => {
    const record = owned(req);
    if (!record) return res.status(404).json({ error: "${label} not found" });
    res.json(record);
  })
  .put((req, res) => {
    const record = owned(req);
    if (!record) return res.status(404).json({ error: "${label} not found" });
    res.json(${s.repo}.save({ ...record, ...pick(req.body, FIELDS) }));
  })
  .delete(requireRole(${roles}), (req, res) => {
    const record = owned(req);
    if (!record) return res.status(404).json({ error: "${label} not found" });
    ${s.repo}.remove(record.id);
    res.status(204).end();
  });
`;
  }
  if (style === 3) {
    return `${header(s, [`import { notFound } from "../lib/errors";`, `import type { AuthUser } from "../models/base";`])}

${consts(s)}
const service = {
  list(user: AuthUser): ${s.Type}[] {
    return ${s.repo}.listForOrg(user.orgId);
  },
  get(user: AuthUser, id: string): ${s.Type} {
    const record = ${s.repo}.findForOrg(user.orgId, id);
    if (!record) throw notFound("${label}");
    return record;
  },
  create(user: AuthUser, body: unknown): ${s.Type} {
    const data = pick(body, FIELDS);
    requireFields(data, REQUIRED);
    return ${s.repo}.insert({ ...data, id: newId("${s.prefix}"), orgId: user.orgId, createdAt: isoNow() } as ${s.Type});
  },
  update(user: AuthUser, id: string, body: unknown): ${s.Type} {
    return ${s.repo}.save({ ...service.get(user, id), ...pick(body, FIELDS) });
  },
  remove(user: AuthUser, id: string): void {
    ${s.repo}.remove(service.get(user, id).id);
  },
};

${s.key}Router.get("/", (req, res) => {
  res.json(service.list(req.user!));
});

${s.key}Router.post("/", (req, res) => {
  res.status(201).json(service.create(req.user!, req.body));
});

${s.key}Router.get("/:id", (req, res) => {
  res.json(service.get(req.user!, req.params.id));
});

${s.key}Router.put("/:id", (req, res) => {
  res.json(service.update(req.user!, req.params.id, req.body));
});

${s.key}Router.delete("/:id", requireRole(${roles}), (req, res) => {
  service.remove(req.user!, req.params.id);
  res.status(204).end();
});
`;
  }
  return `${header(s, [`import type { Request } from "express";`, `import { notFound } from "../lib/errors";`])}

${consts(s)}
// Loads the record and checks that it belongs to the caller's organisation.
function load(req: Request): ${s.Type} {
  const record = ${s.repo}.findById(req.params.id as string);
  if (!record || record.orgId !== req.user!.orgId) throw notFound("${label}");
  return record;
}

${s.key}Router.get("/", (req, res) => {
  res.json(${s.repo}.listForOrg(req.user!.orgId));
});

${s.key}Router.post("/", (req, res) => {
${createBody(s)}  res.status(201).json(record);
});

${s.key}Router.get("/:id", (req, res) => {
  res.json(load(req));
});

${s.key}Router.put("/:id", (req, res) => {
  res.json(${s.repo}.save({ ...load(req), ...pick(req.body, FIELDS) }));
});

${s.key}Router.delete("/:id", requireRole(${roles}), (req, res) => {
  ${s.repo}.remove(load(req).id);
  res.status(204).end();
});
`;
}
FILLERS.forEach((s, i) => put(`src/routes/${s.key}.ts`, fillerRoute(s, i) ));

// ---------------------------------------------------------------------------------------------------------------
// core repositories
// ---------------------------------------------------------------------------------------------------------------
put("src/repositories/userRepo.ts", ts`
import { Repo } from "../lib/store";
import type { User } from "../models/base";

class UserRepo extends Repo<User> {
  findByEmail(email: string): User | undefined {
    const wanted = email.toLowerCase();
    for (const user of this.rows.values()) if (user.email === wanted) return user;
    return undefined;
  }
}

export const userRepo = new UserRepo("user");
`);

put("src/repositories/customerRepo.ts", ts`
import { Repo } from "../lib/store";
import type { Customer } from "../models/billing";

export const customerRepo = new Repo<Customer>("customer");
`);

put("src/repositories/invoiceRepo.ts", ts`
import { Repo } from "../lib/store";
import type { Invoice } from "../models/billing";

class InvoiceRepo extends Repo<Invoice> {
  listOpenForOrg(orgId: string): Invoice[] {
    return this.listForOrg(orgId).filter((invoice) => invoice.status === "open");
  }
}

export const invoiceRepo = new InvoiceRepo("invoice");
`);

put("src/repositories/contractRepo.ts", ts`
import { Repo } from "../lib/store";
import type { Contract } from "../models/billing";

export const contractRepo = new Repo<Contract>("contract");
`);

put("src/repositories/quoteRepo.ts", ts`
import { Repo } from "../lib/store";
import type { Quote } from "../models/billing";

export const quoteRepo = new Repo<Quote>("quote");
`);

put("src/repositories/subscriptionRepo.ts", ts`
import { Repo } from "../lib/store";
import type { Subscription } from "../models/billing";

export const subscriptionRepo = new Repo<Subscription>("subscription");
`);

put("src/repositories/billingRepos.ts", ts`
import { Repo } from "../lib/store";
import type { CreditNote, Payment, Refund } from "../models/billing";

export const paymentRepo = new Repo<Payment>("payment");
export const creditNoteRepo = new Repo<CreditNote>("creditNote");
export const refundRepo = new Repo<Refund>("refund");
`);

put("src/repositories/ticketRepo.ts", ts`
import { Repo } from "../lib/store";
import type { Ticket, TicketComment } from "../models/support";

export const ticketRepo = new Repo<Ticket>("ticket");

class CommentRepo extends Repo<TicketComment> {
  forTicket(ticketId: string): TicketComment[] {
    return [...this.rows.values()].filter((comment) => comment.ticketId === ticketId);
  }
}

export const ticketCommentRepo = new CommentRepo("ticketComment");
`);

put("src/repositories/teamRepo.ts", ts`
import { Repo } from "../lib/store";
import type { Team } from "../models/support";

export const teamRepo = new Repo<Team>("team");
`);

put("src/repositories/productRepo.ts", ts`
import { Repo } from "../lib/store";
import type { Product } from "../models/catalog";

export const productRepo = new Repo<Product>("product");
`);

put("src/repositories/shipmentRepo.ts", ts`
import type { Shipment } from "../models/catalog";

class ShipmentRepo {
  private rows = new Map<string, Shipment>();

  add(shipment: Shipment): Shipment {
    this.rows.set(shipment.id, shipment);
    return shipment;
  }

  get(id: string): Shipment | undefined {
    return this.rows.get(id);
  }

  getForOrg(orgId: string, id: string): Shipment | undefined {
    const shipment = this.rows.get(id);
    return shipment && shipment.orgId === orgId ? shipment : undefined;
  }

  forOrg(orgId: string): Shipment[] {
    return [...this.rows.values()].filter((shipment) => shipment.orgId === orgId);
  }

  save(shipment: Shipment): Shipment {
    this.rows.set(shipment.id, shipment);
    return shipment;
  }
}

export const shipmentRepo = new ShipmentRepo();
`);

put("src/repositories/integrationRepo.ts", ts`
import { Repo } from "../lib/store";
import type { IntegrationAccount } from "../models/catalog";

class IntegrationRepo extends Repo<IntegrationAccount> {
  findByExternal(provider: string, externalAccountId: string): IntegrationAccount | undefined {
    for (const account of this.rows.values()) {
      if (account.provider === provider && account.externalAccountId === externalAccountId) return account;
    }
    return undefined;
  }
}

export const integrationRepo = new IntegrationRepo("integrationAccount");
`);

put("src/repositories/referenceRepos.ts", ts`
import { RefRepo } from "../lib/store";
import type { Country, Currency, Plan } from "../models/catalog";

export const currencyRepo = new RefRepo<Currency>();
export const countryRepo = new RefRepo<Country>();
export const planRepo = new RefRepo<Plan>();
`);

// ---------------------------------------------------------------------------------------------------------------
// seed data
// ---------------------------------------------------------------------------------------------------------------
const fillerSeed = (s) => {
  const sample = (org, tag) => {
    const parts = s.fields.map(([n, t]) => `${n}: ${t === "number" ? 10 : t === "boolean" ? "true" : `"Sample ${n} ${tag}"`}`);
    return `  ${s.repo}.insert({ id: "${s.prefix}_${tag}1", orgId: "org_${tag === "a" ? "a" : "b"}", ${parts.join(", ")}, createdAt: "2026-02-01T09:00:00.000Z" });`;
  };
  return `${sample("a", "a")}\n${sample("b", "b")}`;
};
put("src/seed.ts", `import { randomBytes } from "node:crypto";
import { hashPassword } from "./lib/password";
import { userRepo } from "./repositories/userRepo";
import { customerRepo } from "./repositories/customerRepo";
import { invoiceRepo } from "./repositories/invoiceRepo";
import { contractRepo } from "./repositories/contractRepo";
import { quoteRepo } from "./repositories/quoteRepo";
import { subscriptionRepo } from "./repositories/subscriptionRepo";
import { creditNoteRepo, paymentRepo, refundRepo } from "./repositories/billingRepos";
import { ticketCommentRepo, ticketRepo } from "./repositories/ticketRepo";
import { teamRepo } from "./repositories/teamRepo";
import { productRepo } from "./repositories/productRepo";
import { shipmentRepo } from "./repositories/shipmentRepo";
import { integrationRepo } from "./repositories/integrationRepo";
import { countryRepo, currencyRepo, planRepo } from "./repositories/referenceRepos";
${GROUPS.map((g) => `import { ${FILLERS.filter((s) => s.group === g).map((s) => s.repo).join(", ")} } from "./repositories/${g}Repos";`).join("\n")}

let seeded = false;

export function seedDemoData(): void {
  if (seeded) return;
  seeded = true;
  const password = process.env.TENANTLY_SEED_PASSWORD ?? randomBytes(9).toString("hex");
  const passwordHash = hashPassword(password);

  userRepo.insert({ id: "usr_alice", orgId: "org_a", email: "alice@alpha.example", name: "Alice Meyer", role: "admin", passwordHash, disabled: false });
  userRepo.insert({ id: "usr_bob", orgId: "org_b", email: "bob@beta.example", name: "Bob Keller", role: "member", passwordHash, disabled: false });
  userRepo.insert({ id: "usr_bea", orgId: "org_b", email: "bea@beta.example", name: "Bea Winter", role: "admin", passwordHash, disabled: false });

  customerRepo.insert({ id: "cus_a1", orgId: "org_a", name: "Harbor Logistics", email: "ap@harbor.example", createdAt: "2026-01-04T10:00:00.000Z" });
  customerRepo.insert({ id: "cus_b1", orgId: "org_b", name: "Pine Studio", email: "billing@pine.example", createdAt: "2026-01-09T10:00:00.000Z" });

  invoiceRepo.insert({ id: "inv_a1", orgId: "org_a", customerId: "cus_a1", number: "INV-A-1001", status: "open", currency: "EUR", lines: [{ description: "Consulting retainer", qty: 1, unitPrice: 4200 }], total: 4200, dueDate: "2026-03-15", createdAt: "2026-02-15T08:00:00.000Z" });
  invoiceRepo.insert({ id: "inv_b1", orgId: "org_b", customerId: "cus_b1", number: "INV-B-2001", status: "open", currency: "USD", lines: [{ description: "Design sprint", qty: 2, unitPrice: 900 }], total: 1800, dueDate: "2026-03-20", createdAt: "2026-02-16T08:00:00.000Z" });

  contractRepo.insert({ id: "con_a1", orgId: "org_a", customerId: "cus_a1", title: "Master services agreement", terms: "Net 30, renews yearly with a 12 percent uplift", value: 98000, startsOn: "2026-01-01", endsOn: "2026-12-31", status: "active" });
  contractRepo.insert({ id: "con_b1", orgId: "org_b", customerId: "cus_b1", title: "Studio retainer", terms: "Monthly, cancel with 60 days notice", value: 24000, startsOn: "2026-02-01", endsOn: "2027-01-31", status: "active" });

  quoteRepo.insert({ id: "quo_a1", orgId: "org_a", customerId: "cus_a1", title: "Warehouse automation phase 2", lines: [{ description: "Conveyor retrofit", qty: 1, unitPrice: 15500 }], total: 15500, validUntil: "2026-04-30", status: "sent", internalNotes: "Floor price is 14000, discount allowed once" });
  quoteRepo.insert({ id: "quo_b1", orgId: "org_b", customerId: "cus_b1", title: "Brand refresh", lines: [{ description: "Identity package", qty: 1, unitPrice: 6200 }], total: 6200, validUntil: "2026-05-15", status: "draft", internalNotes: "Stretch goal is a retainer" });

  subscriptionRepo.insert({ id: "sub_a1", orgId: "org_a", customerId: "cus_a1", planId: "plan_pro", status: "active", seats: 25, currentPeriodEnd: "2026-06-30", monthlyAmount: 1250, paymentMethodLast4: "4242" });
  subscriptionRepo.insert({ id: "sub_b1", orgId: "org_b", customerId: "cus_b1", planId: "plan_basic", status: "active", seats: 5, currentPeriodEnd: "2026-06-30", monthlyAmount: 250, paymentMethodLast4: "1881" });

  paymentRepo.insert({ id: "pay_a1", orgId: "org_a", invoiceId: "inv_a1", amount: 1000, method: "bank", receivedAt: "2026-02-20T12:00:00.000Z" });
  paymentRepo.insert({ id: "pay_b1", orgId: "org_b", invoiceId: "inv_b1", amount: 500, method: "card", receivedAt: "2026-02-21T12:00:00.000Z" });
  creditNoteRepo.insert({ id: "cn_a1", orgId: "org_a", invoiceId: "inv_a1", amount: 150, reason: "Goodwill adjustment" });
  creditNoteRepo.insert({ id: "cn_b1", orgId: "org_b", invoiceId: "inv_b1", amount: 50, reason: "Duplicate line" });
  refundRepo.insert({ id: "rfd_a1", orgId: "org_a", paymentId: "pay_a1", amount: 200, status: "pending" });
  refundRepo.insert({ id: "rfd_b1", orgId: "org_b", paymentId: "pay_b1", amount: 75, status: "pending" });

  ticketRepo.insert({ id: "tkt_a1", orgId: "org_a", customerId: "cus_a1", subject: "Refund dispute on the March order", body: "Customer claims the pallets arrived damaged.", status: "open", priority: "high", createdAt: "2026-03-02T09:30:00.000Z" });
  ticketRepo.insert({ id: "tkt_b1", orgId: "org_b", customerId: "cus_b1", subject: "Logo files missing", body: "Where are the vector exports?", status: "open", priority: "normal", createdAt: "2026-03-03T09:30:00.000Z" });
  ticketCommentRepo.insert({ id: "tcm_a1", orgId: "org_a", ticketId: "tkt_a1", authorId: "usr_alice", body: "Carrier photos requested.", createdAt: "2026-03-02T10:00:00.000Z" });
  ticketCommentRepo.insert({ id: "tcm_b1", orgId: "org_b", ticketId: "tkt_b1", authorId: "usr_bob", body: "Sending the files today.", createdAt: "2026-03-03T10:00:00.000Z" });

  teamRepo.insert({ id: "team_a1", orgId: "org_a", name: "Collections", memberIds: ["usr_alice"] });
  teamRepo.insert({ id: "team_b1", orgId: "org_b", name: "Studio", memberIds: ["usr_bob", "usr_bea"] });

  productRepo.insert({ id: "prd_a1", orgId: "org_a", sku: "A-100", name: "Pallet jack", unitPrice: 450, unitCost: 280, active: true });
  productRepo.insert({ id: "prd_b1", orgId: "org_b", sku: "B-200", name: "Easel stand", unitPrice: 120, unitCost: 55, active: true });

  shipmentRepo.add({ id: "shp_a1", orgId: "org_a", orderRef: "SO-5521", carrier: "Fastline", trackingNo: "FL-77120", status: "in_transit", cost: 182.4, billedAmount: 240, destination: "Rotterdam", events: [{ status: "picked_up", at: "2026-03-01T07:00:00.000Z" }] });
  shipmentRepo.add({ id: "shp_b1", orgId: "org_b", orderRef: "SO-7710", carrier: "Quickpost", trackingNo: "QP-4410", status: "label_created", cost: 18.9, billedAmount: 25, destination: "Zurich", events: [{ status: "label_created", at: "2026-03-02T07:00:00.000Z" }] });

  integrationRepo.insert({ id: "ia_a1", orgId: "org_a", provider: "payments", externalAccountId: "acct_alpha" });
  integrationRepo.insert({ id: "ia_b1", orgId: "org_b", provider: "payments", externalAccountId: "acct_beta" });
  integrationRepo.insert({ id: "ia_a2", orgId: "org_a", provider: "carrier", externalAccountId: "car_alpha" });
  integrationRepo.insert({ id: "ia_b2", orgId: "org_b", provider: "carrier", externalAccountId: "car_beta" });

  currencyRepo.insert({ id: "EUR", name: "Euro", symbol: "EUR" });
  currencyRepo.insert({ id: "USD", name: "US dollar", symbol: "$" });
  currencyRepo.insert({ id: "CHF", name: "Swiss franc", symbol: "CHF" });
  countryRepo.insert({ id: "NL", name: "Netherlands" });
  countryRepo.insert({ id: "CH", name: "Switzerland" });
  planRepo.insert({ id: "plan_basic", name: "Basic", monthlyAmount: 50, seatLimit: 5 });
  planRepo.insert({ id: "plan_pro", name: "Pro", monthlyAmount: 50, seatLimit: 100 });

${FILLERS.map(fillerSeed).join("\n")}
}
`);

// ---------------------------------------------------------------------------------------------------------------
// services
// ---------------------------------------------------------------------------------------------------------------
put("src/services/invoiceService.ts", ts`
import { badRequest } from "../lib/errors";
import { isoNow, newId } from "../lib/ids";
import { invoiceRepo } from "../repositories/invoiceRepo";
import { customerRepo } from "../repositories/customerRepo";
import type { AuthUser } from "../models/base";
import type { Invoice, InvoiceLine } from "../models/billing";

function readLines(input: unknown): InvoiceLine[] {
  if (!Array.isArray(input) || input.length === 0) throw badRequest("at least one line is required");
  return input.map((line) => {
    const qty = Number(line?.qty);
    const unitPrice = Number(line?.unitPrice);
    if (!Number.isFinite(qty) || !Number.isFinite(unitPrice) || qty <= 0 || unitPrice < 0) throw badRequest("invalid line");
    return { description: String(line.description ?? "").slice(0, 200), qty, unitPrice };
  });
}

export const invoiceService = {
  create(user: AuthUser, body: any): Invoice {
    const customer = customerRepo.findForOrg(user.orgId, String(body?.customerId ?? ""));
    if (!customer) throw badRequest("unknown customer");
    const lines = readLines(body?.lines);
    const count = invoiceRepo.listForOrg(user.orgId).length + 1;
    return invoiceRepo.insert({
      id: newId("inv"),
      orgId: user.orgId,
      customerId: customer.id,
      number: "INV-" + user.orgId.slice(-1).toUpperCase() + "-" + String(1000 + count),
      status: "draft",
      currency: String(body?.currency ?? "EUR").slice(0, 3).toUpperCase(),
      lines,
      total: lines.reduce((sum, line) => sum + line.qty * line.unitPrice, 0),
      dueDate: String(body?.dueDate ?? ""),
      createdAt: isoNow(),
    });
  },
};
`);

put("src/services/contractService.ts", ts`
import { notFound } from "../lib/errors";
import { contractRepo } from "../repositories/contractRepo";
import type { Contract } from "../models/billing";

export const contractService = {
  list(orgId: string): Contract[] {
    return contractRepo.listForOrg(orgId);
  },

  get(id: string): Contract {
    const contract = contractRepo.findById(id);
    if (!contract) throw notFound("contract");
    return contract;
  },

  getForOrg(orgId: string, id: string): Contract {
    const contract = contractRepo.findForOrg(orgId, id);
    if (!contract) throw notFound("contract");
    return contract;
  },

  summarize(contract: Contract) {
    return {
      id: contract.id,
      title: contract.title,
      customerId: contract.customerId,
      value: contract.value,
      status: contract.status,
      endsOn: contract.endsOn,
      terms: contract.terms,
    };
  },
};
`);

put("src/services/ticketService.ts", ts`
import { notFound } from "../lib/errors";
import { isoNow, newId } from "../lib/ids";
import { hub } from "../ws/hub";
import { ticketCommentRepo, ticketRepo } from "../repositories/ticketRepo";
import type { AuthUser } from "../models/base";
import type { Ticket, TicketComment } from "../models/support";

export const ticketService = {
  list(user: AuthUser): Ticket[] {
    return ticketRepo.listForOrg(user.orgId);
  },

  get(user: AuthUser, id: string): { ticket: Ticket; comments: TicketComment[] } {
    const ticket = ticketRepo.findForOrg(user.orgId, id);
    if (!ticket) throw notFound("ticket");
    return { ticket, comments: ticketCommentRepo.forTicket(ticket.id) };
  },

  comment(user: AuthUser, id: string, body: string): TicketComment {
    const ticket = ticketRepo.findForOrg(user.orgId, id);
    if (!ticket) throw notFound("ticket");
    const comment = ticketCommentRepo.insert({
      id: newId("tcm"),
      orgId: user.orgId,
      ticketId: ticket.id,
      authorId: user.id,
      body: body.slice(0, 2000),
      createdAt: isoNow(),
    });
    hub.publish("ticket:" + ticket.id, { type: "comment", channel: "ticket:" + ticket.id, data: comment });
    return comment;
  },
};
`);

put("src/services/importService.ts", ts`
import { parseCsv } from "../lib/csv";
import { customerRepo } from "../repositories/customerRepo";
import { productRepo } from "../repositories/productRepo";
import type { AuthUser } from "../models/base";

export interface PreviewRow {
  line: number;
  customer: string;
  productId: string;
  name: string;
  unitPrice: number;
  unitCost: number;
  quantity: number;
  lineTotal: number;
  margin: number;
}

function resolveCustomer(user: AuthUser, ref: string) {
  return customerRepo.findForOrg(user.orgId, ref) ?? null;
}

function resolveProduct(ref: string) {
  return productRepo.findById(ref) ?? null;
}

export function previewOrderImport(user: AuthUser, csv: string) {
  const rows: PreviewRow[] = [];
  const problems: string[] = [];
  parseCsv(csv).forEach((row, index) => {
    const line = index + 2;
    const customer = resolveCustomer(user, row.customerId ?? "");
    if (!customer) return void problems.push("line " + line + ": unknown customer");
    const product = resolveProduct(row.productId ?? "");
    if (!product) return void problems.push("line " + line + ": unknown product");
    const quantity = Number(row.quantity);
    if (!Number.isInteger(quantity) || quantity <= 0) return void problems.push("line " + line + ": bad quantity");
    rows.push({
      line,
      customer: customer.name,
      productId: product.id,
      name: product.name,
      unitPrice: product.unitPrice,
      unitCost: product.unitCost,
      quantity,
      lineTotal: product.unitPrice * quantity,
      margin: (product.unitPrice - product.unitCost) * quantity,
    });
  });
  return { rows, problems, total: rows.reduce((sum, row) => sum + row.lineTotal, 0) };
}
`);

put("src/services/reportService.ts", ts`
import { notFound } from "../lib/errors";
import { shipmentRepo } from "../repositories/shipmentRepo";

export function shipmentCostReport(shipmentId: string) {
  const shipment = shipmentRepo.get(shipmentId);
  if (!shipment) throw notFound("shipment");
  return {
    id: shipment.id,
    orderRef: shipment.orderRef,
    carrier: shipment.carrier,
    destination: shipment.destination,
    cost: shipment.cost,
    billedAmount: shipment.billedAmount,
    margin: shipment.billedAmount - shipment.cost,
  };
}

export function shipmentTimeline(orgId: string, shipmentId: string) {
  const shipment = shipmentRepo.getForOrg(orgId, shipmentId);
  if (!shipment) throw notFound("shipment");
  return { id: shipment.id, status: shipment.status, events: shipment.events };
}

export function carrierTotals(orgId: string) {
  const totals: Record<string, { shipments: number; cost: number }> = {};
  for (const shipment of shipmentRepo.forOrg(orgId)) {
    const entry = (totals[shipment.carrier] ??= { shipments: 0, cost: 0 });
    entry.shipments += 1;
    entry.cost += shipment.cost;
  }
  return totals;
}
`);

// ---------------------------------------------------------------------------------------------------------------
// jobs
// ---------------------------------------------------------------------------------------------------------------
put("src/jobs/queue.ts", ts`
import { isoNow, newId } from "../lib/ids";
import type { AuthUser } from "../models/base";

export interface Job<P = any> {
  id: string;
  name: string;
  orgId: string;
  requestedBy: string;
  payload: P;
  status: "queued" | "running" | "done" | "failed";
  result?: unknown;
  error?: string;
  createdAt: string;
}

type Handler = (job: Job) => unknown | Promise<unknown>;

const handlers = new Map<string, Handler>();
const jobs = new Map<string, Job>();

async function run(job: Job): Promise<void> {
  const handler = handlers.get(job.name);
  job.status = "running";
  try {
    if (!handler) throw new Error("no handler for " + job.name);
    job.result = await handler(job);
    job.status = "done";
  } catch (err) {
    job.error = err instanceof Error ? err.message : "job failed";
    job.status = "failed";
  }
}

export const jobQueue = {
  register(name: string, handler: Handler): void {
    handlers.set(name, handler);
  },

  enqueue<P>(name: string, payload: P, user: AuthUser): Job<P> {
    const job: Job<P> = { id: newId("job"), name, orgId: user.orgId, requestedBy: user.id, payload, status: "queued", createdAt: isoNow() };
    jobs.set(job.id, job);
    queueMicrotask(() => void run(job));
    return job;
  },

  get(id: string): Job | undefined {
    return jobs.get(id);
  },
};
`);

put("src/jobs/reminderJob.ts", ts`
import { sendMail } from "../lib/mailer";
import { customerRepo } from "../repositories/customerRepo";
import { invoiceRepo } from "../repositories/invoiceRepo";
import type { Job } from "./queue";

export async function invoiceReminder(job: Job<{ invoiceId: string; to: string }>) {
  const invoice = invoiceRepo.findById(job.payload.invoiceId);
  if (!invoice) throw new Error("invoice not found");
  const customer = customerRepo.findForOrg(invoice.orgId, invoice.customerId);
  const subject = "Reminder: invoice " + invoice.number + " is due " + invoice.dueDate;
  const items = invoice.lines.map((line) => line.qty + " x " + line.description + " at " + line.unitPrice);
  const body = ["Hello " + (customer?.name ?? "there"), ...items, "Total " + invoice.total + " " + invoice.currency].join("\n");
  sendMail({ to: job.payload.to, subject, body });
  return { delivered: true, to: job.payload.to, subject, body };
}
`);

put("src/jobs/renewalJob.ts", ts`
import { contractRepo } from "../repositories/contractRepo";
import type { Job } from "./queue";

export async function contractRenewal(job: Job<{ contractId: string }>) {
  const contract = contractRepo.findById(job.payload.contractId);
  if (!contract || contract.orgId !== job.orgId) throw new Error("contract not found");
  return { contractId: contract.id, title: contract.title, notified: true, endsOn: contract.endsOn };
}
`);

put("src/jobs/registry.ts", ts`
import { jobQueue } from "./queue";
import { invoiceReminder } from "./reminderJob";
import { contractRenewal } from "./renewalJob";

export function registerJobs(): void {
  jobQueue.register("invoice-reminder", invoiceReminder);
  jobQueue.register("contract-renewal", contractRenewal);
}
`);

// ---------------------------------------------------------------------------------------------------------------
// graphql
// ---------------------------------------------------------------------------------------------------------------
put("src/graphql/loaders.ts", ts`
import { customerRepo } from "../repositories/customerRepo";
import type { AuthUser } from "../models/base";
import type { Customer } from "../models/billing";

// One loader set per request; lookups are limited to the caller's organisation.
export function createLoaders(user: AuthUser) {
  const customers = new Map<string, Customer | null>();
  return {
    customer: {
      load(id: string): Customer | null {
        if (!customers.has(id)) customers.set(id, customerRepo.findForOrg(user.orgId, id) ?? null);
        return customers.get(id) ?? null;
      },
    },
  };
}

export type Loaders = ReturnType<typeof createLoaders>;
`);

put("src/graphql/resolvers.ts", ts`
import { invoiceRepo } from "../repositories/invoiceRepo";
import { subscriptionRepo } from "../repositories/subscriptionRepo";
import { userRepo } from "../repositories/userRepo";
import { planRepo } from "../repositories/referenceRepos";
import type { GraphqlContext } from "./executor";

type Args = Record<string, any>;

export const resolvers = {
  Query: {
    me: (_args: Args, ctx: GraphqlContext) => {
      const user = userRepo.findById(ctx.user.id);
      return user ? { id: user.id, email: user.email, name: user.name, role: user.role } : null;
    },

    customer: (args: Args, ctx: GraphqlContext) => {
      return ctx.loaders.customer.load(String(args.id));
    },

    invoices: (_args: Args, ctx: GraphqlContext) => {
      return invoiceRepo.listForOrg(ctx.user.orgId);
    },

    plans: () => planRepo.list(),

    subscription: (args: Args) => {
      const subscription = subscriptionRepo.findById(String(args.id));
      return subscription ?? null;
    },

    openInvoices: (_args: Args, ctx: GraphqlContext) => {
      return invoiceRepo.listOpenForOrg(ctx.user.orgId);
    },
  },
};
`);

put("src/graphql/executor.ts", ts`
import { resolvers } from "./resolvers";
import type { Loaders } from "./loaders";
import type { AuthUser } from "../models/base";

export interface GraphqlContext {
  user: AuthUser;
  loaders: Loaders;
}

export interface GraphqlRequest {
  query: string;
  variables: Record<string, unknown>;
}

type Resolver = (args: Record<string, unknown>, ctx: GraphqlContext) => unknown;

// Supports one top-level field per request: { field(arg: "x", other: $var) { a b c } }
const OPERATION = /^\s*(?:query\s*\w*\s*)?\{\s*(\w+)\s*(?:\(([^)]*)\))?\s*(?:\{([^}]*)\})?\s*\}\s*$/;
const ARG = /(\w+)\s*:\s*(?:"([^"]*)"|\$(\w+))/g;

function project(value: unknown, selection: string): unknown {
  const names = selection.split(/[\s,]+/).filter(Boolean);
  if (value === null || value === undefined) return null;
  if (names.length === 0) return value;
  const shape = (row: any) => Object.fromEntries(names.filter((name) => name in row).map((name) => [name, row[name]]));
  return Array.isArray(value) ? value.map(shape) : shape(value);
}

export function execute(request: GraphqlRequest, ctx: GraphqlContext) {
  const match = OPERATION.exec(request.query);
  if (!match) return { errors: [{ message: "unsupported query" }] };
  const [, field, rawArgs = "", rawSelection = ""] = match;
  const resolver = (resolvers.Query as Record<string, Resolver>)[field];
  if (!resolver) return { errors: [{ message: "unknown field " + field }] };
  const args: Record<string, unknown> = {};
  for (const arg of rawArgs.matchAll(ARG)) args[arg[1]] = arg[2] !== undefined ? arg[2] : request.variables[arg[3]];
  return { data: { [field]: project(resolver(args, ctx), rawSelection) } };
}
`);

put("src/routes/graphql.ts", ts`
import { Router } from "express";
import { execute } from "../graphql/executor";
import { createLoaders } from "../graphql/loaders";

export const graphqlRouter = Router();

graphqlRouter.post("/", (req, res) => {
  const user = req.user!;
  const variables = req.body?.variables && typeof req.body.variables === "object" ? req.body.variables : {};
  const result = execute({ query: String(req.body?.query ?? ""), variables }, { user, loaders: createLoaders(user) });
  res.status("errors" in result ? 400 : 200).json(result);
});
`);

// ---------------------------------------------------------------------------------------------------------------
// ws
// ---------------------------------------------------------------------------------------------------------------
put("src/ws/hub.ts", ts`
import { newId } from "../lib/ids";
import type { AuthUser } from "../models/base";

export interface ServerMessage {
  type: string;
  channel?: string;
  message?: string;
  data?: unknown;
}

export interface Session {
  id: string;
  user: AuthUser;
  channels: Set<string>;
  outbox: ServerMessage[];
}

const sessions = new Map<string, Session>();

export const hub = {
  open(user: AuthUser): Session {
    const session: Session = { id: newId("ses"), user, channels: new Set(), outbox: [] };
    sessions.set(session.id, session);
    return session;
  },

  get(id: string): Session | undefined {
    return sessions.get(id);
  },

  close(id: string): void {
    sessions.delete(id);
  },

  join(session: Session, channel: string): void {
    session.channels.add(channel);
  },

  reply(session: Session, message: ServerMessage): void {
    session.outbox.push(message);
  },

  publish(channel: string, message: ServerMessage): void {
    for (const session of sessions.values()) if (session.channels.has(channel)) session.outbox.push(message);
  },
};
`);

put("src/ws/channels.ts", ts`
export interface ChannelTarget {
  kind: string;
  id: string;
}

export function parseChannel(channel: string): ChannelTarget | null {
  const index = channel.indexOf(":");
  if (index <= 0 || index === channel.length - 1) return null;
  return { kind: channel.slice(0, index), id: channel.slice(index + 1) };
}
`);

put("src/ws/handlers.ts", ts`
import { hub } from "./hub";
import type { Session } from "./hub";
import { parseChannel } from "./channels";
import { teamRepo } from "../repositories/teamRepo";
import { ticketCommentRepo, ticketRepo } from "../repositories/ticketRepo";

export interface ClientMessage {
  type?: string;
  channel?: string;
}

export function handleMessage(session: Session, msg: ClientMessage): void {
  if (msg.type === "ping") return hub.reply(session, { type: "pong" });
  if (msg.type === "unsubscribe" && typeof msg.channel === "string") {
    session.channels.delete(msg.channel);
    return;
  }
  if (msg.type !== "subscribe" || typeof msg.channel !== "string") {
    return hub.reply(session, { type: "error", message: "unsupported message" });
  }
  const target = parseChannel(msg.channel);
  if (!target) return hub.reply(session, { type: "error", channel: msg.channel, message: "bad channel" });
  if (target.kind === "ticket") return subscribeTicket(session, msg.channel, target.id);
  if (target.kind === "team") return subscribeTeam(session, msg.channel, target.id);
  hub.reply(session, { type: "error", channel: msg.channel, message: "unknown channel" });
}

function subscribeTicket(session: Session, channel: string, id: string): void {
  const ticket = ticketRepo.findById(id);
  if (!ticket) return hub.reply(session, { type: "error", channel, message: "not found" });
  hub.join(session, channel);
  hub.reply(session, { type: "snapshot", channel, data: { ticket, comments: ticketCommentRepo.forTicket(ticket.id) } });
}

function subscribeTeam(session: Session, channel: string, id: string): void {
  const team = teamRepo.findById(id);
  if (!team || !team.memberIds.includes(session.user.id)) {
    return hub.reply(session, { type: "error", channel, message: "not found" });
  }
  hub.join(session, channel);
  hub.reply(session, { type: "snapshot", channel, data: { team } });
}
`);

put("src/ws/bridge.ts", ts`
import { Router } from "express";
import type { Request } from "express";
import { hub } from "./hub";
import { handleMessage } from "./handlers";

// HTTP bridge for clients that cannot hold a socket open: the same sessions and handlers, polled.
export const realtimeRouter = Router();

const owned = (req: Request) => {
  const session = hub.get(req.params.sid as string);
  return session && session.user.id === req.user!.id ? session : undefined;
};

realtimeRouter.post("/sessions", (req, res) => {
  const session = hub.open(req.user!);
  res.status(201).json({ sessionId: session.id });
});

realtimeRouter.post("/sessions/:sid/messages", (req, res) => {
  const session = owned(req);
  if (!session) return res.status(404).json({ error: "session not found" });
  handleMessage(session, req.body ?? {});
  res.status(202).json({ accepted: true });
});

realtimeRouter.get("/sessions/:sid/events", (req, res) => {
  const session = owned(req);
  if (!session) return res.status(404).json({ error: "session not found" });
  res.json({ events: session.outbox.splice(0) });
});

realtimeRouter.delete("/sessions/:sid", (req, res) => {
  const session = owned(req);
  if (!session) return res.status(404).json({ error: "session not found" });
  hub.close(session.id);
  res.status(204).end();
});
`);

// ---------------------------------------------------------------------------------------------------------------
// integrations
// ---------------------------------------------------------------------------------------------------------------
put("src/integrations/signature.ts", ts`
import { config } from "../lib/config";
import { hmacHex, safeEqual } from "../lib/hmac";

function fresh(timestamp: string): boolean {
  const seconds = Number(timestamp);
  if (!Number.isFinite(seconds)) return false;
  return Math.abs(Math.floor(Date.now() / 1000) - seconds) <= config.webhookToleranceSeconds;
}

/** Payments provider scheme: the signature is an HMAC of the delivery timestamp. */
export function verifyTimestampSignature(timestamp: string, signature: string): boolean {
  if (!fresh(timestamp)) return false;
  return safeEqual(hmacHex(config.webhookSecret, timestamp), signature);
}

/** Carrier scheme: the signature covers the timestamp and the exact body that was delivered. */
export function verifyBodySignature(timestamp: string, body: unknown, signature: string): boolean {
  if (!fresh(timestamp)) return false;
  return safeEqual(hmacHex(config.webhookSecret, timestamp + "." + JSON.stringify(body)), signature);
}
`);

put("src/integrations/paymentWebhook.ts", ts`
import { Router } from "express";
import { verifyTimestampSignature } from "./signature";
import { integrationRepo } from "../repositories/integrationRepo";
import { invoiceRepo } from "../repositories/invoiceRepo";

export const paymentWebhook = Router();

paymentWebhook.post("/", (req, res) => {
  const timestamp = String(req.headers["x-pay-timestamp"] ?? "");
  const signature = String(req.headers["x-pay-signature"] ?? "");
  if (!verifyTimestampSignature(timestamp, signature)) return res.status(401).json({ error: "bad signature" });

  const { event, accountId, invoiceId, reference } = req.body ?? {};
  const account = integrationRepo.findByExternal("payments", String(accountId ?? ""));
  if (!account) return res.status(404).json({ error: "unknown account" });
  if (event !== "payment.settled") return res.json({ received: true });

  const invoice = invoiceRepo.findById(String(invoiceId ?? ""));
  if (!invoice) return res.status(404).json({ error: "invoice not found" });
  invoiceRepo.save({ ...invoice, status: "paid", paidReference: String(reference ?? "") });
  res.json({ received: true, invoice: { id: invoice.id, number: invoice.number, total: invoice.total, currency: invoice.currency, status: "paid" } });
});
`);

put("src/integrations/carrierWebhook.ts", ts`
import { Router } from "express";
import { verifyBodySignature } from "./signature";
import { integrationRepo } from "../repositories/integrationRepo";
import { shipmentRepo } from "../repositories/shipmentRepo";

export const carrierWebhook = Router();

carrierWebhook.post("/", (req, res) => {
  const timestamp = String(req.headers["x-carrier-timestamp"] ?? "");
  const signature = String(req.headers["x-carrier-signature"] ?? "");
  if (!verifyBodySignature(timestamp, req.body, signature)) return res.status(401).json({ error: "bad signature" });

  const { accountId, shipmentId, status } = req.body ?? {};
  const account = integrationRepo.findByExternal("carrier", String(accountId ?? ""));
  if (!account) return res.status(404).json({ error: "unknown account" });
  const shipment = shipmentRepo.getForOrg(account.orgId, String(shipmentId ?? ""));
  if (!shipment) return res.status(404).json({ error: "shipment not found" });
  const next = String(status ?? "").slice(0, 40);
  shipmentRepo.save({ ...shipment, status: next, events: [...shipment.events, { status: next, at: new Date().toISOString() }] });
  res.json({ received: true });
});
`);

put("src/integrations/index.ts", ts`
import { Router } from "express";
import { paymentWebhook } from "./paymentWebhook";
import { carrierWebhook } from "./carrierWebhook";

export const integrationsRouter = Router();

integrationsRouter.use("/payments", paymentWebhook);
integrationsRouter.use("/carrier", carrierWebhook);
`);

// ---------------------------------------------------------------------------------------------------------------
// hand written routes
// ---------------------------------------------------------------------------------------------------------------
put("src/routes/auth.ts", ts`
import { Router } from "express";
import { badRequest } from "../lib/errors";
import { checkPassword } from "../lib/password";
import { signToken } from "../lib/token";
import { userRepo } from "../repositories/userRepo";

export const authRouter = Router();

authRouter.post("/login", (req, res) => {
  const { email, password } = req.body ?? {};
  if (typeof email !== "string" || typeof password !== "string") throw badRequest("email and password are required");
  const user = userRepo.findByEmail(email);
  if (!user || user.disabled || !checkPassword(password, user.passwordHash)) {
    return res.status(401).json({ error: "invalid credentials" });
  }
  res.json({ token: signToken(user.id), user: { id: user.id, orgId: user.orgId, role: user.role } });
});
`);

put("src/routes/me.ts", ts`
import { Router } from "express";
import { userRepo } from "../repositories/userRepo";

export const meRouter = Router();

meRouter.get("/", (req, res) => {
  const me = userRepo.findById(req.user!.id);
  if (!me) return res.status(404).json({ error: "user not found" });
  res.json({ id: me.id, orgId: me.orgId, email: me.email, name: me.name, role: me.role });
});

meRouter.put("/", (req, res) => {
  const me = userRepo.findById(req.user!.id);
  if (!me) return res.status(404).json({ error: "user not found" });
  const name = typeof req.body?.name === "string" ? req.body.name.slice(0, 80) : me.name;
  userRepo.save({ ...me, name });
  res.json({ id: me.id, name });
});
`);

put("src/routes/invoices.ts", ts`
import { Router } from "express";
import { invoiceRepo } from "../repositories/invoiceRepo";
import { invoiceService } from "../services/invoiceService";
import { signShare } from "../lib/shareToken";
import { assertSameOrg } from "../lib/policy";
import { pick } from "../lib/validate";
import { requireRole } from "../middleware/requireRole";

export const invoicesRouter = Router();

invoicesRouter.get("/", (req, res) => {
  res.json(invoiceRepo.listForOrg(req.user!.orgId));
});

invoicesRouter.get("/:id", (req, res) => {
  const invoice = invoiceRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!invoice) return res.status(404).json({ error: "invoice not found" });
  res.json(invoice);
});

invoicesRouter.post("/", (req, res) => {
  res.status(201).json(invoiceService.create(req.user!, req.body));
});

invoicesRouter.put("/:id", (req, res) => {
  const invoice = invoiceRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!invoice) return res.status(404).json({ error: "invoice not found" });
  res.json(invoiceRepo.save({ ...invoice, ...pick(req.body, ["dueDate", "currency"] as const) }));
});

invoicesRouter.post("/:id/void", requireRole("admin", "manager"), (req, res) => {
  const invoice = invoiceRepo.findById(req.params.id);
  if (!invoice) return res.status(404).json({ error: "invoice not found" });
  assertSameOrg(req.user!, invoice, "invoice");
  res.json(invoiceRepo.save({ ...invoice, status: "void" }));
});

invoicesRouter.post("/:id/share", (req, res) => {
  const invoice = invoiceRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!invoice) return res.status(404).json({ error: "invoice not found" });
  res.json({ token: signShare(invoice.id, invoice.orgId, 7 * 24 * 3600) });
});
`);

put("src/routes/publicInvoice.ts", ts`
import { Router } from "express";
import { readShare } from "../lib/shareToken";
import { invoiceRepo } from "../repositories/invoiceRepo";

export const publicRouter = Router();

// Customers open invoices from an emailed link: /public/invoices/<id>?token=<share token>.
publicRouter.get("/invoices/:id", (req, res) => {
  const claims = readShare(String(req.query.token ?? ""));
  if (!claims || claims.inv !== req.params.id) return res.status(404).json({ error: "link not found" });
  const invoice = invoiceRepo.findById(claims.inv);
  if (!invoice || invoice.orgId !== claims.org) return res.status(404).json({ error: "link not found" });
  res.json({ number: invoice.number, status: invoice.status, total: invoice.total, currency: invoice.currency, dueDate: invoice.dueDate });
});
`);

put("src/routes/contracts.ts", ts`
import { Router } from "express";
import { contractService } from "../services/contractService";
import { jobQueue } from "../jobs/queue";
import { pick } from "../lib/validate";
import { contractRepo } from "../repositories/contractRepo";

export const contractsRouter = Router();

contractsRouter.get("/", (req, res) => {
  res.json(contractService.list(req.user!.orgId));
});

contractsRouter.get("/:id", (req, res) => {
  res.json(contractService.get(req.params.id));
});

contractsRouter.get("/:id/summary", (req, res) => {
  res.json(contractService.summarize(contractService.get(req.params.id)));
});

contractsRouter.put("/:id", (req, res) => {
  const contract = contractService.getForOrg(req.user!.orgId, req.params.id);
  res.json(contractRepo.save({ ...contract, ...pick(req.body, ["title", "terms", "endsOn"] as const) }));
});

contractsRouter.post("/:id/renewal-notice", (req, res) => {
  const job = jobQueue.enqueue("contract-renewal", { contractId: req.params.id }, req.user!);
  res.status(202).json({ jobId: job.id, status: job.status });
});
`);

put("src/routes/quotes.ts", ts`
import { Router } from "express";
import { quoteRepo } from "../repositories/quoteRepo";
import { customerRepo } from "../repositories/customerRepo";
import type { Quote } from "../models/billing";

export const quotesRouter = Router();

function renderQuote(quote: Quote, customerName: string): string {
  const rows = quote.lines.map((line) => line.qty + " x " + line.description + " @ " + line.unitPrice);
  return ["QUOTE " + quote.id, quote.title, "For: " + customerName, ...rows, "Total: " + quote.total, "Valid until " + quote.validUntil, "Notes: " + quote.internalNotes].join("\n");
}

quotesRouter.get("/", (req, res) => {
  res.json(quoteRepo.listForOrg(req.user!.orgId));
});

quotesRouter.get("/:id", (req, res) => {
  const quote = quoteRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!quote) return res.status(404).json({ error: "quote not found" });
  res.json(quote);
});

quotesRouter.get("/:id/pdf", (req, res) => {
  const quote = quoteRepo.findById(req.params.id);
  if (!quote) return res.status(404).json({ error: "quote not found" });
  const customer = customerRepo.findForOrg(quote.orgId, quote.customerId);
  res.type("text/plain").send(renderQuote(quote, customer?.name ?? "unknown customer"));
});
`);

put("src/routes/customers.ts", ts`
import { Router } from "express";
import { customerRepo } from "../repositories/customerRepo";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { isoNow, newId } from "../lib/ids";
import type { Customer } from "../models/billing";

const FIELDS = ["name", "email", "billingAddress"] as const;

export const customersRouter = Router();

customersRouter.get("/", (req, res) => {
  res.json(customerRepo.listForOrg(req.user!.orgId));
});

customersRouter.post("/", (req, res) => {
  const data = pick(req.body, FIELDS);
  requireFields(data, ["name", "email"]);
  const customer = customerRepo.insert({ ...data, id: newId("cus"), orgId: req.user!.orgId, createdAt: isoNow() } as Customer);
  res.status(201).json(customer);
});

customersRouter
  .route("/:id")
  .get((req, res) => {
    const customer = customerRepo.findForOrg(req.user!.orgId, req.params.id);
    if (!customer) return res.status(404).json({ error: "customer not found" });
    res.json(customer);
  })
  .put((req, res) => {
    const customer = customerRepo.findForOrg(req.user!.orgId, req.params.id);
    if (!customer) return res.status(404).json({ error: "customer not found" });
    res.json(customerRepo.save({ ...customer, ...pick(req.body, FIELDS) }));
  })
  .delete(requireRole("admin", "manager"), (req, res) => {
    const customer = customerRepo.findForOrg(req.user!.orgId, req.params.id);
    if (!customer) return res.status(404).json({ error: "customer not found" });
    customerRepo.remove(customer.id);
    res.status(204).end();
  });
`);

put("src/routes/products.ts", ts`
import { Router } from "express";
import { productRepo } from "../repositories/productRepo";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { newId } from "../lib/ids";
import type { Product } from "../models/catalog";

const FIELDS = ["sku", "name", "unitPrice", "unitCost", "active"] as const;

export const productsRouter = Router();

productsRouter.get("/", (req, res) => {
  res.json(productRepo.listForOrg(req.user!.orgId));
});

productsRouter.post("/", requireRole("admin", "manager"), (req, res) => {
  const data = pick(req.body, FIELDS);
  requireFields(data, ["sku", "name", "unitPrice"]);
  res.status(201).json(productRepo.insert({ unitCost: 0, active: true, ...data, id: newId("prd"), orgId: req.user!.orgId } as Product));
});

productsRouter.get("/:id", (req, res) => {
  const product = productRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!product) return res.status(404).json({ error: "product not found" });
  res.json(product);
});

productsRouter.put("/:id", requireRole("admin", "manager"), (req, res) => {
  const product = productRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!product) return res.status(404).json({ error: "product not found" });
  res.json(productRepo.save({ ...product, ...pick(req.body, FIELDS) }));
});

productsRouter.delete("/:id", requireRole("admin"), (req, res) => {
  const product = productRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!product) return res.status(404).json({ error: "product not found" });
  productRepo.remove(product.id);
  res.status(204).end();
});
`);

put("src/routes/subscriptions.ts", ts`
import { Router } from "express";
import { subscriptionRepo } from "../repositories/subscriptionRepo";
import { requireRole } from "../middleware/requireRole";

export const subscriptionsRouter = Router();

subscriptionsRouter.get("/", (req, res) => {
  res.json(subscriptionRepo.listForOrg(req.user!.orgId));
});

subscriptionsRouter.get("/:id", (req, res) => {
  const subscription = subscriptionRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!subscription) return res.status(404).json({ error: "subscription not found" });
  res.json(subscription);
});

subscriptionsRouter.post("/:id/cancel", requireRole("admin"), (req, res) => {
  const subscription = subscriptionRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!subscription) return res.status(404).json({ error: "subscription not found" });
  res.json(subscriptionRepo.save({ ...subscription, status: "cancelled" }));
});
`);

put("src/routes/tickets.ts", ts`
import { Router } from "express";
import { ticketService } from "../services/ticketService";
import { badRequest } from "../lib/errors";

export const ticketsRouter = Router();

ticketsRouter.get("/", (req, res) => {
  res.json(ticketService.list(req.user!));
});

ticketsRouter.get("/:id", (req, res) => {
  res.json(ticketService.get(req.user!, req.params.id));
});

ticketsRouter.post("/:id/comments", (req, res) => {
  if (typeof req.body?.body !== "string" || !req.body.body.trim()) throw badRequest("comment body is required");
  res.status(201).json(ticketService.comment(req.user!, req.params.id, req.body.body));
});
`);

put("src/routes/shipments.ts", ts`
import { Router } from "express";
import { shipmentRepo } from "../repositories/shipmentRepo";

export const shipmentsRouter = Router();

shipmentsRouter.get("/", (req, res) => {
  res.json(shipmentRepo.forOrg(req.user!.orgId));
});

shipmentsRouter.get("/:id", (req, res) => {
  const shipment = shipmentRepo.getForOrg(req.user!.orgId, req.params.id);
  if (!shipment) return res.status(404).json({ error: "shipment not found" });
  res.json(shipment);
});
`);

put("src/routes/reports.ts", ts`
import { Router } from "express";
import { carrierTotals, shipmentCostReport, shipmentTimeline } from "../services/reportService";

export const reportsRouter = Router();

reportsRouter.get("/carriers", (req, res) => {
  res.json(carrierTotals(req.user!.orgId));
});

reportsRouter.get("/shipments/:id/costs", (req, res) => {
  res.json(shipmentCostReport(req.params.id));
});

reportsRouter.get("/shipments/:id/timeline", (req, res) => {
  res.json(shipmentTimeline(req.user!.orgId, req.params.id));
});
`);

put("src/routes/imports.ts", ts`
import { Router } from "express";
import { badRequest } from "../lib/errors";
import { previewOrderImport } from "../services/importService";

export const importsRouter = Router();

importsRouter.post("/orders/preview", (req, res) => {
  if (typeof req.body?.csv !== "string" || req.body.csv.length > 200_000) throw badRequest("csv text is required");
  res.json(previewOrderImport(req.user!, req.body.csv));
});
`);

put("src/routes/reminders.ts", ts`
import { Router } from "express";
import { badRequest, notFound } from "../lib/errors";
import { jobQueue } from "../jobs/queue";

export const remindersRouter = Router();

// Send a payment reminder for an invoice to the given address right away.
remindersRouter.post("/", (req, res) => {
  const { invoiceId, to } = req.body ?? {};
  if (typeof invoiceId !== "string" || typeof to !== "string" || !/^[^@\s]+@[^@\s]+$/.test(to)) {
    throw badRequest("invoiceId and a valid recipient are required");
  }
  const job = jobQueue.enqueue("invoice-reminder", { invoiceId, to }, req.user!);
  res.status(202).json({ jobId: job.id, status: job.status });
});

remindersRouter.get("/jobs/:jobId", (req, res) => {
  const job = jobQueue.get(req.params.jobId);
  if (!job || job.orgId !== req.user!.orgId) throw notFound("job");
  res.json({ id: job.id, status: job.status, result: job.result, error: job.error });
});
`);

put("src/routes/payments.ts", ts`
import { Router } from "express";
import { paymentRepo } from "../repositories/billingRepos";

export const paymentsRouter = Router();

paymentsRouter.get("/", (req, res) => {
  res.json(paymentRepo.listForOrg(req.user!.orgId));
});

paymentsRouter.get("/:id", (req, res) => {
  const user = req.user!;
  const payment = paymentRepo.findById(req.params.id);
  if (!payment) return res.status(404).json({ error: "payment not found" });
  if (payment.orgId !== user.orgId) return res.status(404).json({ error: "payment not found" });
  res.json(payment);
});
`);

put("src/routes/creditNotes.ts", ts`
import { Router } from "express";
import { creditNoteRepo } from "../repositories/billingRepos";
import { assertSameOrg } from "../lib/policy";
import { notFound } from "../lib/errors";

export const creditNotesRouter = Router();

creditNotesRouter.get("/", (req, res) => {
  res.json(creditNoteRepo.listForOrg(req.user!.orgId));
});

creditNotesRouter.get("/:id", (req, res) => {
  const note = creditNoteRepo.findById(req.params.id);
  if (!note) throw notFound("credit note");
  assertSameOrg(req.user!, note, "credit note");
  res.json(note);
});
`);

put("src/routes/refunds.ts", ts`
import { Router } from "express";
import { refundRepo } from "../repositories/billingRepos";
import { refundPolicy } from "../lib/policy";

export const refundsRouter = Router();

refundsRouter.get("/", (req, res) => {
  res.json(refundRepo.listForOrg(req.user!.orgId));
});

refundsRouter.get("/:id", (req, res) => {
  const refund = refundRepo.findById(req.params.id);
  if (!refund || !refundPolicy.canView(req.user!, refund)) return res.status(404).json({ error: "refund not found" });
  res.json(refund);
});
`);

put("src/routes/reference.ts", ts`
import { Router } from "express";
import { countryRepo, currencyRepo, planRepo } from "../repositories/referenceRepos";

export const referenceRouter = Router();

referenceRouter.get("/currencies", (_req, res) => {
  res.json(currencyRepo.list());
});

referenceRouter.get("/currencies/:id", (req, res) => {
  const currency = currencyRepo.findById(req.params.id.toUpperCase());
  if (!currency) return res.status(404).json({ error: "currency not found" });
  res.json(currency);
});

referenceRouter.get("/countries/:id", (req, res) => {
  const country = countryRepo.findById(req.params.id.toUpperCase());
  if (!country) return res.status(404).json({ error: "country not found" });
  res.json(country);
});

referenceRouter.get("/plans/:id", (req, res) => {
  const plan = planRepo.findById(req.params.id);
  if (!plan) return res.status(404).json({ error: "plan not found" });
  res.json(plan);
});
`);

put("src/routes/internal.ts", ts`
import { Router } from "express";
import { invoiceRepo } from "../repositories/invoiceRepo";

// Mounted behind the service token; used by the billing workers.
export const internalRouter = Router();

internalRouter.get("/invoices/:id", (req, res) => {
  const invoice = invoiceRepo.findById(req.params.id);
  if (!invoice) return res.status(404).json({ error: "invoice not found" });
  res.json(invoice);
});

internalRouter.get("/orgs/:orgId/usage", (req, res) => {
  res.json({ orgId: req.params.orgId, invoices: invoiceRepo.listForOrg(req.params.orgId).length });
});
`);

// api router + app
const handRouters = [
  ["me", "meRouter", "me"], ["invoices", "invoicesRouter", "invoices"], ["contracts", "contractsRouter", "contracts"], ["quotes", "quotesRouter", "quotes"],
  ["customers", "customersRouter", "customers"], ["products", "productsRouter", "products"], ["subscriptions", "subscriptionsRouter", "subscriptions"],
  ["tickets", "ticketsRouter", "tickets"], ["shipments", "shipmentsRouter", "shipments"], ["reports", "reportsRouter", "reports"], ["imports", "importsRouter", "imports"],
  ["reminders", "remindersRouter", "reminders"], ["payments", "paymentsRouter", "payments"], ["creditNotes", "creditNotesRouter", "credit-notes"],
  ["refunds", "refundsRouter", "refunds"], ["reference", "referenceRouter", "reference"],
];
put("src/routes/index.ts", `import { Router } from "express";
${handRouters.map(([file, name]) => `import { ${name} } from "./${file}";`).join("\n")}
${FILLERS.map((s) => `import { ${s.key}Router } from "./${s.key}";`).join("\n")}

export const apiRouter = Router();

${handRouters.map(([, name, path]) => `apiRouter.use("/${path}", ${name});`).join("\n")}
${FILLERS.map((s) => `apiRouter.use("/${s.path}", ${s.key}Router);`).join("\n")}
`);

put("src/app.ts", ts`
import express from "express";
import { authenticate } from "./middleware/authenticate";
import { errorHandler } from "./middleware/errorHandler";
import { requestLog } from "./middleware/requestLog";
import { serviceToken } from "./middleware/serviceToken";
import { apiRouter } from "./routes/index";
import { authRouter } from "./routes/auth";
import { graphqlRouter } from "./routes/graphql";
import { internalRouter } from "./routes/internal";
import { publicRouter } from "./routes/publicInvoice";
import { integrationsRouter } from "./integrations/index";
import { realtimeRouter } from "./ws/bridge";
import { registerJobs } from "./jobs/registry";
import { seedDemoData } from "./seed";

export function createApp() {
  seedDemoData();
  registerJobs();
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "1mb" }));
  app.use(requestLog);
  app.use("/public", publicRouter);
  app.use("/api/auth", authRouter);
  app.use("/api/internal", serviceToken, internalRouter);
  app.use("/integrations", integrationsRouter);
  app.use("/graphql", authenticate, graphqlRouter);
  app.use("/rt", authenticate, realtimeRouter);
  app.use("/api", authenticate, apiRouter);
  app.use(errorHandler);
  return app;
}
`);

put("src/server.ts", ts`
import { createApp } from "./app";
import { config } from "./lib/config";

createApp().listen(config.port, () => {
  console.log("tenantly api listening on " + config.port);
});
`);

// ---------------------------------------------------------------------------------------------------------------
// anchors -> line ranges
// ---------------------------------------------------------------------------------------------------------------
const lineCache = new Map();
const linesOf = (path) => {
  if (!files.has(path)) throw new Error(`no such file ${path}`);
  if (!lineCache.has(path)) lineCache.set(path, files.get(path).split("\n"));
  return lineCache.get(path);
};
/** from: substring of the first line; to: exact trimmed text of the closing line (searched from the first line on). */
function block(path, from, to) {
  const lines = linesOf(path);
  const start = lines.findIndex((l) => l.includes(from));
  if (start < 0) throw new Error(`anchor not found in ${path}: ${from}`);
  let end = -1;
  for (let i = start; i < lines.length; i++) if (lines[i].trim() === to) { end = i; break; }
  if (end < 0) throw new Error(`end anchor not found in ${path}: ${to}`);
  return { path, startLine: start + 1, endLine: end + 1 };
}

const seedRange = block("src/routes/invoices.ts", 'invoicesRouter.get("/:id"', "});");
const seed = {
  ...seedRange,
  title: "Any signed-in user can read any tenant's invoice by id",
  category: "broken-access-control",
  severity: "high",
  description:
    "GET /api/invoices/:id returned any tenant's invoice to any signed-in user because the route loaded the record with the unscoped invoiceRepo.findById(id) and never compared its orgId with the caller's. The fix scoped the lookup to the caller's organisation with invoiceRepo.findForOrg(req.user.orgId, id).",
};

const items = [
  {
    id: "vt-contract-service",
    ...block("src/services/contractService.ts", "get(id: string): Contract {", "},"),
    category: "authz",
    description: "contractService.get loads a contract by id with contractRepo.findById and never compares its orgId with the caller's; the routes GET /api/contracts/:id and /:id/summary return other tenants' contracts through it",
    alsoAt: [
      block("src/routes/contracts.ts", 'contractsRouter.get("/:id",', "});"),
      block("src/routes/contracts.ts", 'contractsRouter.get("/:id/summary"', "});"),
    ],
    oracle: { mention: ["contract"], lineSlack: 3 },
    probe: "contract service lookup",
  },
  {
    id: "vt-quote-pdf",
    ...block("src/routes/quotes.ts", 'quotesRouter.get("/:id/pdf"', "});"),
    category: "authz",
    description: "the quote pdf route inlines quoteRepo.findById and renders any tenant's quote, including internal notes, for any signed-in user",
    alsoAt: [],
    oracle: { mention: ["quote", "pdf"], lineSlack: 3 },
    probe: "quote pdf",
  },
  {
    id: "vt-reminder-job",
    ...block("src/jobs/reminderJob.ts", "export async function invoiceReminder", "}"),
    category: "authz",
    description: "the invoice reminder job loads the invoice from the job payload with invoiceRepo.findById and does not compare its orgId with the job's org; POST /api/reminders enqueues it with a caller-supplied invoiceId and the rendered invoice comes back from the job status endpoint and is mailed to a caller-chosen address",
    alsoAt: [block("src/routes/reminders.ts", 'remindersRouter.post("/"', "});")],
    oracle: { mention: ["remind", "job", "queue"], lineSlack: 3 },
    probe: "reminder job",
  },
  {
    id: "vt-graphql-subscription",
    ...block("src/graphql/resolvers.ts", "subscription: (args: Args) => {", "},"),
    category: "authz",
    description: "the graphql subscription resolver loads a subscription by id with subscriptionRepo.findById and ignores the caller's org, so POST /graphql returns other tenants' subscription data (plan, seats, amount, card digits)",
    alsoAt: [block("src/routes/graphql.ts", 'graphqlRouter.post("/"', "});")],
    oracle: { mention: ["graphql", "resolver", "subscription"], lineSlack: 3 },
    probe: "graphql subscription resolver",
  },
  {
    id: "vt-ws-ticket-subscribe",
    ...block("src/ws/handlers.ts", "function subscribeTicket", "}"),
    category: "authz",
    description: "the realtime message handler's subscribe to ticket:<id> loads the ticket with ticketRepo.findById and joins the channel without an org or membership check, so any signed-in user receives another tenant's ticket and comments (websocket-style channel subscription)",
    alsoAt: [block("src/ws/handlers.ts", 'if (target.kind === "ticket")', 'if (target.kind === "ticket") return subscribeTicket(session, msg.channel, target.id);')],
    oracle: { mention: ["websocket", "subscribe", "channel", "realtime", "ticket"], lineSlack: 3 },
    probe: "websocket ticket channel subscribe",
  },
  {
    id: "vt-import-product",
    ...block("src/services/importService.ts", "function resolveProduct", "}"),
    category: "authz",
    description: "the order import preview resolves productId references with productRepo.findById, so a csv naming another tenant's product id returns that product's name, price and unit cost",
    alsoAt: [block("src/services/importService.ts", "const product = resolveProduct", 'if (!product) return void problems.push("line " + line + ": unknown product");')],
    oracle: { mention: ["import", "csv", "product"], lineSlack: 3 },
    probe: "csv import product preview",
  },
  {
    id: "vt-report-shipment",
    ...block("src/services/reportService.ts", "export function shipmentCostReport", 'if (!shipment) throw notFound("shipment");'),
    category: "authz",
    description: "the shipment cost report loads the shipment through shipmentRepo.get(id), which is a plain lookup by id, so GET /api/reports/shipments/:id/costs returns other tenants' carrier cost, billed amount and margin",
    alsoAt: [
      block("src/routes/reports.ts", 'reportsRouter.get("/shipments/:id/costs"', "});"),
      block("src/repositories/shipmentRepo.ts", "get(id: string)", "}"),
    ],
    oracle: { mention: ["report", "shipment"], lineSlack: 3 },
    probe: "shipment report",
  },
  {
    id: "vt-payment-webhook",
    ...block("src/integrations/paymentWebhook.ts", "const invoice = invoiceRepo.findById", 'invoiceRepo.save({ ...invoice, status: "paid", paidReference: String(reference ?? "") });'),
    category: "authz",
    description: "the inbound payments webhook accepts any body under a signature that only covers the timestamp, looks the account up but then loads the invoice by the payload's invoiceId with invoiceRepo.findById and marks it paid without comparing its org to the account's, so a replayed signature can settle or read another tenant's invoice",
    alsoAt: [],
    oracle: { mention: ["webhook", "inbound", "integration", "payment"], lineSlack: 3 },
    probe: "payment webhook",
  },
];

const decoyDefs = [
  ["vt-decoy-payments-inline", "src/routes/payments.ts", 'paymentsRouter.get("/:id"', "});", "findById followed by an inline orgId comparison"],
  ["vt-decoy-credit-notes", "src/routes/creditNotes.ts", 'creditNotesRouter.get("/:id"', "});", "findById followed by assertSameOrg"],
  ["vt-decoy-refunds-policy", "src/routes/refunds.ts", 'refundsRouter.get("/:id"', "});", "findById checked by the refund policy object"],
  ["vt-decoy-invoice-void", "src/routes/invoices.ts", 'invoicesRouter.post("/:id/void"', "});", "findById followed by assertSameOrg"],
  ["vt-decoy-invoice-share", "src/routes/invoices.ts", 'invoicesRouter.post("/:id/share"', "});", "scoped lookup with findForOrg before minting a share token"],
  ["vt-decoy-internal-invoice", "src/routes/internal.ts", 'internalRouter.get("/invoices/:id"', "});", "findById behind the service token middleware"],
  ["vt-decoy-public-invoice", "src/routes/publicInvoice.ts", 'publicRouter.get("/invoices/:id"', "});", "public link keyed by a signed share token that binds and is verified against the invoice id and org"],
  ["vt-decoy-reference-currency", "src/routes/reference.ts", 'referenceRouter.get("/currencies/:id"', "});", "findById on global reference data without orgId"],
  ["vt-decoy-reference-plan", "src/routes/reference.ts", 'referenceRouter.get("/plans/:id"', "});", "findById on global reference data without orgId"],
  ["vt-decoy-me", "src/routes/me.ts", 'meRouter.get("/"', "});", "lookup by the caller's own user id from the session"],
  ["vt-decoy-renewal-job", "src/jobs/renewalJob.ts", "export async function contractRenewal", "}", "job re-validates the contract's org against the job org before use"],
  ["vt-decoy-graphql-customer", "src/graphql/resolvers.ts", "customer: (args: Args, ctx: GraphqlContext) => {", "},", "resolver goes through the org scoped data loader"],
  ["vt-decoy-ws-team", "src/ws/handlers.ts", "function subscribeTeam", "}", "subscribe checks team membership of the session user"],
  ["vt-decoy-import-customer", "src/services/importService.ts", "function resolveCustomer", "}", "import step uses findForOrg"],
  ["vt-decoy-contract-for-org", "src/services/contractService.ts", "getForOrg(orgId: string, id: string): Contract {", "},", "service method uses findForOrg"],
  ["vt-decoy-quote-get", "src/routes/quotes.ts", 'quotesRouter.get("/:id",', "});", "quote read uses findForOrg"],
  ["vt-decoy-shipment-timeline", "src/services/reportService.ts", "export function shipmentTimeline", "}", "report uses the org scoped getForOrg helper"],
  ["vt-decoy-carrier-webhook", "src/integrations/carrierWebhook.ts", 'carrierWebhook.post("/"', "});", "signature covers the body and the shipment is loaded inside the account's org"],
];
const decoys = decoyDefs.map(([id, path, from, to, description]) => ({ id, ...block(path, from, to), category: "authz", description }));

const cleanPaths = [
  ...FILLERS.map((s) => `src/routes/${s.key}.ts`),
  ...GROUPS.flatMap((g) => [`src/models/${g}.ts`, `src/repositories/${g}Repos.ts`]),
  "src/routes/customers.ts", "src/routes/products.ts", "src/routes/subscriptions.ts", "src/routes/tickets.ts", "src/routes/shipments.ts", "src/routes/auth.ts",
  "src/services/ticketService.ts", "src/services/invoiceService.ts",
  "src/lib/validate.ts", "src/lib/ids.ts", "src/lib/errors.ts", "src/lib/hmac.ts", "src/lib/token.ts", "src/lib/csv.ts", "src/lib/mailer.ts", "src/lib/password.ts", "src/lib/config.ts",
  "src/middleware/authenticate.ts", "src/middleware/requireRole.ts", "src/middleware/errorHandler.ts", "src/middleware/requestLog.ts",
].sort();

const answer = { fixture: "variants-tenant", skill: null, seed, cleanPaths, items: items.map(({ probe, ...rest }) => rest), decoys };
put("answer.json", JSON.stringify(answer, null, 2) + "\n");

// ---------------------------------------------------------------------------------------------------------------
// validation
// ---------------------------------------------------------------------------------------------------------------
const fileLines = Object.fromEntries([...files].filter(([p]) => p !== "answer.json").map(([p, t]) => [p, t.split("\n").length - 1]));
const problems = validateAnswer(answer, { fileLines });
if (!fileLines[seed.path] || seed.endLine > fileLines[seed.path]) problems.push("seed range outside its file");
const spans = [...answer.items, ...answer.decoys, { id: "seed", ...seed }];
for (let i = 0; i < spans.length; i++) for (let j = i + 1; j < spans.length; j++) {
  const a = spans[i], b = spans[j];
  if (a.path === b.path && a.startLine <= b.endLine && b.startLine <= a.endLine) problems.push(`ranges overlap: ${a.id} and ${b.id}`);
}
for (const item of answer.items) if (item.endLine - item.startLine + 1 < 3 || item.endLine - item.startLine + 1 > 12) problems.push(`${item.id}: range of ${item.endLine - item.startLine + 1} lines is outside 3-12`);
if (answer.decoys.length < 12) problems.push("fewer than 12 decoys");
const fileCount = [...files.keys()].length;
if (fileCount < 70 || fileCount > 120) problems.push(`file count ${fileCount} outside 70-120`);
const banned = /vulnerab|\bbug|bug\b|flaw|exploit|insecure|\bidor\b|todo|fixme|missing check|should check|unsafe|attack|leak|legacy|unscoped|competitor/i;
for (const [p, t] of files) if (p !== "answer.json" && banned.test(t)) problems.push(`banned word in ${p}: ${banned.exec(t)[0]}`);
// Dry scoring: synthetic findings placed on each item credit it, and the oracle rejects a neighbouring finding's text.
const synthetic = items.map((it, i) => ({ id: `s${i}`, title: `Other tenant can read ${it.probe}`, description: `${it.probe} lacks a tenant check`, category: "broken-access-control", location: { path: it.path, startLine: it.startLine + 1 } }));
const dry = scoreFindings(answer, synthetic);
if (dry.found !== answer.items.length) problems.push(`synthetic findings found ${dry.found}/${answer.items.length}`);
if (problems.length) {
  console.error(problems.join("\n"));
  process.exit(1);
}

// ---------------------------------------------------------------------------------------------------------------
// write
// ---------------------------------------------------------------------------------------------------------------
rmSync(outDir, { recursive: true, force: true });
for (const [path, text] of [...files].sort(([a], [b]) => (a < b ? -1 : 1))) {
  const target = join(outDir, path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, text);
}

const coreScoped = [
  { name: "customers", path: "/api/customers", id: "cus_a1", methods: ["GET", "PUT", "DELETE"] },
  { name: "products", path: "/api/products", id: "prd_a1", methods: ["GET", "PUT", "DELETE"] },
  { name: "subscriptions", path: "/api/subscriptions", id: "sub_a1", methods: ["GET"] },
  { name: "tickets", path: "/api/tickets", id: "tkt_a1", methods: ["GET"] },
  { name: "shipments", path: "/api/shipments", id: "shp_a1", methods: ["GET"] },
  { name: "invoices-put", path: "/api/invoices", id: "inv_a1", methods: ["PUT"] },
];
const manifest = {
  routes: [...coreScoped, ...FILLERS.map((s) => ({ name: s.key, path: "/api/" + s.path, id: s.prefix + "_a1", methods: ["GET", "PUT", "DELETE"] }))],
};
mkdirSync(proofDir, { recursive: true });
writeFileSync(join(proofDir, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");

console.log(`variants-tenant: ${fileCount} files, ${items.length} items, ${decoys.length} decoys, ${cleanPaths.length} clean paths`);
