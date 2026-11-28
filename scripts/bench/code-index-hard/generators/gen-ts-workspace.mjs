#!/usr/bin/env node
// Generates the ts-workspace fixture (Express/TypeScript, layered, multi-tenant) and its answer key.
//   node scripts/bench/code-index-hard/generators/gen-ts-workspace.mjs
// Hand-written core files live in ./ts-workspace/core-*.txt (split on "//// FILE: <path>"). The filler modules are
// generated from the table below; every one is correctly authorised (three different styles). Answer-key line numbers
// are computed from anchor strings searched in the generated files, so the key cannot drift from the code.
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, "..", "fixtures", "ts-workspace");
const proofDir = join(here, "..", "proofs", "ts-workspace");

const files = new Map();
for (const name of readdirSync(join(here, "ts-workspace")).filter((n) => /^core-.*\.txt$/.test(n)).sort()) {
  const parts = readFileSync(join(here, "ts-workspace", name), "utf8").split(/^\/\/\/\/ FILE: (.+)\n/m);
  for (let i = 1; i < parts.length; i += 2) files.set(parts[i], parts[i + 1].replace(/\n+$/, "\n"));
}

files.set("src/lib/validate.ts", `import { badRequest } from "./http";

export function str(value: unknown, max: number): string {
  if (typeof value !== "string" || !value.trim()) throw badRequest("text value required");
  return value.trim().slice(0, max);
}

export function num(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) throw badRequest("number required");
  return parsed;
}

export function bool(value: unknown): boolean {
  return value === true || value === "true";
}
`);

// ---- filler modules -------------------------------------------------------------------------------------------
const S = "string", N = "number", B = "boolean";
const MODULES = [
  ["label", "labels", [["name", S], ["color", S]], "A", false],
  ["milestone", "milestones", [["title", S], ["dueOn", S]], "B", true],
  ["note", "notes", [["title", S], ["body", S]], "A", true],
  ["sprint", "sprints", [["name", S], ["goal", S], ["capacity", N]], "C", false],
  ["epic", "epics", [["name", S], ["summary", S]], "A", false],
  ["reminder", "reminders", [["message", S], ["remindAt", S]], "B", false],
  ["tag", "tags", [["name", S]], "C", true],
  ["template", "templates", [["name", S], ["body", S]], "A", true],
  ["automation", "automations", [["name", S], ["trigger", S], ["enabled", B]], "B", false],
  ["integrationLink", "integration-links", [["provider", S], ["externalId", S]], "C", false],
  ["apiKey", "api-keys", [["label", S], ["scope", S]], "A", false],
  ["notification", "notifications", [["title", S], ["channel", S]], "B", true],
  ["dashboard", "dashboards", [["name", S], ["layout", S]], "A", false],
  ["goal", "goals", [["name", S], ["target", N]], "C", true],
  ["timesheet", "timesheets", [["weekOf", S], ["hours", N]], "B", false],
  ["release", "releases", [["version", S], ["notes", S]], "A", true],
  ["component", "components", [["name", S], ["lead", S]], "C", false],
  ["approval", "approvals", [["subject", S], ["state", S]], "B", false],
  ["poll", "polls", [["question", S], ["closesOn", S]], "A", false],
  ["checklist", "checklists", [["title", S], ["items", S]], "C", true],
  ["customField", "custom-fields", [["name", S], ["kind", S]], "B", true],
];

const Pascal = (s) => s[0].toUpperCase() + s.slice(1);
const kebab = (s) => s.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);
const tsType = (t) => t;
const sample = (name, type) => (type === N ? 3 : type === B ? true : `sample ${name}`);

const manifest = [];
const fillerPaths = [];
const fillerImports = [];
const fillerMounts = [];
const seedImports = [];
const seedBody = [];

for (const [name, plural, fields, style, extras] of MODULES) {
  const P = Pascal(name);
  const repo = `${name}Repo`, svc = `${name}Service`, router = `${plural.replace(/-./g, (m) => m[1].toUpperCase())}Router`;
  const fieldLines = fields.map(([f, t]) => `  ${f}: ${tsType(t)};`).join("\n");
  const inputType = fields.map(([f, t]) => `${f}: ${tsType(t)}`).join("; ");
  const parseBody = fields.map(([f, t]) => `    ${f}: ${t === N ? `num(input.${f})` : t === B ? `bool(input.${f})` : `str(input.${f}, 200)`},`).join("\n");
  const paths = { model: `src/models/${name}.ts`, repo: `src/repositories/${repo}.ts`, service: `src/services/${svc}.ts`, route: `src/routes/${plural.replace(/-./g, (m) => m[1].toUpperCase())}.ts`, validator: `src/validators/${name}.ts` };
  fillerPaths.push(...Object.values(paths));

  files.set(paths.model, `export interface ${P} {
  id: string;
  orgId: string;
  ownerId: string;
${fieldLines}
${extras ? "  archived: boolean;\n" : ""}  createdAt: string;
}
`);

  files.set(paths.validator, `import { bool, num, str } from "../lib/validate";

export interface ${P}Input {
  ${fields.map(([f, t]) => `${f}: ${tsType(t)};`).join("\n  ")}
}

export function parse${P}Input(body: unknown): ${P}Input {
  const input = (body ?? {}) as Record<string, unknown>;
  return {
${parseBody}
  };
}
`.replace(/import \{ bool, num, str \}/, `import { ${["bool", "num", "str"].filter((h) => fields.some(([, t]) => (h === "num" ? t === N : h === "bool" ? t === B : t === S))).join(", ")} }`));

  const repoBase = `import { Table } from "../db";
import type { ${P} } from "../models/${name}";

const table = new Table<${P}>("${plural.replace(/-/g, "_")}");
`;
  if (style === "C") {
    files.set(paths.repo, `${repoBase}
export const ${repo} = {
  getInOrg(orgId: string, id: string) {
    const row = table.get(id);
    return row && row.orgId === orgId ? row : undefined;
  },
  listForOrg: (orgId: string) => table.where((r) => r.orgId === orgId),
  insert: (row: ${P}) => table.insert(row),
  updateInOrg(orgId: string, id: string, patch: Partial<${P}>) {
    const row = table.get(id);
    return row && row.orgId === orgId ? table.update(id, patch) : undefined;
  },
  removeInOrg(orgId: string, id: string) {
    const row = table.get(id);
    return row && row.orgId === orgId ? table.remove(id) : false;
  },
};
`);
  } else {
    files.set(paths.repo, `${repoBase}
export const ${repo} = {
  get: (id: string) => table.get(id),
  listForOrg: (orgId: string) => table.where((r) => r.orgId === orgId),
  insert: (row: ${P}) => table.insert(row),
  update: (id: string, patch: Partial<${P}>) => table.update(id, patch),
  remove: (id: string) => table.remove(id),
};
`);
  }

  const newRow = (orgExpr, ownerExpr) => `{ id: newId("${kebab(name)}"), orgId: ${orgExpr}, ownerId: ${ownerExpr}, ...input, ${extras ? "archived: false, " : ""}createdAt: now() }`;

  if (style === "A") {
    files.set(paths.service, `import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { forbidden, notFound } from "../lib/http";
import { ${repo} } from "../repositories/${repo}";
import type { ${P}Input } from "../validators/${name}";
import type { User } from "../models/user";

export const ${svc} = {
  require(user: User, id: string) {
    const row = ${repo}.get(id);
    if (!row || row.orgId !== user.orgId) throw notFound();
    return row;
  },

  requireWritable(user: User, id: string) {
    const row = ${svc}.require(user, id);
    if (row.ownerId !== user.id && user.role === "member") throw forbidden();
    return row;
  },

  list(user: User) {
    return ${repo}.listForOrg(user.orgId);
  },

  create(user: User, input: ${P}Input) {
    return ${repo}.insert(${newRow("user.orgId", "user.id")});
  },

  update(user: User, id: string, input: ${P}Input) {
    const row = ${svc}.requireWritable(user, id);
    return ${repo}.update(row.id, input);
  },

  remove(user: User, id: string) {
    const row = ${svc}.requireWritable(user, id);
    ${repo}.remove(row.id);
  },
${extras ? `
  archive(user: User, id: string) {
    const row = ${svc}.requireWritable(user, id);
    return ${repo}.update(row.id, { archived: true });
  },
` : ""}};
`);
    files.set(paths.route, `import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { ${svc} } from "../services/${svc}";
import { parse${P}Input } from "../validators/${name}";

export const ${router} = Router();
const who = (req: unknown) => (req as AuthedRequest).user;

${router}.get("/", (req, res) => {
  res.json(${svc}.list(who(req)));
});

${router}.post("/", (req, res) => {
  res.status(201).json(${svc}.create(who(req), parse${P}Input(req.body)));
});

${router}.get("/:id", (req, res) => {
  res.json(${svc}.require(who(req), req.params.id));
});

${router}.put("/:id", (req, res) => {
  res.json(${svc}.update(who(req), req.params.id, parse${P}Input(req.body)));
});

${router}.delete("/:id", (req, res) => {
  ${svc}.remove(who(req), req.params.id);
  res.sendStatus(204);
});
${extras ? `
${router}.post("/:id/archive", (req, res) => {
  res.json(${svc}.archive(who(req), req.params.id));
});
` : ""}`);
  } else if (style === "B") {
    files.set(paths.service, `import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { ${repo} } from "../repositories/${repo}";
import type { ${P} } from "../models/${name}";
import type { ${P}Input } from "../validators/${name}";

export const ${svc} = {
  list(orgId: string) {
    return ${repo}.listForOrg(orgId);
  },

  create(orgId: string, ownerId: string, input: ${P}Input) {
    return ${repo}.insert(${newRow("orgId", "ownerId")});
  },

  update(row: ${P}, input: ${P}Input) {
    return ${repo}.update(row.id, input);
  },

  remove(row: ${P}) {
    ${repo}.remove(row.id);
  },
${extras ? `
  archive(row: ${P}) {
    return ${repo}.update(row.id, { archived: true });
  },
` : ""}};
`);
    files.set(paths.route, `import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { ${repo} } from "../repositories/${repo}";
import { ${svc} } from "../services/${svc}";
import { parse${P}Input } from "../validators/${name}";
import type { ${P} } from "../models/${name}";
import type { User } from "../models/user";

export const ${router} = Router();
const canWrite = (user: User, row: ${P}) => row.ownerId === user.id || user.role !== "member";

${router}.param("id", (req, res, next, id) => {
  const row = ${repo}.get(id);
  if (!row || row.orgId !== (req as AuthedRequest).org) return res.sendStatus(404);
  res.locals.row = row;
  next();
});

${router}.get("/", (req, res) => {
  res.json(${svc}.list((req as AuthedRequest).org));
});

${router}.post("/", (req, res) => {
  const authed = req as AuthedRequest;
  res.status(201).json(${svc}.create(authed.org, authed.user.id, parse${P}Input(req.body)));
});

${router}.get("/:id", (_req, res) => {
  res.json(res.locals.row);
});

${router}.put("/:id", (req, res) => {
  if (!canWrite((req as AuthedRequest).user, res.locals.row)) return res.sendStatus(403);
  res.json(${svc}.update(res.locals.row, parse${P}Input(req.body)));
});

${router}.delete("/:id", (req, res) => {
  if (!canWrite((req as AuthedRequest).user, res.locals.row)) return res.sendStatus(403);
  ${svc}.remove(res.locals.row);
  res.sendStatus(204);
});
${extras ? `
${router}.post("/:id/archive", (req, res) => {
  if (!canWrite((req as AuthedRequest).user, res.locals.row)) return res.sendStatus(403);
  res.json(${svc}.archive(res.locals.row));
});
` : ""}`);
  } else {
    files.set(paths.service, `import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { forbidden, notFound } from "../lib/http";
import { ${repo} } from "../repositories/${repo}";
import type { ${P}Input } from "../validators/${name}";
import type { User } from "../models/user";

function requireManager(user: User) {
  if (user.role === "member") throw forbidden();
}

export const ${svc} = {
  require(user: User, id: string) {
    const row = ${repo}.getInOrg(user.orgId, id);
    if (!row) throw notFound();
    return row;
  },

  list(user: User) {
    return ${repo}.listForOrg(user.orgId);
  },

  create(user: User, input: ${P}Input) {
    requireManager(user);
    return ${repo}.insert(${newRow("user.orgId", "user.id")});
  },

  update(user: User, id: string, input: ${P}Input) {
    requireManager(user);
    const row = ${repo}.updateInOrg(user.orgId, id, input);
    if (!row) throw notFound();
    return row;
  },

  remove(user: User, id: string) {
    requireManager(user);
    if (!${repo}.removeInOrg(user.orgId, id)) throw notFound();
  },
${extras ? `
  archive(user: User, id: string) {
    requireManager(user);
    const row = ${repo}.updateInOrg(user.orgId, id, { archived: true });
    if (!row) throw notFound();
    return row;
  },
` : ""}};
`);
    files.set(paths.route, `import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { ${svc} } from "../services/${svc}";
import { parse${P}Input } from "../validators/${name}";

export const ${router} = Router();
const who = (req: unknown) => (req as AuthedRequest).user;

${router}.get("/", (req, res) => {
  res.json(${svc}.list(who(req)));
});

${router}.post("/", (req, res) => {
  res.status(201).json(${svc}.create(who(req), parse${P}Input(req.body)));
});

${router}.get("/:id", (req, res) => {
  res.json(${svc}.require(who(req), req.params.id));
});

${router}.put("/:id", (req, res) => {
  res.json(${svc}.update(who(req), req.params.id, parse${P}Input(req.body)));
});

${router}.delete("/:id", (req, res) => {
  ${svc}.remove(who(req), req.params.id);
  res.sendStatus(204);
});
${extras ? `
${router}.post("/:id/archive", (req, res) => {
  res.json(${svc}.archive(who(req), req.params.id));
});
` : ""}`);
  }

  const routeFile = paths.route.replace(/^src\/routes\//, "./").replace(/\.ts$/, "");
  fillerImports.push(`import { ${router} } from "${routeFile}";`);
  fillerMounts.push(`apiRouter.use("/${plural}", ${router});`);
  seedImports.push(`import { ${repo} } from "./repositories/${repo}";`);
  const val = (v) => (typeof v === "string" ? JSON.stringify(v) : String(v));
  const rec = (suffix, org, owner) => `${repo}.insert({ id: "${kebab(name)}_${suffix}", orgId: "${org}", ownerId: "${owner}", ${fields.map(([f, t]) => `${f}: ${val(sample(f, t))}`).join(", ")}, ${extras ? "archived: false, " : ""}createdAt: at });`;
  seedBody.push(`  ${rec("a1", "org_acme", "usr_alice")}`, `  ${rec("a2", "org_acme", "usr_alice")}`, `  ${rec("g1", "org_globex", "usr_carol")}`);

  const body = Object.fromEntries(fields.map(([f, t]) => [f, sample(f, t)]));
  const entry = (method, path, expectCross, expectMember, withBody) => manifest.push({ module: name, method, path, ...(withBody ? { body } : {}), crossOrgManager: expectCross, sameOrgMember: expectMember });
  entry("GET", `/api/${plural}/${kebab(name)}_a1`, [403, 404], [200]);
  entry("PUT", `/api/${plural}/${kebab(name)}_a1`, [403, 404], [403], true);
  entry("DELETE", `/api/${plural}/${kebab(name)}_a1`, [403, 404], [403]);
  if (extras) entry("POST", `/api/${plural}/${kebab(name)}_a1/archive`, [403, 404], [403]);
}

files.set("src/routes/index.ts", files.get("src/routes/index.ts").replace("//@FILLER_IMPORTS", fillerImports.join("\n")).replace("//@FILLER_MOUNTS", fillerMounts.join("\n")));
files.set("src/seed.ts", files.get("src/seed.ts").replace("//@FILLER_SEED_IMPORTS", seedImports.join("\n")).replace("//@FILLER_SEED", seedBody.join("\n")));

// ---- answer key -----------------------------------------------------------------------------------------------
const lines = (p) => files.get(p).split("\n");
function lineOf(p, needle, from = 0) {
  const i = lines(p).findIndex((l, idx) => idx >= from && l.includes(needle));
  if (i < 0) throw new Error(`anchor not found in ${p}: ${needle}`);
  return i + 1;
}
/** Range of the statement starting at the line containing `needle` and ending at the closing brace at the same indent. */
function block(p, needle, from = 0) {
  const start = lineOf(p, needle, from);
  const ls = lines(p);
  const indent = ls[start - 1].match(/^\s*/)[0];
  for (let i = start; i < ls.length; i++) if ((ls[i].startsWith(`${indent}}`) || ls[i].startsWith(`${indent}]`)) && ls[i].match(/^\s*/)[0] === indent) return { path: p, startLine: start, endLine: i + 1 };
  throw new Error(`no end for ${needle} in ${p}`);
}
const one = (p, needle) => ({ path: p, startLine: lineOf(p, needle), endLine: lineOf(p, needle) });
const span = (p, a, b) => ({ path: p, startLine: lineOf(p, a), endLine: lineOf(p, b, lineOf(p, a) - 1) });

const item = (id, category, description, main, alsoAt, mention) => ({ id, ...main, category, description, ...(alsoAt.length ? { alsoAt } : {}), oracle: { mention, lineSlack: 3 } });

const items = [
  item("tw-task-history", ["authz", "secret"], "GET /tasks/:id/history returns the activity entries of any task id: the nine sibling task routes resolve the task through taskService.require (organisation check) first, this one goes straight to activityService.forEntity and the repository, which filter by entity and id only.", block("src/routes/tasks.ts", 'tasksRouter.get("/:id/history"'), [block("src/services/activityService.ts", "forEntity(entity: string"), one("src/repositories/activityRepo.ts", "forEntity:")], ["history", "activity", "audit (log|trail)"]),
  item("tw-invoice-pdf", ["authz", "secret"], "GET /invoices/:id/pdf renders any invoice by id: the other invoice routes go through invoiceService.get (organisation check), the pdf route calls pdfService.render, which loads the invoice from the repository directly.", block("src/routes/invoices.ts", 'invoicesRouter.get("/:id/pdf"'), [block("src/services/pdfService.ts", "render(invoiceId: string)")], ["pdf", "render"]),
  item("tw-webhook-deliveries", ["authz", "secret"], "GET /webhooks/:id/deliveries is registered before webhooksRouter.use(requireOrgRole('manager')), so any member can read delivery logs, which contain the Authorization header sent to the target (the webhook auth token).", block("src/routes/webhooks.ts", 'webhooksRouter.get("/:id/deliveries"'), [one("src/routes/webhooks.ts", 'webhooksRouter.use(requireOrgRole("manager"))'), block("src/services/webhookService.ts", "deliveries(user: User")], ["deliver"]),
  item("tw-public-export", ["authz", "secret"], "The public board export calls exportService.exportProject, which returns every task of the project including private ones and their notes; only the public board view filters on visibility.", block("src/routes/boardsPublic.ts", 'boardsPublicRouter.get("/:slug/export"'), [block("src/services/exportService.ts", "exportProject(projectId: string)")], ["export"]),
  item("tw-billing-org-header", ["authz", "secret"], "Billing routes take the organisation from the X-Org-Id header without checking membership (the router is mounted before resolveOrg), so any manager can read another organisation's plan, payment method and invoices.", span("src/routes/billing.ts", "// The invoicing job", "const orgOf"), [block("src/routes/billing.ts", 'billingRouter.get("/plan"'), block("src/routes/billing.ts", 'billingRouter.get("/invoices"'), span("src/app.ts", 'api.use("/billing"', "api.use(resolveOrg)")], ["x-org-id", "org(anisation)? header", "billing"]),
  item("tw-attachment-filename", ["path-traversal"], "Attachment upload builds the storage key from cleanName(filename); cleanName only strips markup characters, so ../ sequences survive and storage.put writes outside the upload root.", span("src/services/attachmentService.ts", "const name = cleanName", "const key = storage.put"), [block("src/routes/tasks.ts", 'tasksRouter.post("/:id/attachments"'), block("src/lib/sanitize.ts", "export function cleanName"), block("src/lib/storage.ts", "put(key: string")], ["attachment", "upload", "file ?name", "cleanName", "traversal"]),
  item("tw-security-case", ["authz"], "securityRules matches the request path with a case-sensitive startsWith on the lower-case prefixes while Express routes case-insensitively, so /API/ADMIN/... skips the admin rule; the admin handlers rely on that rule alone and have no role check of their own.", block("src/middleware/securityRules.ts", "export function securityRules"), [block("src/config/security.ts", "export const urlRules"), block("src/routes/admin/users.ts", 'adminUsersRouter.get("/"'), block("src/routes/admin/users.ts", 'adminUsersRouter.put("/:id/role"'), block("src/routes/admin/orgs.ts", 'adminOrgsRouter.get("/"'), block("src/routes/admin/audit.ts", 'adminAuditRouter.get("/"')], ["case", "upper", "lower-?case", "startsWith", "prefix", "normali[sz]", "bypass"]),
  item("tw-search-comments", ["authz", "secret"], "Search filters tasks and projects by the caller's organisation but searches comments across all organisations (commentRepo.search has no organisation argument).", one("src/services/searchService.ts", "comments: commentRepo.search"), [one("src/repositories/commentRepo.ts", "search:")], ["comment"]),
  item("tw-comment-author", ["authz", "mass-assignment", "business-logic"], "The user comment route spreads req.body after authorId, so a caller can post as any user; the integration route sets authorId legitimately, and commentService.add trusts the input.", block("src/routes/tasks.ts", 'tasksRouter.post("/:id/comments"'), [block("src/services/commentService.ts", "add(input: CommentInput)")], ["comment", "author", "spread", "impersonat", "spoof"]),
  item("tw-task-move", ["authz"], "taskService.move checks that the caller may write the task but loads the target project without an organisation check and stores the target's orgId on the task, so a caller can move tasks into another organisation's project.", block("src/services/taskService.ts", "move(user: User, id: string, projectId: string)"), [block("src/routes/tasks.ts", 'tasksRouter.post("/:id/move"')], ["move", "target project", "projectId"]),
];

const decoy = (id, category, description, loc) => ({ id, ...loc, category, description });
const decoys = [
  decoy("tw-d-comments-list", "authz", "comments list resolves the task through taskService.require", block("src/routes/tasks.ts", 'tasksRouter.get("/:id/comments"')),
  decoy("tw-d-attachments-list", "authz", "attachment list resolves the task through taskService.require", block("src/routes/tasks.ts", 'tasksRouter.get("/:id/attachments"')),
  decoy("tw-d-watchers", "authz", "watchers resolve the task through taskService.require", block("src/routes/tasks.ts", 'tasksRouter.get("/:id/watchers"')),
  decoy("tw-d-subtasks", "authz", "subtasks resolve the task through taskService.require", block("src/routes/tasks.ts", 'tasksRouter.get("/:id/subtasks"')),
  decoy("tw-d-time", "authz", "time entries resolve the task through taskService.require", block("src/routes/tasks.ts", 'tasksRouter.get("/:id/time"')),
  decoy("tw-d-task-get", "authz", "task read goes through taskService.require", block("src/routes/tasks.ts", 'tasksRouter.get("/:id", ')),
  decoy("tw-d-task-require", "authz", "organisation and owner checks in the service", block("src/services/taskService.ts", "requireWritable(user: User, id: string)")),
  decoy("tw-d-task-create", "authz", "create resolves the project (and parent) through the checked services", block("src/services/taskService.ts", "create(user: User, input")),
  decoy("tw-d-invoice-get", "authz", "invoice read goes through invoiceService.get", block("src/routes/invoices.ts", 'invoicesRouter.get("/:id", ')),
  decoy("tw-d-invoice-lines", "authz", "invoice lines go through invoiceService.get", block("src/routes/invoices.ts", 'invoicesRouter.get("/:id/lines"')),
  decoy("tw-d-invoice-share", "authz", "share token issuance is manager only and checks the invoice's organisation", block("src/routes/invoices.ts", 'invoicesRouter.post("/:id/share"')),
  decoy("tw-d-internal-invoice", "authz", "internal route, service token required by internalRouter.use(requireServiceToken); getById has no check by design", block("src/routes/internal/invoices.ts", 'internalInvoicesRouter.get("/:id"')),
  decoy("tw-d-internal-export", "authz", "internal route behind the service token", block("src/routes/internal/exports.ts", 'internalExportsRouter.get("/:projectId"')),
  decoy("tw-d-public-invoice", "authz", "public share link: the signed claim carries the invoice id, kind and expiry, and the id used is the claim's", block("src/routes/public.ts", 'publicRouter.get("/invoices/:token"')),
  decoy("tw-d-project-export", "authz", "project export resolves the project through projectService.require first", block("src/routes/projects.ts", 'projectsRouter.get("/:id/export"')),
  decoy("tw-d-board-public", "authz", "public board view filters to public tasks of a published board", block("src/routes/boardsPublic.ts", 'boardsPublicRouter.get("/:slug", ')),
  decoy("tw-d-billing-usage", "authz", "usage uses the caller's own organisation", block("src/routes/billing.ts", 'billingRouter.get("/usage"')),
  decoy("tw-d-webhook-list", "authz", "list returns summaries (no secrets) for the caller's organisation on purpose", block("src/routes/webhooks.ts", 'webhooksRouter.get("/", ')),
  decoy("tw-d-webhook-rotate", "authz", "registered after the manager guard", block("src/routes/webhooks.ts", 'webhooksRouter.post("/:id/rotate"')),
  decoy("tw-d-attachment-download", "authz", "organisation check and the stored key, not the client name", block("src/routes/attachments.ts", 'attachmentsRouter.get("/:id/download"')),
  decoy("tw-d-comment-display", "xss", "cleanName used for a display name (HTML sink), which is what it is for", block("src/services/commentService.ts", "list(user: User, taskId: string)")),
  decoy("tw-d-integration-comment", "authz", "service-token route; the author must belong to the task's organisation", block("src/routes/internal/integrations.ts", 'integrationsRouter.post("/slack/comments"')),
  decoy("tw-d-ops-flags", "authz", "inline admin check on top of the URL rule", block("src/routes/ops.ts", 'opsRouter.get("/flags"')),
  decoy("tw-d-register", "mass-assignment", "role is fixed server side and not read from the body", block("src/services/authService.ts", "register(input")),
  decoy("tw-d-me-update", "authz", "self only", block("src/routes/me.ts", 'meRouter.put("/"')),
  decoy("tw-d-search-scoped", "authz", "tasks and projects are scoped to the caller's organisation", span("src/services/searchService.ts", "tasks: taskRepo.search", "projects: projectRepo.search")),
  decoy("tw-d-pdf-filename", "path-traversal", "safeSegment for the download file name", one("src/services/pdfService.ts", "filename: `invoice-")),
  decoy("tw-d-export-filename", "path-traversal", "safeSegment for the export file name", one("src/services/exportService.ts", "filename: `${safeSegment")),
  decoy("tw-d-resolve-org", "authz", "header accepted only for the caller's own organisation or a platform admin", block("src/middleware/resolveOrg.ts", "export function resolveOrg")),
];

const cleanPaths = [...fillerPaths, "src/routes/projects.ts", "src/services/projectService.ts", "src/services/timeEntryService.ts", "src/services/boardService.ts", "src/middleware/requireOrgRole.ts", "src/middleware/serviceToken.ts", "src/routes/me.ts"];
const answer = { fixture: "ts-workspace", skill: null, cleanPaths, items, decoys };

// ---- write ----------------------------------------------------------------------------------------------------
rmSync(outDir, { recursive: true, force: true });
for (const [p, content] of files) {
  mkdirSync(dirname(join(outDir, p)), { recursive: true });
  writeFileSync(join(outDir, p), content);
}
writeFileSync(join(outDir, "answer.json"), `${JSON.stringify(answer, null, 2)}\n`);
mkdirSync(proofDir, { recursive: true });
writeFileSync(join(proofDir, "filler-routes.json"), `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`ts-workspace: ${files.size} files, ${items.length} planted, ${decoys.length} decoys, ${cleanPaths.length} clean paths, ${manifest.length} filler routes in the sweep`);
