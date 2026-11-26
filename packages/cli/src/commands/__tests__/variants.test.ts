/**
 * Variant hunting end to end: a fixture repository with one fixed SQL injection and two unfixed siblings, a real
 * findings database, the real verify / variants code paths and a model stub at the console-client seam (the same one
 * verify.test.ts uses). The stub answers from the files on disk, so a hunt only finds what is really there.
 */
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "@0/engine/shared";
import { osecDB } from "@0/engine/storage";
import { registerFindingsCommand } from "../findings.js";
import { defaultVerifyDeps, runVerify, type VerifyDeps, type VerifyOptions } from "../verify.js";
import { defaultVariantDeps, renderVariantsReport, runVariants, type VariantDeps, type VariantsOptions } from "../variants.js";

vi.mock("../../state/runtime.js", () => ({ isBunRuntime: () => false, canUseOpenTui: () => false }));

const ROOT_CAUSE = {
  bug_class: "SQL injection",
  unsafe_pattern: { sink: "db.query with a template literal", source: "the id request parameter" },
  missing_guard: "a bound parameter in the query",
  design_origin: "a shared query helper that only accepts bound parameters",
};

const FIXED = "export function getUser(db, id) {\n  // fixed: bound parameter\n  return db.query(\"SELECT * FROM users WHERE id = ?\", [id]);\n}\n";
const UNFIXED = (table: string) => `export function load(db, id) {\n  return db.query(\`SELECT * FROM ${table} WHERE id = \${id}\`);\n}\n`;
const GUARDED = "export function find(db, name) {\n  return db.query(\"SELECT * FROM tags WHERE name = ?\", [name]);\n}\n";

const directories: string[] = [];
let folder = "";
let dbPath = "";
let parentId = "";

function fixtureRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), "0-variants-repo-")); directories.push(dir);
  mkdirSync(join(dir, "src"));
  writeFileSync(join(dir, "src", "users.ts"), FIXED);
  writeFileSync(join(dir, "src", "orders.ts"), UNFIXED("orders"));
  writeFileSync(join(dir, "src", "invoices.ts"), UNFIXED("invoices"));
  writeFileSync(join(dir, "src", "tags.ts"), GUARDED);
  return dir;
}

const finding = (id: string, extra: Partial<Finding> = {}): Finding => ({
  id, templateId: "agent", title: "SQL injection in getUser", description: "getUser built its query with the id.", severity: "high", category: "sql-injection", status: "discovered",
  evidence: { request: "src/users.ts:3", response: "db.query(`... ${id}`)" }, reviewAnnotation: { path: "src/users.ts", startLine: 3 }, timestamp: 1, ...extra,
});

beforeEach(() => {
  folder = fixtureRepo();
  const dir = mkdtempSync(join(tmpdir(), "0-variants-db-")); directories.push(dir);
  dbPath = join(dir, "history.db");
  const db = new osecDB(dbPath);
  try {
    const scan = db.createScan({ target: "https://example.test", depth: "default", format: "json" });
    parentId = "finding-parent";
    db.saveFinding(scan, finding(parentId));
  } finally { db.close(); }
});
afterEach(() => { vi.restoreAllMocks(); for (const dir of directories.splice(0)) rmSync(dir, { recursive: true, force: true }); });

const block = (o: unknown) => `\`\`\`json\n${JSON.stringify(o)}\n\`\`\``;

/** The model: answers a verify, a hunt or a rescan prompt by reading the folder the thread was pointed at. */
function modelClient() {
  const workspaces = new Map<string, string>();
  const replies = new Map<string, string>();
  const seeds: Array<Record<string, unknown>> = [];
  const prompts: string[] = [];
  let threads = 0;
  const sources = (root: string) => readdirSync(join(root, "src")).filter(name => name.endsWith(".ts")).sort();
  const answer = (text: string, root: string): string => {
    prompts.push(text);
    if (text.startsWith("Re-check")) return block({ finding: /"id": "([^"]+)"/.exec(text)![1], verdict: "true-positive", reasoning: "src/users.ts:3 builds the query from the id.", root_cause: ROOT_CAUSE });
    if (text.includes("<seed>")) {
      const seed = JSON.parse(/<seed>\n([\s\S]*?)\n<\/seed>/.exec(text)![1]!) as Record<string, unknown>;
      seeds.push(seed);
      const variants: Array<Record<string, unknown>> = [];
      for (const name of sources(root)) {
        if (`src/${name}` === seed.file) continue;
        const lines = readFileSync(join(root, "src", name), "utf8").split("\n");
        lines.forEach((line, index) => {
          if (/db\.query\(`[^`]*\$\{/.test(line)) variants.push({ title: `SQL injection in src/${name}`, severity: "high", file: `src/${name}`, startLine: index + 1, description: `load() puts id into the query at src/${name}:${index + 1}; the id comes from the request.`, evidence: line.trim(), suggested_fix: "Bind the id as a parameter." });
        });
      }
      return `Searched for ${JSON.stringify((seed.rootCause as { unsafe_pattern?: unknown } | undefined) ?? "")}.\n${block({ root_cause: ROOT_CAUSE, variants })}`;
    }
    if (text.includes("<site>")) {
      const sites = [...text.matchAll(/<site>\n([\s\S]*?)\n<\/site>/g)].map(m => JSON.parse(m[1]!) as { id: string; file: string; startLine: number });
      return sites.map(site => {
        const line = readFileSync(join(root, site.file), "utf8").split("\n")[site.startLine - 1] ?? "";
        return block({ site: site.id, state: line.includes("${") ? "open" : "fixed", reasoning: `${site.file}:${site.startLine} ${line.includes("${") ? "still builds the query from id" : "binds the id"}.` });
      }).join("\n");
    }
    return "";
  };
  const client = { request: async (method: string, path: string, body?: { text?: string; workspacePath?: string }) => {
    const id = path.split("/")[4]!;
    if (method === "POST" && path.endsWith("/sessions")) { threads++; return { session: { id: `t${threads}` } }; }
    if (method === "PATCH") { workspaces.set(id, body!.workspacePath!); return {}; }
    if (method === "POST" && path.endsWith("/messages")) { replies.set(id, answer(body!.text!, workspaces.get(id)!)); return {}; }
    if (method === "GET") return { snapshot: { session: { status: "ready" }, messages: [{ role: "assistant", content: [{ type: "text", text: replies.get(id) ?? "" }] }], lastOutcome: {}, usage: { costUsd: 0.05 } } };
    return {};
  } };
  return { client, seeds, prompts };
}

const verifyOptions = (): VerifyOptions => ({ folder, dbPath, budget: "2", perFinding: "0.3", concurrency: "1", batch: "1", maxConsecutiveFailures: "3", timeout: "60" });
const variantsOptions = (extra: Partial<VariantsOptions> = {}): VariantsOptions => ({ folder, dbPath, budget: "1", timeout: "60", ...extra });

function verifyDeps(model: ReturnType<typeof modelClient>): VerifyDeps {
  return { ...defaultVerifyDeps, open: async () => model.client as never, err: () => {}, sleep: async () => {}, startConsole: async () => () => {}, out: () => {}, metrics: undefined, now: () => new Date("2026-11-25T00:00:00Z") };
}
function variantDeps(model: ReturnType<typeof modelClient>): VariantDeps {
  return { ...defaultVariantDeps, open: async () => model.client as never, err: () => {}, sleep: async () => {}, startConsole: async () => () => {}, out: () => {} };
}

function withDb<T>(use: (db: osecDB) => T): T {
  const db = new osecDB(dbPath);
  try { return use(db); } finally { db.close(); }
}

async function cli(args: string[]): Promise<string> {
  const log = vi.spyOn(console, "log").mockImplementation(() => {});
  log.mockClear();
  const program = new Command(); registerFindingsCommand(program);
  await program.parseAsync(args, { from: "user" });
  return log.mock.calls.map(call => String(call[0])).join("\n");
}

describe("variant hunting from a verified finding", () => {
  it("records the root cause and links the two unfixed siblings as variants, not the fixed or guarded sites", async () => {
    const model = modelClient();
    const report = await runVerify([parentId], verifyOptions(), verifyDeps(model));
    expect(report.counts["true-positive"]).toBe(1);
    expect(report.variantsCreated).toBe(2);

    // The hunt was seeded from the stored record: the seed carries the root cause the verdict produced.
    expect(model.seeds).toHaveLength(1);
    expect(model.seeds[0]!.rootCause).toMatchObject({ bugClass: "SQL injection", missingGuard: "a bound parameter in the query" });

    withDb(db => {
      expect(db.getFindingRootCause(parentId)).toMatchObject({ bugClass: "SQL injection", designOrigin: "a shared query helper that only accepts bound parameters" });
      const variants = db.listVariantsOf(parentId);
      expect(variants.map(v => v.variantOf)).toEqual([parentId, parentId]);
      expect(variants.map(v => v.title).sort()).toEqual(["SQL injection in src/invoices.ts", "SQL injection in src/orders.ts"]);
      expect(variants.every(v => v.status === "discovered" && v.templateId === "variant-hunting")).toBe(true);
      expect(db.getFindingRootCause(variants[0]!.id)?.bugClass).toBe("SQL injection");
    });
  });

  it("does not hunt with --no-variants, and never starts a hunt from a variant", async () => {
    const off = modelClient();
    await runVerify([parentId], { ...verifyOptions(), variants: false }, verifyDeps(off));
    expect(off.seeds).toHaveLength(0);
    withDb(db => { expect(db.listVariantsOf(parentId)).toHaveLength(0); expect(db.getFindingRootCause(parentId)).toBeDefined(); });

    const on = modelClient();
    await runVerify([parentId], { ...verifyOptions(), force: true }, verifyDeps(on));
    const variant = withDb(db => db.listVariantsOf(parentId)[0]!);
    const again = modelClient();
    const second = await runVerify([variant.id], verifyOptions(), verifyDeps(again));
    expect(second.counts["true-positive"]).toBe(1);
    expect(again.seeds).toHaveLength(0);
  });

  it("running the hunt again records no duplicates", async () => {
    const model = modelClient();
    await runVerify([parentId], verifyOptions(), verifyDeps(model));
    const report = await runVariants(parentId, variantsOptions(), variantDeps(model));
    expect(report.hunt).toMatchObject({ created: [], skipped: 2, rootCauseSource: "stored" });
    expect(model.prompts.at(-1)).toContain("alreadyRecorded");
    withDb(db => expect(db.listVariantsOf(parentId)).toHaveLength(2));
  });

  it("shows variantOf and the variants in findings show and findings list", async () => {
    await runVerify([parentId], verifyOptions(), verifyDeps(modelClient()));
    const variantId = withDb(db => db.listVariantsOf(parentId)[0]!.id);

    const parent = await cli(["findings", "show", parentId, "--db-path", dbPath]);
    expect(parent).toContain("Root cause: SQL injection");
    expect(parent).toContain("missing guard: a bound parameter in the query");
    expect(parent).toContain("Variants: 2 (2 open, 0 fixed)");

    const child = await cli(["findings", "show", variantId, "--db-path", dbPath]);
    expect(child).toContain("Variant of:");
    expect(child).toContain("SQL injection in getUser");

    const json = JSON.parse(await cli(["findings", "show", variantId, "--db-path", dbPath, "--json"])) as Record<string, unknown>;
    expect(json.variantOf).toBe(parentId);
    expect(json.rootCause).toMatchObject({ bugClass: "SQL injection" });
    const parentJson = JSON.parse(await cli(["findings", "show", parentId, "--db-path", dbPath, "--json"])) as { variants: Array<{ id: string; status: string }> };
    expect(parentJson.variants).toHaveLength(2);

    const list = await cli(["findings", "list", "--all", "--db-path", dbPath]);
    expect(list).toContain("2 variants: 2 open, 0 fixed");
    expect(list).toContain(`variant of ${parentId.slice(0, 8)}`);
  });
});

describe("rescan of variants after a fix", () => {
  it("marks the variant that was fixed and leaves the other open", async () => {
    const model = modelClient();
    await runVerify([parentId], verifyOptions(), verifyDeps(model));
    writeFileSync(join(folder, "src", "orders.ts"), "export function load(db, id) {\n  return db.query(\"SELECT * FROM orders WHERE id = ?\", [id]);\n}\n");

    const report = await runVariants(parentId, variantsOptions({ rescan: true }), variantDeps(model));
    expect(report.rescan!.items.map(i => [i.title, i.state]).sort()).toEqual([["SQL injection in src/invoices.ts", "open"], ["SQL injection in src/orders.ts", "fixed"]]);
    expect(renderVariantsReport(report)).toContain("still open");
    withDb(db => {
      const status = Object.fromEntries(db.listVariantsOf(parentId).map(v => [v.title, v.status]));
      expect(status).toEqual({ "SQL injection in src/invoices.ts": "discovered", "SQL injection in src/orders.ts": "fixed" });
    });

    // A fixed variant is not checked again; the one still open is.
    const next = await runVariants(parentId, variantsOptions({ rescan: true }), variantDeps(model));
    expect(next.rescan!.items).toHaveLength(1);
    const detail = await cli(["findings", "show", parentId, "--db-path", dbPath]);
    expect(detail).toContain("Variants: 2 (1 open, 1 fixed)");
  });

  it("leaves a variant as it was when the thread does not answer for it", async () => {
    const model = modelClient();
    await runVerify([parentId], verifyOptions(), verifyDeps(model));
    const silent = { ...model, client: { request: async (method: string, path: string, body?: unknown) => {
      const result = await model.client.request(method, path, body as never) as { snapshot?: { messages: unknown[] } };
      return method === "GET" ? { snapshot: { ...result.snapshot, messages: [{ role: "assistant", content: [{ type: "text", text: "Could not tell." }] }] } } : result;
    } } };
    const report = await runVariants(parentId, variantsOptions({ rescan: true }), variantDeps(silent as never));
    expect(report.rescan!.items.every(i => i.state === "unchecked")).toBe(true);
    withDb(db => expect(db.listVariantsOf(parentId).every(v => v.status === "discovered")).toBe(true));
  });

  it("refuses to hunt from a finding that is itself a variant", async () => {
    const model = modelClient();
    await runVerify([parentId], verifyOptions(), verifyDeps(model));
    const variant = withDb(db => db.listVariantsOf(parentId)[0]!);
    await expect(runVariants(variant.id, variantsOptions(), variantDeps(model))).rejects.toThrow(/is itself a variant/);
  });
});
