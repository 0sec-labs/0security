import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Command } from "commander";
import { afterEach, describe, expect, it, vi } from "vitest";
import { osecDB } from "@0/engine/storage";
import { adjustmentFor, contextScore, describeAdjustment, findingPath, parseBusinessContext } from "../../business-context.js";
import { registerFindingsCommand } from "../findings.js";
vi.mock("../../state/runtime.js", () => ({ isBunRuntime: () => false, canUseOpenTui: () => false }));
const paths: string[] = [];
vi.mock("@0/engine/storage", async importOriginal => ({ ...await importOriginal<typeof import("@0/engine/storage")>(), listOsecRunDatabasePaths: () => paths, resolveOsecDbPath: () => paths[0] }));
const directories: string[] = [];
afterEach(() => { vi.restoreAllMocks(); paths.length = 0; for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true }); });

const parse = (value: unknown) => parseBusinessContext(JSON.stringify(value), "ctx.json");

describe("business context file", () => {
  it("accepts entries and weights and rejects anything else", () => {
    expect(parse({ entries: [{ match: "src/payments/**", tags: ["payments", "internet-facing"], note: "checkout" }], weights: { payments: 2 } }).weights.payments).toBe(2);
    expect(() => parseBusinessContext("nope", "c.json")).toThrow("not valid JSON");
    expect(() => parse({ entries: [{ tags: ["fun"] }] })).toThrow("not a tag");
    expect(() => parse({ entries: [{ tags: [] }] })).toThrow("non-empty");
    expect(() => parse({ entries: [], extra: 1 })).toThrow("not a setting");
    expect(() => parse({ entries: [{ tags: ["payments"], match: "" }] })).toThrow("match");
    expect(() => parse({ entries: [], weights: { payments: 9 } })).toThrow("whole number");
    expect(() => parse({ entries: [{ tags: ["payments"], other: 1 }] })).toThrow("not a setting");
  });

  it("matches paths by glob, folder name, or every finding when there is no match", () => {
    const context = parse({ entries: [{ match: "src/payments/**", tags: ["payments"] }, { match: "services/billing", tags: ["personal-data"] }, { match: "**/*.test.ts", tags: ["non-production"] }, { tags: ["internet-facing"] }] });
    expect(adjustmentFor(context, "src/payments/a/b.ts").tags).toEqual(["payments", "internet-facing"]);
    expect(adjustmentFor(context, "services/billing/db.ts").tags).toEqual(["personal-data", "internet-facing"]);
    expect(adjustmentFor(context, "src/x.test.ts").tags).toEqual(["non-production", "internet-facing"]);
    expect(adjustmentFor(context, "src/other.ts").tags).toEqual(["internet-facing"]);
    expect(adjustmentFor(context, undefined).tags).toEqual(["internet-facing"]);
    expect(adjustmentFor(parse({ entries: [{ match: "src/**", tags: ["payments"] }] }), undefined).tags).toEqual([]);
  });

  it("moves the order by at most two steps and says why", () => {
    const all = parse({ entries: [{ tags: ["internet-facing", "payments", "personal-data", "operationally-critical"], note: "the shop" }] });
    const adj = adjustmentFor(all, "a.ts");
    expect(adj.shift).toBe(2);
    expect(contextScore("low", adj)).toBe(3);
    expect(describeAdjustment(adj)).toBe("ranked higher (+2): internet-facing, payments, personal-data, operationally-critical. the shop");
    const down = adjustmentFor(parse({ entries: [{ tags: ["non-production", "internal-only"] }] }), "a.ts");
    expect(down.shift).toBe(-2);
    expect(describeAdjustment(down)).toContain("ranked lower (-2)");
    expect(describeAdjustment({ shift: 0, tags: [], notes: [] })).toBe("");
    expect(contextScore("weird", down)).toBeLessThan(contextScore("info", down));
  });

  it("reads the file path from a stored annotation", () => {
    expect(findingPath(JSON.stringify({ path: "./src/a.ts", startLine: 3 }))).toBe("src/a.ts");
    expect(findingPath({ path: "src\\b.ts" })).toBe("src/b.ts");
    expect(findingPath("{broken")).toBeUndefined();
    expect(findingPath(null)).toBeUndefined();
  });
});

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "0-cli-context-")); directories.push(directory);
  const path = join(directory, "history.db"); paths.push(path);
  const db = new osecDB(path);
  const scan = db.createScan({ target: "https://example.test", depth: "default", format: "json" });
  const sqlite = (db as unknown as { sqlite: { prepare(query: string): { run(...values: unknown[]): unknown } } }).sqlite;
  const statement = sqlite.prepare("INSERT INTO findings(id,scanId,templateId,title,description,severity,category,status,fingerprint,evidenceRequest,evidenceResponse,timestamp,reviewAnnotation) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)");
  const insert = (id: string, severity: string, file: string) => statement.run(id, scan, "t", id, "d", severity, "xss", "confirmed", id, "req", "res", 100, JSON.stringify({ path: file, startLine: 1 }));
  return { db, path, directory, insert };
}
async function list(args: string[]) {
  const log = vi.spyOn(console, "log").mockImplementation(() => {});
  log.mockClear();
  const program = new Command(); registerFindingsCommand(program);
  await program.parseAsync(["findings", "list", ...args], { from: "user" });
  return log.mock.calls.map(call => String(call[0])).join("\n");
}

describe("findings list --context", () => {
  it("gives two contexts two different orderings of the same findings, with the reason", async () => {
    const { db, path, directory, insert } = fixture();
    try {
      insert("admin-high", "high", "services/admin/panel.ts");
      insert("checkout-medium", "medium", "src/payments/checkout.ts");
      insert("docs-critical", "critical", "examples/demo.ts");
    } finally { db.close(); }
    const shop = join(directory, "shop.json");
    writeFileSync(shop, JSON.stringify({ entries: [{ match: "src/payments/**", tags: ["payments", "personal-data"], note: "card data" }, { match: "examples/**", tags: ["non-production"] }] }));
    const internal = join(directory, "internal.json");
    writeFileSync(internal, JSON.stringify({ entries: [{ match: "services/admin/**", tags: ["operationally-critical"] }] }));

    const plain = await list(["--db-path", path]);
    expect(plain.indexOf("docs-critical")).toBeLessThan(plain.indexOf("admin-high"));
    expect(plain).not.toContain("Business context");

    const first = await list(["--db-path", path, "--context", shop]);
    // medium + 2 = critical level, ties broken as without a context; the demo critical drops two steps to medium.
    expect(first.indexOf("checkout-medium")).toBeLessThan(first.indexOf("admin-high"));
    expect(first.indexOf("admin-high")).toBeLessThan(first.indexOf("docs-critical"));
    expect(first).toContain("Business context: ranked higher (+2): payments, personal-data. card data");
    expect(first).toContain("ranked lower (-2): non-production");
    expect(first).toContain("Technical severity: critical");

    const second = await list(["--db-path", path, "--context", internal]);
    expect(second.indexOf("docs-critical")).toBeLessThan(second.indexOf("admin-high"));
    expect(second.indexOf("admin-high")).toBeLessThan(second.indexOf("checkout-medium"));
    expect(second).toContain("ranked higher (+1): operationally-critical");
  });

  it("ranks before it limits, so a raised finding is not cut off", async () => {
    const { db, path, directory, insert } = fixture();
    try {
      insert("a-high", "high", "src/a.ts"); insert("b-high", "high", "src/b.ts"); insert("c-medium-payments", "medium", "src/payments/c.ts");
    } finally { db.close(); }
    const ctx = join(directory, "c.json");
    writeFileSync(ctx, JSON.stringify({ entries: [{ match: "src/payments/**", tags: ["payments", "personal-data"] }] }));
    const text = await list(["--db-path", path, "--context", ctx, "--limit", "1"]);
    expect(text).toContain("c-medium-payments"); expect(text).not.toContain("a-high");
  });

  it("stops on a bad file before reading any finding", async () => {
    const { db, path, directory } = fixture(); db.close();
    const bad = join(directory, "bad.json"); writeFileSync(bad, "{}");
    await expect(list(["--db-path", path, "--context", bad])).rejects.toThrow("entries");
    await expect(list(["--db-path", path, "--context", join(directory, "missing.json")])).rejects.toThrow("does not exist");
  });
});
