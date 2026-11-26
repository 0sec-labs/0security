import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { labelFamilies } from "./findings-ranking.js";

const dirs: string[] = [];
afterEach(() => dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true })));
const file = (value: string) => { const dir = mkdtempSync(join(tmpdir(), "0-web-ctx-")); dirs.push(dir); const path = join(dir, "c.json"); writeFileSync(path, value); return path; };
const family = (key: string, path: string, scanId = "s1", severity = "medium") => ({ key, latest: { scanId, severity, reviewAnnotation: JSON.stringify({ path, startLine: 1 }) } });

describe("web findings labels from the findingsContext setting", () => {
  it("labels each finding family and nothing without a setting", async () => {
    const path = file(JSON.stringify({ entries: [{ match: "src/payments/**", tags: ["payments"], note: "card data" }] }));
    const labels = await labelFamilies([family("a", "src/payments/x.ts"), family("b", "src/other.ts")], new Map(), { findingsContext: path });
    expect(labels.get("a")).toMatchObject({ provenance: "operator", shift: 1, tags: ["payments"], notes: ["card data"], score: 3 });
    expect(labels.get("b")).toMatchObject({ shift: 0, tags: [] });
    expect((await labelFamilies([family("a", "src/payments/x.ts")], new Map(), { findingsContext: "" })).size).toBe(0);
  });

  it("matches repository rules against the scan target of each finding", async () => {
    const path = file(JSON.stringify({ repositories: { "acme/shop": [{ tags: ["payments"] }], "acme/docs": [{ tags: ["non-production"] }] } }));
    const targets = new Map([["s1", "https://github.com/acme/shop.git"], ["s2", "https://github.com/acme/docs"]]);
    const labels = await labelFamilies([family("a", "a.ts", "s1"), family("b", "b.ts", "s2"), family("c", "c.ts", "s3")], targets, { findingsContext: path });
    expect(labels.get("a")!.tags).toEqual(["payments"]);
    expect(labels.get("b")!.tags).toEqual(["non-production"]);
    expect(labels.get("c")!.tags).toEqual([]);
  });

  it("labels nothing when the file is missing, invalid or too large, so the list keeps its order", async () => {
    const dir = mkdtempSync(join(tmpdir(), "0-web-ctx-")); dirs.push(dir);
    for (const path of [join(dir, "missing.json"), file("not json"), file("{}"), file(JSON.stringify({ entries: [{ tags: ["payments"], note: "x".repeat(70_000) }] }))]) {
      expect((await labelFamilies([family("a", "src/x.ts")], new Map(), { findingsContext: path })).size).toBe(0);
    }
  });
});
