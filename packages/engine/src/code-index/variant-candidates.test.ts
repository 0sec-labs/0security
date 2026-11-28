import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { guardWordsOf, sinkNamesOf, variantCandidates, type RootCauseLike } from "./variant-candidates.js";

const rootCause: RootCauseLike = { bugClass: "Broken access control", unsafePattern: { sink: "invoiceRepo.findById(id)", source: "req.params.id" }, missingGuard: "orgId scoping: invoiceRepo.findForOrg(req.user.orgId, id)", designOrigin: "repository" };

describe("root cause tokens", () => {
  it("takes the sink name and the guard words, not the entity words", () => {
    expect(sinkNamesOf(rootCause)).toEqual({ names: ["findById"], receivers: ["invoiceRepo"] });
    expect(guardWordsOf(rootCause)).toEqual(["org"]);
  });
});

describe("variantCandidates", () => {
  const dir = mkdtempSync(join(tmpdir(), "variant-cand-"));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(join(dir, "src", "invoices.ts"), `import { Router } from "express";
export const r = Router();
r.get("/:id", (req, res) => {
  res.json(invoiceRepo.findForOrg(req.user.orgId, req.params.id));
});
`);
  writeFileSync(join(dir, "src", "quotes.ts"), `import { Router } from "express";
export const q = Router();
q.get("/:id/pdf", (req, res) => {
  const quote = quoteRepo.findById(req.params.id);
  res.json(quote);
});
q.get("/:id/ok", (req, res) => {
  const quote = quoteRepo.findById(req.params.id);
  if (quote.orgId !== req.user.orgId) return res.sendStatus(404);
  res.json(quote);
});
`);
  writeFileSync(join(dir, "src", "job.ts"), `export function nightly(id) {
  return ticketRepo.findById(id);
}
`);

  it("lists every site of the unsafe call, unguarded ones first, with routes and entries, never file content", async () => {
    const list = await variantCandidates(dir, { path: "src/invoices.ts", startLine: 3, endLine: 5 }, rootCause, { foxguard: false });
    expect(list.strategy).toBe("authorization");
    expect(list.candidates.map(c => `${c.file}:${c.symbol}`)).toEqual(["src/job.ts:nightly", "src/quotes.ts:<GET /:id/pdf>", "src/quotes.ts:<GET /:id/ok>"]);
    expect(list.candidates[1]!.entries).toEqual(["GET /:id/pdf"]);
    expect(list.candidates[0]!.entries[0]).toContain("entry nightly");
    expect(list.candidates[0]!.guardHint).toBeUndefined();
    expect(list.candidates[2]!.guardHint).toContain("org");
    expect(list.candidates.map(c => c.id)).toEqual(["C1", "C2", "C3"]);
    expect(JSON.stringify(list)).not.toContain("req.params");
  });

  it("caps the list and says how many were left out", async () => {
    const list = await variantCandidates(dir, { path: "src/invoices.ts", startLine: 3, endLine: 5 }, rootCause, { foxguard: false, limit: 2 });
    expect(list.candidates).toHaveLength(2);
    expect(list.total).toBe(3);
    expect(list.omitted).toBe(1);
  });

  it("falls back to a text search when the index has no such call, and says so", async () => {
    const text = mkdtempSync(join(tmpdir(), "variant-text-"));
    mkdirSync(join(text, "src"), { recursive: true });
    writeFileSync(join(text, "src", "Account.java"), "class Account {\n  Object load(String id) { return repo.findById(id); }\n}\n");
    const list = await variantCandidates(text, {}, rootCause, { foxguard: false });
    rmSync(text, { recursive: true, force: true });
    expect(list.engine).toBe("text");
    expect(list.candidates[0]).toMatchObject({ file: "src/Account.java", line: 2 });
  });
});
