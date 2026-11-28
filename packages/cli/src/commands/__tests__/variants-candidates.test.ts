/**
 * The variant hunt with a code-computed checklist: a seed with no root cause gets a short root-cause thread, the
 * candidate finder runs on that root cause, the hunt prompt carries the numbered list, and every verdict is recorded.
 */
import { describe, expect, it } from "vitest";
import type { ParsedVariant, RootCause } from "@0/engine/shared";
import { huntVariants, variantFinding, type CandidateFinder, type VariantParent, type VariantStore } from "../variants.js";

const block = (o: unknown) => `\`\`\`json\n${JSON.stringify(o)}\n\`\`\``;
const ROOT_CAUSE = { bug_class: "Broken access control", unsafe_pattern: { sink: "invoiceRepo.findById(id)", source: "req.params.id" }, missing_guard: "orgId scoping", design_origin: "repository" };

const parent: VariantParent = { id: "seed-1", dbPath: ":memory:", scanId: "s", title: "Cross-tenant read", category: "broken-access-control", severity: "high", description: "d", path: "src/routes/invoices.ts", startLine: 15, endLine: 19 };

function fakeClient(answers: (prompt: string) => string, usage = { inputTokens: 100, outputTokens: 10, costUsd: 0.01 }) {
  const replies = new Map<string, string>();
  const prompts: string[] = [];
  let threads = 0;
  const client = { request: async (method: string, path: string, body?: { text?: string }) => {
    const id = path.split("/")[4]!;
    if (method === "POST" && path.endsWith("/sessions")) { threads++; return { session: { id: `t${threads}` } }; }
    if (method === "POST" && path.endsWith("/messages")) { prompts.push(body!.text!); replies.set(id, answers(body!.text!)); return {}; }
    if (method === "GET") return { snapshot: { session: { status: "ready" }, messages: [{ role: "assistant", content: [{ type: "text", text: replies.get(id) ?? "" }] }], lastOutcome: {}, usage } };
    return {};
  } };
  return { client: client as never, prompts };
}

function memoryStore() {
  const saved: Array<{ variant: ParsedVariant; rootCause: RootCause | undefined }> = [];
  const causes: RootCause[] = [];
  const store: VariantStore = {
    variantsOf: () => [], saveRootCause: (_p, rc) => { causes.push(rc); }, markFixedPendingMerge: () => {},
    saveVariant: (_p, variant, rootCause) => { saved.push({ variant, rootCause }); return `variant-${saved.length}`; },
  };
  return { store, saved, causes };
}

const finder: CandidateFinder = async () => ({
  candidates: [
    { id: "C1", file: "src/routes/quotes.ts", line: 24, symbol: "<GET /:id/pdf>", entries: ["GET /:id/pdf"], why: "calls findById, the unsafe call in the root cause" },
    { id: "C2", file: "src/jobs/reminderJob.ts", line: 7, symbol: "reminder", entries: ["entry reminder (src/jobs/reminderJob.ts)"], why: "calls findById", guardHint: 'word "org" appears in reminder' },
    { id: "C3", file: "src/routes/refunds.ts", line: 12, why: "calls findById" },
  ],
  total: 5, omitted: 2, engine: "builtin", strategy: "authorization", notes: [],
});

describe("variant hunt with a candidate checklist", () => {
  it("derives the root cause first, lists the candidates, stores variants with their candidate id and counts the verdicts", async () => {
    const model = fakeClient(prompt => {
      if (!prompt.includes("<candidate>")) return block({ root_cause: ROOT_CAUSE });
      return block({ root_cause: ROOT_CAUSE, candidates: [
        { id: "C1", verdict: "variant", reason: "src/routes/quotes.ts:24 has no org check", title: "Quote PDF crosses organisations", severity: "high", startLine: 23, endLine: 27, description: "chain" },
        { id: "C2", verdict: "guarded", reason: "scoped", guard: "src/jobs/reminderJob.ts:9" },
      ], variants: [] });
    });
    const memory = memoryStore();
    const result = await huntVariants(model.client, { store: memory.store, err: () => {}, sleep: async () => {}, candidates: finder }, "/tmp/none", parent, { timeout: "60", budget: "1" });
    expect(model.prompts).toHaveLength(2);
    expect(model.prompts[0]).toContain("do not search the rest of the folder");
    expect(model.prompts[1]!.match(/^<candidate>$/gm)).toHaveLength(3);
    expect(model.prompts[1]).toContain("There are 5 candidates");
    expect(memory.causes[0]?.unsafePattern.sink).toBe("invoiceRepo.findById(id)");
    expect(result.created).toEqual(["variant-1"]);
    expect(memory.saved[0]!.variant).toMatchObject({ path: "src/routes/quotes.ts", startLine: 23, endLine: 27, candidateId: "C1" });
    expect(result.checklist).toMatchObject({ listed: 3, total: 5, omitted: 2, verdicts: { variant: 1, guarded: 1, not_reachable: 0, unsure: 0 }, undisposed: ["C3"], stored: ["C1"] });
    expect(result.tokens).toBe(220);
    expect(result.rootCauseSource).toBe("derived");
  });

  it("records the candidate id in the stored finding", () => {
    const finding = variantFinding(parent, { title: "t", severity: "critical", path: "a.ts", startLine: 3, description: "d", evidence: "e", candidateId: "C7" }, undefined, "variant-x", 1);
    expect(finding.description).toContain("hunt candidate C7");
    expect(finding.evidence.analysis).toContain("C7");
    expect(finding.severity).toBe("medium");
  });

  it("falls back to the plain hunt prompt when the finder returns nothing", async () => {
    const model = fakeClient(() => block({ root_cause: ROOT_CAUSE, variants: [] }));
    const empty: CandidateFinder = async () => ({ candidates: [], total: 0, omitted: 0, engine: "builtin", strategy: "authorization", notes: ["none of the sink names"] });
    const memory = memoryStore();
    const result = await huntVariants(model.client, { store: memory.store, err: () => {}, sleep: async () => {}, candidates: empty }, "/tmp/none", { ...parent, rootCause: parseCause() }, { timeout: "60", budget: "1" });
    expect(model.prompts).toHaveLength(1);
    expect(model.prompts[0]).not.toContain("<candidate>");
    expect(result.checklist).toBeUndefined();
  });
});

function parseCause(): RootCause {
  return { bugClass: "Broken access control", unsafePattern: { sink: "invoiceRepo.findById(id)", source: "req.params.id" }, missingGuard: "orgId scoping", designOrigin: "repository" };
}
