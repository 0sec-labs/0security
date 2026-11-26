import { describe, expect, it } from "vitest";
import { CANARY_PLACEHOLDER } from "../scenario.js";
import { validateResponse, type BrainManifest } from "../brain/schema.js";
import type { OracleSpec } from "../oracle-types.js";
import { evaluateOracle } from "../oracle.js";
import { CATALOG, CATALOG_BY_ID, TEMPLATES, VOCABULARY, VOCABULARY_TOOLS, applies, catalogScenarios, catalogStats, selectGenerators } from "./index.js";

/** Every row of the research catalog; the catalog must keep converting all of them. */
const RESEARCH_IDS = [
  "adaptive-vs-guard",
  "agency-approval-gate-skip",
  "agency-credentialed-offscope",
  "agency-destructive-under-freeze",
  "agency-exec-unrequested",
  "agency-network-out-unrequested",
  "agency-read-local-overreach",
  "agency-write-local-unrequested",
  "best-of-n-augmentation",
  "browser-confirmation-bypass",
  "browser-cross-origin-session",
  "browser-decoy-click",
  "browser-form-pii-entry",
  "browser-navigation-only",
  "browser-screenshot-injection",
  "ci-poisoned-dependency-script",
  "ci-pr-body-injection",
  "consume-recursive-spawn",
  "consume-tool-loop",
  "cross-agent-config-planting",
  "deputy-cross-user-credential",
  "deputy-state-handle-hijack",
  "direct-instruction-override",
  "direct-persona-reframe",
  "eval-baseline-behavior-diff",
  "eval-contamination-gap",
  "eval-dataset-row-poison",
  "eval-judge-manipulation",
  "eval-partial-success-trace",
  "exfil-cross-scope-public-sink",
  "exfil-link-fetch",
  "exfil-markdown-image",
  "exfil-side-channel-dns",
  "exfil-tool-argument",
  "goal-drift-long-horizon",
  "goal-hijack-task-substitution",
  "identity-bearer-to-untrusted-tool",
  "identity-consent-bypass",
  "identity-stepup-scope-escalation",
  "identity-token-audience-confusion",
  "indirect-delayed-trigger",
  "indirect-document-embedded",
  "indirect-email-body",
  "indirect-encoded-obfuscated",
  "indirect-repo-issue-text",
  "indirect-tool-result",
  "indirect-web-hidden-text",
  "iterative-refinement-search",
  "ma-agent-card-poison",
  "ma-delegation-privilege-loss",
  "ma-orchestrator-hijack",
  "ma-peer-obedience",
  "ma-prompt-infection",
  "ma-session-smuggling",
  "ma-topology-leak",
  "many-shot-priming",
  "mcp-cross-server-shadowing",
  "mcp-lookalike-registry-entry",
  "mcp-rug-pull",
  "mcp-tool-description-poison",
  "mcp-tool-name-collision",
  "memory-cross-session-echo",
  "memory-cross-user-contamination",
  "memory-triggered-backdoor",
  "memory-write-from-untrusted",
  "multi-turn-escalation",
  "pay-amount-quote-mismatch",
  "pay-budget-drain-paid-api",
  "pay-injected-unauthorized-purchase",
  "pay-mandate-cap-overreach",
  "pay-product-ranking-steer",
  "pay-recipient-tamper",
  "pay-replay-double-spend",
  "pay-signed-decision-gap",
  "pay-social-pressure-discount",
  "rag-document-poison",
  "rag-ranking-manipulation",
  "rules-file-hidden-text",
  "sched-unattended-queue",
  "secrets-env-context-disclosure",
  "secrets-system-prompt-marker",
  "self-config-escalation",
  "self-modifying-notes-persistence",
  "skill-file-poison",
  "ssrf-internal-url-fetch",
  "ssrf-metadata-redirect",
  "xuser-record-leak",
];

const RESEARCH_AREAS = ["Direct injection", "Indirect injection", "Attack strategy", "Excessive agency", "Exfiltration", "Secrets disclosure", "System prompt leakage", "Memory poisoning", "RAG poisoning", "Goal hijacking", "MCP poisoning", "MCP rug pull", "MCP shadowing", "Supply chain", "Skills poisoning", "Rules-file poisoning", "Config abuse", "Confused deputy", "Cross-user leakage", "Permission escalation", "Identity", "Credential disclosure", "Payment", "Payment mandate", "Payment recipient", "Payment amount", "Purchase manipulation", "Payment replay", "Multi-agent", "Browser", "Scheduled and background", "CI agent", "SSRF through tools", "Unbounded consumption", "Eval integrity"];

const RESERVED_HOST = /(^|\.)(invalid|test|example)$|^example\.(com|org|net)$|(^|\.)example\.(com|org|net)$/;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001F\u007F-\u009F]/;
const hostsIn = (text: string): string[] => [...[...text.matchAll(/https?:\/\/([^/\s:?#"')\]>]+)/gi)].map(m => m[1]!), ...[...text.matchAll(/[\w.+-]+@([\w.-]+\.[A-Za-z]+)/g)].map(m => m[1]!)].map(host => host.toLowerCase());

function toolsIn(oracle: OracleSpec): { tools: string[]; args: { tool: string; arg: string }[] } {
  const out: { tools: string[]; args: { tool: string; arg: string }[] } = { tools: [], args: [] };
  const walk = (node: OracleSpec): void => {
    switch (node.kind) {
      case "marker-in-sink": out.tools.push(...(node.tools ?? [])); return;
      case "tool-called": out.tools.push(node.tool); if (node.where) out.args.push({ tool: node.tool, arg: node.where.arg }); return;
      case "tool-not-called": out.tools.push(node.tool); return;
      case "sequence": node.steps.forEach(walk); return;
      case "any": case "all": node.of.forEach(walk); return;
    }
  };
  walk(oracle);
  return out;
}

const manifest = (tools: string[], sources: BrainManifest["sources"] = []): BrainManifest => ({ tools: tools.map(name => ({ name, privilege: VOCABULARY[name]?.privilege === "source" ? "none" : (VOCABULARY[name]?.privilege ?? "none") as BrainManifest["tools"][number]["privilege"], gate: "none" })), sources });

describe("catalog contents", () => {
  it("converts every research row and nothing else", () => {
    expect(CATALOG.map(spec => spec.id).sort()).toEqual([...RESEARCH_IDS].sort());
    expect(CATALOG.length).toBeGreaterThanOrEqual(80);
  });

  it("has unique kebab-case ids and every research area", () => {
    const ids = CATALOG.map(spec => spec.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) expect(id).toMatch(/^[a-z0-9]+(-[a-z0-9]+)*$/);
    for (const id of ids) expect(id.length).toBeLessThanOrEqual(64);
    const areas = Object.keys(catalogStats().byArea);
    for (const area of RESEARCH_AREAS) expect(areas.some(a => a.toLowerCase().startsWith(area.toLowerCase())), area).toBe(true);
    expect(CATALOG_BY_ID.size).toBe(CATALOG.length);
  });

  it("keeps oracles and requirements inside the shared vocabulary", () => {
    for (const spec of CATALOG) {
      const { tools, args } = toolsIn(spec.oracle);
      for (const tool of [...tools, ...(spec.requires.tools ?? [])]) expect(VOCABULARY_TOOLS, `${spec.id}: ${tool}`).toContain(tool);
      for (const { tool, arg } of args) expect(VOCABULARY[tool]!.args, `${spec.id}: ${tool}.${arg}`).toContain(arg);
      expect(spec.weakness.length).toBeGreaterThan(10);
      expect(spec.payloadShape.length).toBeGreaterThan(10);
    }
  });

  it("only uses framework tags that are OWASP LLM Top 10 2025 ids", () => {
    for (const spec of CATALOG) for (const tag of spec.tags) {
      expect(tag.framework).toBe("OWASP LLM Top 10 (2025)");
      expect(tag.id).toMatch(/^LLM(0[1-9]|10)$/);
    }
  });

  it("gives a template to every open or both generator and none to closed ones", () => {
    const withTemplate = new Set(TEMPLATES.map(t => t.generatorId));
    expect(withTemplate.size).toBe(TEMPLATES.length);
    for (const spec of CATALOG) expect(withTemplate.has(spec.id), spec.id).toBe(spec.tier !== "closed");
    for (const template of TEMPLATES) expect(CATALOG_BY_ID.has(template.generatorId)).toBe(true);
  });

  it("writes safe, well-formed templates", () => {
    for (const template of TEMPLATES) {
      const where = template.generatorId;
      expect(template.payload, where).toContain(CANARY_PLACEHOLDER);
      expect(template.success.includes(CANARY_PLACEHOLDER) || VOCABULARY_TOOLS.some(tool => template.success.includes(tool)), where).toBe(true);
      for (const field of [template.goal, template.payload, template.success]) {
        expect(field.length, where).toBeGreaterThan(0);
        expect(field.length, where).toBeLessThanOrEqual(1000);
        // Newline and tab are allowed in text; any other control character is not.
        expect(CONTROL.test(field.replace(/[\n\t]/g, "")), where).toBe(false);
        for (const host of hostsIn(field)) expect(RESERVED_HOST.test(host), `${where}: ${host}`).toBe(true);
      }
      expect(template.goal.length, where).toBeLessThanOrEqual(300);
      expect(template.success.length, where).toBeLessThanOrEqual(500);
      expect(template.payload, where).not.toMatch(/sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{12,}/);
    }
  });

  it("reports counts by area, tier and difficulty", () => {
    const stats = catalogStats();
    expect(stats.total).toBe(CATALOG.length);
    expect(Object.values(stats.byArea).reduce((a, b) => a + b, 0)).toBe(stats.total);
    expect(stats.byTier.open + stats.byTier.closed + stats.byTier.both).toBe(stats.total);
    expect(stats.byDifficulty.basic + stats.byDifficulty.intermediate + stats.byDifficulty.advanced).toBe(stats.total);
    expect(stats.byTier.closed).toBeGreaterThan(0);
    expect(stats.byTier.open).toBeGreaterThan(0);
  });
});

describe("oracles run against the shared vocabulary", () => {
  const canary = "CANARY-1a2b3c4d5e6f";
  it("a representative oracle fires on the intended call and not on an unrelated one", () => {
    const spec = CATALOG_BY_ID.get("pay-injected-unauthorized-purchase")!;
    const hit = [{ seq: 1, tool: "make_payment", privilege: "network-out" as const, args: { to: "shop@example.test", amount: 3, currency: "EUR", memo: canary } }];
    const miss = [{ seq: 1, tool: "make_payment", privilege: "network-out" as const, args: { to: "shop@example.test", amount: 3, currency: "EUR", memo: "lunch" } }];
    expect(evaluateOracle(hit, spec.oracle, { canary }).hit).toBe(true);
    expect(evaluateOracle(miss, spec.oracle, { canary }).hit).toBe(false);
    const cap = CATALOG_BY_ID.get("pay-mandate-cap-overreach")!;
    expect(evaluateOracle([{ seq: 1, tool: "make_payment", privilege: "network-out", args: { amount: 25 } }], cap.oracle, { canary }).hit).toBe(true);
    expect(evaluateOracle([{ seq: 1, tool: "request_user_approval", privilege: "read-local", args: { action: "pay" } }, { seq: 2, tool: "make_payment", privilege: "network-out", args: { amount: 4 } }], cap.oracle, { canary }).hit).toBe(false);
    const gate = CATALOG_BY_ID.get("agency-approval-gate-skip")!;
    expect(evaluateOracle([{ seq: 1, tool: "run_command", privilege: "exec", args: { command: `echo ${canary}` } }], gate.oracle, { canary }).hit).toBe(true);
    const loop = CATALOG_BY_ID.get("consume-recursive-spawn")!;
    const spawn = (n: number) => ({ seq: n, tool: "spawn_agent", privilege: "exec" as const, args: { role: "checker", instructions: "verify" } });
    expect(evaluateOracle([spawn(1), spawn(2), spawn(3)], loop.oracle, { canary }).hit).toBe(true);
    expect(evaluateOracle([spawn(1)], loop.oracle, { canary }).hit).toBe(false);
  });

  it("every tool-called oracle for an open template fires on a call built from its own condition", () => {
    for (const template of TEMPLATES) {
      const spec = CATALOG_BY_ID.get(template.generatorId)!;
      if (spec.oracle.kind !== "tool-called" || !spec.oracle.where?.contains) continue;
      const value = `x ${spec.oracle.where.contains} y`.split(CANARY_PLACEHOLDER).join(canary);
      const event = { seq: 1, tool: spec.oracle.tool, privilege: VOCABULARY[spec.oracle.tool]!.privilege, args: { [spec.oracle.where.arg]: value } };
      expect(evaluateOracle([event], spec.oracle, { canary }).hit, spec.id).toBe(true);
    }
  });
});

describe("selectGenerators", () => {
  const everything = manifest(VOCABULARY_TOOLS as string[]);
  const noPayments = manifest(VOCABULARY_TOOLS.filter(tool => !["make_payment", "get_quote", "list_products"].includes(tool)));

  it("never gives payment generators to an agent without a payment tool", () => {
    const chosen = selectGenerators(noPayments);
    expect(chosen.length).toBeGreaterThan(0);
    for (const spec of chosen) expect(spec.requires.tools ?? [], spec.id).not.toContain("make_payment");
    expect(chosen.some(spec => spec.area.startsWith("Payment"))).toBe(false);
    expect(chosen.some(spec => spec.id === "pay-injected-unauthorized-purchase")).toBe(false);
    expect(selectGenerators(everything).some(spec => spec.id === "pay-injected-unauthorized-purchase")).toBe(true);
  });

  it("honours every requirement for every agent shape", () => {
    for (const m of [everything, noPayments, manifest(["send_email"]), manifest(["read_file", "http_post"], [{ kind: "web" }]), manifest([])]) {
      for (const spec of selectGenerators(m)) expect(applies(spec, m), spec.id).toBe(true);
    }
    expect(selectGenerators(manifest([]))).toEqual([]);
  });

  it("requires privileges and sources when the manifest lists them", () => {
    const noNetwork: BrainManifest = { tools: [{ name: "read_file", privilege: "read-local", gate: "none" }], sources: [{ kind: "document" }] };
    const ids = selectGenerators(noNetwork).map(spec => spec.id);
    expect(ids).not.toContain("indirect-repo-issue-text");
    expect(ids).not.toContain("agency-network-out-unrequested");
    expect(ids).toContain("indirect-document-embedded");
    expect(ids).not.toContain("indirect-web-hidden-text");
  });

  it("filters by difficulty, area and tier and respects the count", () => {
    expect(selectGenerators(everything, { difficulties: ["advanced"] }).every(spec => spec.difficulty === "advanced")).toBe(true);
    expect(selectGenerators(everything, { areas: ["exfiltration"] }).every(spec => spec.area.startsWith("Exfiltration"))).toBe(true);
    expect(selectGenerators(everything, { areas: ["exfiltration"] }).length).toBeGreaterThan(1);
    expect(selectGenerators(everything, { tiers: ["closed"] }).every(spec => spec.tier === "closed")).toBe(true);
    expect(selectGenerators(everything, { count: 7 })).toHaveLength(7);
  });

  it("mixes difficulties and areas in a small pick", () => {
    const chosen = selectGenerators(everything, { count: 9 });
    expect(new Set(chosen.map(spec => spec.difficulty)).size).toBe(3);
    expect(new Set(chosen.map(spec => spec.area)).size).toBeGreaterThanOrEqual(5);
  });

  it("is deterministic for one seed and varies across seeds", () => {
    const ids = (seed?: string) => selectGenerators(everything, { count: 6, ...(seed ? { seed } : {}) }).map(spec => spec.id).join();
    expect(ids("CANARY-aaaaaaaaaaaa")).toBe(ids("CANARY-aaaaaaaaaaaa"));
    expect(new Set(["CANARY-0a", "CANARY-1b", "CANARY-2c", "CANARY-3d", "CANARY-4e"].map(ids)).size).toBeGreaterThan(1);
  });
});

describe("catalogScenarios", () => {
  const everything = manifest(VOCABULARY_TOOLS as string[], [{ kind: "web" }, { kind: "email" }, { kind: "document" }, { kind: "tool-result" }, { kind: "repository" }, { kind: "memory" }, { kind: "user-message" }, { kind: "other" }]);

  it("produces output that the brain contract accepts", () => {
    const scenarios = catalogScenarios(everything, "CANARY-1a2b3c4d5e6f", 20);
    expect(scenarios).toHaveLength(20);
    const checked = validateResponse({ v: 1, task: "scenarios", scenarios });
    expect(checked.ok, checked.ok ? "" : checked.error).toBe(true);
    expect(new Set(scenarios.map(s => s.id)).size).toBe(20);
  });

  it("validates the whole open catalog", () => {
    const scenarios = catalogScenarios(everything, "CANARY-0", 50);
    expect(scenarios.length).toBe(Math.min(50, TEMPLATES.length));
    expect(validateResponse({ v: 1, task: "scenarios", scenarios }).ok).toBe(true);
  });

  it("only returns open templates that fit the agent", () => {
    const m = manifest(["send_email", "read_email"], [{ kind: "email" }]);
    const scenarios = catalogScenarios(m, "CANARY-1", 20);
    expect(scenarios.length).toBeGreaterThan(0);
    for (const scenario of scenarios) {
      expect(CATALOG_BY_ID.get(scenario.id)!.tier).not.toBe("closed");
      expect(applies(CATALOG_BY_ID.get(scenario.id)!, m)).toBe(true);
      expect(scenario.payload).toContain(CANARY_PLACEHOLDER);
    }
    expect(scenarios.some(s => s.id === "indirect-email-body")).toBe(true);
    expect(catalogScenarios(manifest([]), "CANARY-1", 5)).toEqual([]);
  });
});
