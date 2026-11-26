import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  BRANCH_PREFIX,
  failedCheckReports,
  fixBranchName,
  parseFixPolicy,
  fixMetric,
  pullRequestBody,
  runFix,
  type FixDeps,
  type FixOptions,
  type FindingToFix,
} from "../fix.js";
import type { FixPolicy } from "@0/engine/shared";
import type { LoadedFixPolicy } from "../fix-policy.js";
import type { StoredVariant, VariantStore } from "../variants.js";

const finding: FindingToFix = { id: "f-1234567890ab", fingerprint: "sarif-x:abc", title: "SQL injection in search", severity: "high", category: "sql-injection", tool: "foxguard", description: "d", path: "src/db.ts", startLine: 10 };

function harness(overrides: Partial<{ status: string; checks: Record<string, number>; pulls: string; remote: string; policy: FixPolicy; fromRepo: boolean; loadPolicyArgs: unknown[]; answer: (message: string) => string; variants: VariantStore; costs: Array<number | undefined>; tokens: boolean }> = {}) {
  const calls: string[] = [];
  const requests: Array<[string, string, unknown]> = [];
  const bodies: string[] = [];
  let threadIndex = -1;
  let lastReply = "Parameterized the query.";
  const client = { request: async (method: string, path: string, body?: unknown) => {
    requests.push([method, path, body]);
    if (method === "POST" && path.endsWith("/sessions")) { threadIndex++; return { session: { id: "t1" } }; }
    if (method === "POST" && path.endsWith("/messages") && overrides.answer) lastReply = overrides.answer((body as { text: string }).text);
    if (method === "GET") return { snapshot: { session: { status: "ready" }, messages: [{ role: "assistant", content: [{ type: "text", text: lastReply }] }], usage: { ...(overrides.tokens === false ? {} : { inputTokens: 10, outputTokens: 5 }), costUsd: overrides.costs ? overrides.costs[threadIndex] : 0.12 } } };
    return {};
  } };
  const deps: FixDeps = {
    open: async () => client as never, err: () => {}, sleep: async () => {}, startConsole: async () => () => {}, out: () => {},
    git: async (_cwd, args) => {
      calls.push(`git ${args.join(" ")}`);
      if (args[0] === "rev-parse" && args[1] === "--show-toplevel") return "/repo\n";
      if (args[0] === "remote" && args[1] === "get-url") return "https://github.com/o/r.git\n";
      if (args[0] === "symbolic-ref") return "origin/main\n";
      if (args[0] === "status") return overrides.status ?? " M src/db.ts\n";
      return "";
    },
    gh: async (_cwd, args) => { calls.push(`gh ${args.join(" ")}`); return args[1] === "list" ? overrides.pulls ?? "[]" : args[1] === "create" ? "https://github.com/o/r/pull/7\n" : ""; },
    check: async (_cwd, command) => ({ command, code: overrides.checks?.[command] ?? 0, output: "out" }),
    loadFinding: () => finding,
    loadPolicy: (root, opts) => { overrides.loadPolicyArgs?.push(root, opts); return overrides.policy ? { policy: overrides.policy, source: "/ops/policy.json", fromRepo: overrides.fromRepo ?? false } as LoadedFixPolicy : undefined; },
    ...(overrides.variants ? { variants: overrides.variants } : {}),
    makeTemp: () => "/tmp/x", removeTemp: () => {}, writeFile: (_p, text) => { bodies.push(text); },
  };
  return { deps, calls, requests, bodies };
}
const options = (extra: Partial<FixOptions> = {}): FixOptions => ({ budget: "3", timeout: "60", pr: true, ...extra });

describe("0 findings fix", () => {
  it("names the branch from the finding, the same every time, and never as the base", () => {
    expect(fixBranchName("a")).toBe(fixBranchName("a"));
    expect(fixBranchName("a")).not.toBe(fixBranchName("b"));
    expect(fixBranchName("a").startsWith(BRANCH_PREFIX)).toBe(true);
  });

  it("works in a separate work tree, pushes only its own branch and opens a ready pull request when checks pass", async () => {
    const h = harness();
    const outcome = await runFix("f-1", options({ test: ["pnpm test"] }), h.deps);
    expect(outcome).toMatchObject({ changed: true, committed: true, verified: true, pullRequest: { created: true, draft: false, url: "https://github.com/o/r/pull/7" } });
    const worktree = h.calls.find(call => call.startsWith("git worktree add"))!;
    expect(worktree).toContain(`-B ${fixBranchName(finding.fingerprint)}`);
    const push = h.calls.find(call => call.startsWith("git push"))!;
    expect(push).toContain("--force-with-lease");
    expect(push).toContain(`${fixBranchName(finding.fingerprint)}:${fixBranchName(finding.fingerprint)}`);
    expect(push).not.toContain(":main");
    expect(h.calls.find(call => call.startsWith("gh pr create"))).not.toContain("--draft");
    expect(h.calls.at(-1)).toContain("worktree remove");
    const message = h.requests.find(([, path]) => path.endsWith("/messages"))![2] as { text: string };
    expect(message.text).toContain("pnpm test");
    expect(message.text).toContain("<finding>");
  });

  it("opens a draft when a check fails, and says which", async () => {
    const h = harness({ checks: { "pnpm lint": 2 } });
    const outcome = await runFix("f-1", options({ test: ["pnpm test", "pnpm lint"] }), h.deps);
    expect(outcome).toMatchObject({ verified: false, pullRequest: { draft: true } });
    expect(h.calls.find(call => call.startsWith("gh pr create"))).toContain("--draft");
    expect(h.bodies[0]).toContain("failed (exit 2)");
  });

  it("opens a draft that says no checks were run when there is no --test, and a ready one with --ready", async () => {
    const h = harness();
    const outcome = await runFix("f-1", options(), h.deps);
    expect(outcome?.pullRequest).toMatchObject({ created: true, draft: true });
    expect(h.calls.find(call => call.startsWith("gh pr create"))).toContain("--draft");
    expect(h.bodies[0]).toContain("No checks were run.");
    const ready = harness();
    const readyOutcome = await runFix("f-1", options({ ready: true }), ready.deps);
    expect(readyOutcome?.pullRequest).toMatchObject({ draft: false });
    expect(ready.calls.find(call => call.startsWith("gh pr create"))).not.toContain("--draft");
    expect(ready.bodies[0]).toContain("No checks were run.");
  });

  it("updates the pull request that already exists instead of opening another", async () => {
    const h = harness({ pulls: JSON.stringify([{ number: 7, url: "https://github.com/o/r/pull/7", isDraft: true }]) });
    const outcome = await runFix("f-1", options({ test: ["pnpm test"] }), h.deps);
    expect(outcome?.pullRequest).toMatchObject({ created: false, draft: false });
    expect(h.calls.some(call => call.startsWith("gh pr create"))).toBe(false);
    expect(h.calls).toContain(`gh pr edit 7 --body-file ${join("/tmp/x", "body.md")} --repo o/r`);
    expect(h.calls).toContain("gh pr ready 7 --repo o/r");
  });

  describe("a Maven dependency finding", () => {
    const pom = (version: string) => `<project><dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>${version}</version></dependency></dependencies></project>`;
    const withTree = (text: string) => {
      const temp = mkdtempSync(join(tmpdir(), "0-fixdirect-"));
      mkdirSync(join(temp, "tree"));
      writeFileSync(join(temp, "tree", "pom.xml"), text);
      return temp;
    };
    const dependencyFinding: FindingToFix = { ...finding, category: "dependency", title: "org.apache.commons/commons-text 1.9 has GHSA-599f-7c49-w659", description: "org.apache.commons/commons-text 1.9 has GHSA-599f-7c49-w659: Arbitrary code execution. Fixed in 1.10.0.", path: "pom.xml", startLine: 1 };
    it("bumps the version itself, without a model, and says so in the pull request", async () => {
      const temp = withTree(pom("1.9"));
      const h = harness();
      h.deps.makeTemp = () => temp;
      h.deps.loadFinding = () => dependencyFinding;
      const outcome = await runFix("f-1", options({ test: ["mvn -q test"] }), h.deps);
      expect(readFileSync(join(temp, "tree", "pom.xml"), "utf8")).toContain("<version>1.10.0</version>");
      expect(h.requests).toEqual([]); // no console, no thread
      expect(outcome).toMatchObject({ changed: true, verified: true, costUsd: 0 });
      expect(outcome?.threadId).toBeUndefined();
      expect(h.bodies.join("\n")).toContain("The version edit used no model.");
      expect(h.bodies.join("\n")).toContain("Written by 0 from the edit it made.");
    });
    it("asks the model when the version is set outside the repository", async () => {
      const temp = withTree(pom("${external.version}"));
      const h = harness();
      h.deps.makeTemp = () => temp;
      h.deps.loadFinding = () => dependencyFinding;
      await runFix("f-1", options(), h.deps);
      expect(h.requests.some(([, path]) => path.endsWith("/messages"))).toBe(true);
      expect(readFileSync(join(temp, "tree", "pom.xml"), "utf8")).toContain("${external.version}");
      const message = h.requests.find(([, path]) => path.endsWith("/messages"))![2] as { text: string };
      expect(message.text).toContain("java-dependency-fix");
    });
  });

  it("opens nothing when the thread changed nothing", async () => {
    const h = harness({ status: "" });
    const outcome = await runFix("f-1", options(), h.deps);
    expect(outcome).toMatchObject({ changed: false, committed: false });
    expect(h.calls.some(call => call.startsWith("git commit") || call.startsWith("git push") || call.startsWith("gh "))).toBe(false);
  });

  it("commits but does not push with --no-pr, and refuses a remote engine", async () => {
    const h = harness();
    const outcome = await runFix("f-1", options({ pr: false }), h.deps);
    expect(outcome).toMatchObject({ committed: true });
    expect(h.calls.some(call => call.startsWith("git push"))).toBe(false);
    await expect(runFix("f-1", options({ computer: "box" }), harness().deps)).rejects.toThrow("local console");
  });

  it("keeps report text from notifying anyone in the pull request", () => {
    const body = pullRequestBody({ ...finding, title: "ping @victim about #12" }, "see @team", [{ command: "a|b", code: 1, output: "```x```" }]);
    expect(body).not.toMatch(/@(?!​)/);
    expect(body).toContain("Opened as a draft");
  });

  it("puts the real checks table before the model's text, labels that text, and drops its own Checks headings", () => {
    const body = pullRequestBody(finding, "Fixed it.\n## Checks\nnpm test exited with 3\n**Checks** all passed\nChecks:\n\nDone.", [{ command: "npm test", code: 2, output: "boom" }]);
    expect(body.indexOf("| `npm test` | failed (exit 2) |")).toBeGreaterThan(-1);
    expect(body.indexOf("failed (exit 2)")).toBeLessThan(body.indexOf("Summary written by the model (not verified)"));
    expect(body.indexOf("Summary written by the model (not verified)")).toBeLessThan(body.indexOf("Fixed it."));
    expect(body).not.toContain("exited with 3");
    expect(body).not.toContain("all passed");
    expect(body).toContain("Done.");
    expect(body.match(/### Checks/g)).toHaveLength(1);
  });

  it("escapes table cells and the command inside <summary>", () => {
    const body = pullRequestBody({ ...finding, category: "a|b <i>", tool: "t|x" }, undefined, [{ command: "echo </summary><script>", code: 1, output: "o" }]);
    expect(body).toContain("| high | a\\|b &lt;i&gt; | t\\|x |");
    expect(body).toContain("<summary>echo &lt;/summary&gt;&lt;script&gt;</summary>");
    expect(body.match(/<\/summary>/g)).toHaveLength(1);
  });

  it("hints an id that resolves, not a shared prefix", () => {
    const scan = `sarif-${"b".repeat(64)}`;
    expect(pullRequestBody({ ...finding, id: `${scan}-12345678abcdef` }, "s", [])).toContain("Fixes finding 12345678:");
  });
});

describe("run metrics", () => {
  it("records one row per run with counts and the finding id, and none for a usage error", async () => {
    const h = harness();
    const rows: unknown[] = [];
    const deps: FixDeps = { ...h.deps, metrics: row => { rows.push(row); } };
    await runFix("f-1", options({ test: ["pnpm test"], model: "m1" }), deps);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ command: "fix", model: "m1", budgetUsd: 3, costUsd: 0.12, findingsAttempted: 1, findingsProposed: 1, checksPassed: 1, status: "ok", findingIds: ["f-1234567890ab"] });
    expect(JSON.stringify(rows[0])).not.toContain("SQL injection");
    expect(JSON.stringify(rows[0])).not.toContain("src/db.ts");
    await expect(runFix("f-1", options({ budget: "0" }), deps)).rejects.toThrow();
    expect(rows).toHaveLength(1);
  });

  it("scores a failed check as proposed but not verified, and a run with no change as failed", () => {
    const base = { finding: "f-1", branch: "b", changed: true, checks: [] };
    expect(fixMetric({ ...base, committed: true, verified: false } as never, { budget: "1" }, 0, 5000)).toMatchObject({ findingsProposed: 1, checksPassed: 0, status: "ok", durationSeconds: 5 });
    expect(fixMetric({ ...base, committed: false, verified: false } as never, { budget: "1" }, 0, 0)).toMatchObject({ findingsProposed: 0, status: "failed" });
    expect(fixMetric(undefined, { budget: "1" }, 0, 0)).toMatchObject({ status: "failed", findingIds: [], costUsd: null });
    expect(fixMetric({ ...base, committed: true, verified: true, budgetExhausted: true } as never, { budget: "1" }, 0, 0).status).toBe("budget");
  });
});

describe("the commit identity", () => {
  it("uses a neutral one when git has none (a clean machine, an Actions runner), and the person's own when it has", async () => {
    const none = harness();
    await runFix("f-1", options({ pr: false }), none.deps);
    expect(none.calls.find(call => call.includes(" commit "))).toContain("-c user.email=noreply@0.security");
    const named = harness();
    const git = named.deps.git;
    named.deps.git = async (cwd, args) => (args[0] === "config" && args[1] === "user.email" ? "dev@example.com\n" : git(cwd, args));
    await runFix("f-1", options({ pr: false }), named.deps);
    expect(named.calls.find(call => call.includes(" commit "))).not.toContain("user.email");
  });
});

describe("fix policy injection", () => {
  it("injects fix policy into the thread prompt when policy is loaded", async () => {
    const policy: FixPolicy = {
      approvedLibraries: [
        { name: "kysely", preferredVersion: "^0.27.0", purpose: "SQL query building" },
        "dompurify",
      ],
      forbiddenPatterns: [
        { pattern: "eval", reason: "Arbitrary code execution risk" },
      ],
      rules: ["Always use parameterized queries for database operations"],
    };
    const h = harness({ policy });
    const outcome = await runFix("f-1", options({ policy: ".zero/fix-policy.json" }), h.deps);
    expect(outcome).toMatchObject({ changed: true, committed: true });
    const message = h.requests.find(([, path]) => path.endsWith("/messages"))![2] as { text: string };
    expect(message.text).toContain("<fix-policy>");
    expect(message.text).toContain("kysely (version: ^0.27.0, purpose: SQL query building)");
    expect(message.text).toContain("dompurify");
    expect(message.text).toContain("eval (reason: Arbitrary code execution risk)");
    expect(message.text).toContain("Always use parameterized queries for database operations");
    // The non-negotiable rules come after the policy block.
    expect(message.text.indexOf("Non-negotiable rules")).toBeGreaterThan(message.text.indexOf("</fix-policy>"));
  });

  it("asks for the repository's policy only with --repo-policy, and warns that it is untrusted", async () => {
    const policy: FixPolicy = { rules: ["r"] };
    const args: unknown[] = [];
    const opted = harness({ policy, fromRepo: true, loadPolicyArgs: args });
    const logs: string[] = [];
    opted.deps.err = line => { logs.push(line); };
    await runFix("f-1", options({ repoPolicy: true }), opted.deps);
    expect(args[1]).toMatchObject({ repoPolicy: true });
    expect(logs.join("\n")).toMatch(/repository being fixed, which is untrusted/);
    const plainArgs: unknown[] = [];
    const own = harness({ policy, loadPolicyArgs: plainArgs });
    const ownLogs: string[] = [];
    own.deps.err = line => { ownLogs.push(line); };
    await runFix("f-1", options(), own.deps);
    expect(plainArgs[1]).not.toMatchObject({ repoPolicy: true });
    expect(ownLogs.join("\n")).not.toMatch(/untrusted/);
  });
});

describe("parseFixPolicy", () => {
  it("parses valid JSON fix policy", () => {
    const json = JSON.stringify({
      approvedLibraries: ["dompurify", { name: "kysely", preferredVersion: "0.27" }],
      forbiddenPatterns: ["dangerouslySetInnerHTML"],
      rules: ["Do not add new dependencies"],
      notes: "Internal security policy v1",
    });
    const policy = parseFixPolicy(json, "test.json");
    expect(policy.approvedLibraries).toHaveLength(2);
    expect(policy.forbiddenPatterns).toEqual(["dangerouslySetInnerHTML"]);
    expect(policy.rules).toEqual(["Do not add new dependencies"]);
    expect(policy.notes).toBe("Internal security policy v1");
  });

  it("parses valid YAML fix policy", () => {
    const yaml = `
approvedLibraries:
  - dompurify
  - name: kysely
    purpose: SQL builder
rules:
  - Use parameterized queries
`;
    const policy = parseFixPolicy(yaml, "test.yaml");
    expect(policy.approvedLibraries).toHaveLength(2);
    expect(policy.rules).toEqual(["Use parameterized queries"]);
  });

  it("throws UsageError on invalid syntax", () => {
    expect(() => parseFixPolicy("not valid: [json or yaml", "bad.json")).toThrow("Failed to parse fix policy");
  });

  it("throws UsageError when policy is not an object", () => {
    expect(() => parseFixPolicy("[\"invalid\"]", "arr.json")).toThrow("must be an object");
    expect(() => parseFixPolicy("\"string\"", "str.json")).toThrow("must be an object");
  });
});

describe("0 findings fix records its outcome for export-fixes", () => {
  it("hands the repository, fingerprint and outcome to the recorder, and survives a recorder that fails", async () => {
    const h = harness();
    const seen: Array<{ repo: string; fingerprint: string; url?: string }> = [];
    const outcome = await runFix("f-1", options({ test: ["pnpm test"] }), { ...h.deps, record: e => { seen.push({ repo: e.repo, fingerprint: e.fingerprint, url: e.outcome.pullRequest?.url }); } });
    expect(seen).toEqual([{ repo: "/repo", fingerprint: "sarif-x:abc", url: "https://github.com/o/r/pull/7" }]);
    expect(outcome?.pullRequest?.url).toBe("https://github.com/o/r/pull/7");
    const failing = await runFix("f-1", options(), { ...harness().deps, record: () => { throw new Error("disk full"); } });
    expect(failing?.pullRequest?.url).toBe("https://github.com/o/r/pull/7");
  });
  it("records a run that changed nothing, and a committed run without a pull request", async () => {
    const seen: string[] = [];
    await runFix("f-1", options(), { ...harness({ status: "" }).deps, record: e => { seen.push(`${e.outcome.changed}/${e.outcome.committed}`); } });
    await runFix("f-1", options({ pr: false }), { ...harness().deps, record: e => { seen.push(`${e.outcome.changed}/${e.outcome.committed}`); } });
    expect(seen).toEqual(["false/false", "true/true"]);
  });

  describe("variant hunt after the fix", () => {
    const rootCause = { bugClass: "SQL injection", unsafePattern: { sink: "db.query with a template literal", source: "the id parameter" }, missingGuard: "a bound parameter", designOrigin: "a shared query helper" };
    const fence = (value: unknown) => `\`\`\`json\n${JSON.stringify(value)}\n\`\`\``;
    const memory = () => {
      const variants: StoredVariant[] = [{ id: "old-1", title: "SQL injection in src/orders.ts", status: "discovered", path: "src/orders.ts", startLine: 2 }];
      const saved: Array<{ id: string; variantOf: string; path: string }> = [];
      const fixed: string[] = [];
      const store: VariantStore = {
        variantsOf: () => variants.filter(v => !fixed.includes(v.id)).concat(saved.map(v => ({ id: v.id, title: "new", status: "discovered", path: v.path, startLine: 2 }))),
        saveRootCause: () => {},
        saveVariant: (parent, variant) => { const id = `new-${saved.length + 1}`; saved.push({ id, variantOf: parent.id, path: variant.path }); return id; },
        markFixedPendingMerge: (_parent, id) => { fixed.push(id); },
      };
      return { store, saved, fixed };
    };
    const answer = (text: string) => text.includes("<site>")
      ? fence({ site: "old-1", state: "fixed", reasoning: "src/orders.ts:2 binds the id." })
      : text.includes("<seed>")
        ? fence({ root_cause: { bug_class: "SQL injection", unsafe_pattern: { sink: "db.query with a template literal", source: "the id parameter" }, missing_guard: "a bound parameter", design_origin: "a shared query helper" }, variants: [{ title: "SQL injection in src/invoices.ts", severity: "high", file: "src/invoices.ts", startLine: 2, description: "Same sink at src/invoices.ts:2.", evidence: "db.query(template)" }] })
        : "Parameterized the query.";
    const withLinks = { ...finding, dbPath: "/db", scanId: "s1", rootCause };

    it("rescans the recorded variants in the fixed tree and records the new ones, seeded from the stored root cause", async () => {
      const mem = memory();
      const h = harness({ answer, variants: mem.store });
      h.deps.loadFinding = () => withLinks;
      const outcome = await runFix("f-1", options({ test: ["pnpm test"] }), h.deps);
      expect(outcome).toMatchObject({ committed: true, variants: { created: 1, rescanned: { fixed: 1, open: 0 } } });
      expect(mem.fixed).toEqual(["old-1"]);
      expect(mem.saved).toEqual([{ id: "new-1", variantOf: finding.id, path: "src/invoices.ts" }]);
      const seeded = h.requests.find(([, path, body]) => path.endsWith("/messages") && String((body as { text?: string }).text).includes("<seed>"));
      expect(String((seeded![2] as { text: string }).text)).toContain("a shared query helper");
      // The fix thread, the rescan and the hunt all ran in the fix work tree, not the user's checkout.
      expect(h.requests.filter(([method, , body]) => method === "PATCH" && (body as { workspacePath?: string }).workspacePath === "/tmp/x/tree")).toHaveLength(3);
    });

    it("clamps each follow-up to the remaining total and reports all receipts", async () => {
      const h = harness({ answer, variants: memory().store, costs: [0.2, 0.2, 0.1] });
      h.deps.loadFinding = () => withLinks;
      const outcome = await runFix("f-1", options({ budget: "0.5", pr: false }), h.deps);
      const caps = h.requests.filter(([m, p]) => m === "POST" && p.endsWith("/sessions")).map(([, , b]) => (b as { costCeilingUsd: number }).costCeilingUsd);
      expect(caps).toHaveLength(3);
      expect(caps[0]).toBe(0.5);
      expect(caps[1]).toBeCloseTo(0.3);
      expect(caps[2]).toBeCloseTo(0.1);
      expect(outcome!.costUsd).toBeCloseTo(0.5);
      expect(outcome!.tokens).toBe(45);
    });

    it("keeps an empty rescan known-zero and omits incomplete aggregate token receipts", async () => {
      const mem = memory();
      mem.store.variantsOf = () => [];
      const h = harness({ answer, variants: mem.store, costs: [0.2, 0.1], tokens: false });
      h.deps.loadFinding = () => withLinks;
      const outcome = await runFix("f-1", options({ budget: "0.5", pr: false }), h.deps);
      expect(outcome!.costUsd).toBeCloseTo(0.3);
      expect(outcome!.tokens).toBeUndefined();
      expect(outcome!.variants!.error).toBeUndefined();
      expect(h.requests.filter(([m, p]) => m === "POST" && p.endsWith("/sessions"))).toHaveLength(2);
    });

    it.each([[undefined], [NaN], [Infinity], [-1], [0.2, undefined], [0.5]])("stops further paid follow-ups after unknown or exhausted receipts %j", async (...costs) => {
      const h = harness({ answer, variants: memory().store, costs });
      h.deps.loadFinding = () => withLinks;
      const outcome = await runFix("f-1", options({ budget: "0.5", pr: false }), h.deps);
      expect(h.requests.filter(([m, p]) => m === "POST" && p.endsWith("/sessions"))).toHaveLength(costs.length);
      expect(outcome!.variants!.error).toMatch(/budget exhausted|receipt unavailable/);
      if (costs.some(cost => cost === undefined || !Number.isFinite(cost) || cost < 0)) expect(outcome!.costUsd).toBeUndefined();
      else expect(outcome!.costUsd).toBe(0.5);
    });

    it("does nothing extra with --no-variants, and a failed hunt never fails the fix", async () => {
      const off = memory();
      const h = harness({ answer, variants: off.store });
      h.deps.loadFinding = () => withLinks;
      const outcome = await runFix("f-1", options({ test: ["pnpm test"], variants: false }), h.deps);
      expect(outcome!.variants).toBeUndefined();
      expect(off.saved).toEqual([]);

      const broken = memory();
      broken.store.variantsOf = () => { throw new Error("db locked"); };
      const g = harness({ answer, variants: broken.store });
      g.deps.loadFinding = () => withLinks;
      const result = await runFix("f-1", options({ test: ["pnpm test"] }), g.deps);
      expect(result).toMatchObject({ committed: true, pullRequest: { created: true }, variants: { created: 0, error: "db locked" } });
    });
  });
});

describe("fix metric host association", () => {
  it("captures the actual returned PR URL, never a guessed URL from a branch or count", () => {
    const record = fixMetric({ finding: "f-1", committed: true, verified: true, pullRequest: { url: "https://bitbucket.org/o/r/pull-requests/8", created: true, draft: true } } as never, { budget: "1" }, 0, 1);
    expect(record.pullRequestUrl).toBe("https://bitbucket.org/o/r/pull-requests/8"); expect(record.repositoryId).toMatch(/^[a-f0-9]{64}$/);
    expect(fixMetric({ finding: "f-1", committed: true, branch: "0/fix-a" } as never, { budget: "1" }, 0, 1).pullRequestUrl).toBeUndefined();
  });
});

describe("failed check report", () => {
  it("names each failed check, keeps the last 15 lines and drops control characters", () => {
    const output = Array.from({ length: 20 }, (_, i) => `line ${i + 1}`).join("\n") + "\n\u001b[31mred\u001b[0m\u0007";
    const reports = failedCheckReports([{ command: "mvn -o test", code: 1, output }, { command: "ok", code: 0, output: "fine" }]);
    expect(reports).toHaveLength(1);
    expect(reports[0]).toContain("check failed (exit 1): mvn -o test");
    expect(reports[0]).toContain("  | line 7");
    expect(reports[0]).not.toContain("line 6\n");
    expect(reports[0]).not.toMatch(/[\u001b\u0007]/);
    expect(reports[0]).toContain("  | [31mred[0m");
    // Every output line is indented, so build output cannot pose as a message from the command.
    const forged = failedCheckReports([{ command: "t", code: 2, output: "x\nCommitted on main." }])[0]!;
    expect(forged.split("\n").slice(1).every((l) => l.startsWith("  | "))).toBe(true);
  });
});
