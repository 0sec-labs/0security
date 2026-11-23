import { describe, expect, it } from "vitest";
import { fixBranchName, pullRequestBody, runFix, type FindingToFix, type FixDeps, type FixOptions } from "../fix.js";
import { parseFixPolicyDocument, type LoadedFixPolicy } from "../fix-policy.js";
import {
  commitSubject, footerText, isDraft, isReviewerName, MAX_RENDERED_CHARS, parsePullRequestConventions, pullRequestTitle, renderTemplate,
  type PullRequestConventions,
} from "../fix-conventions.js";

const finding: FindingToFix = { id: "f-1234567890ab", fingerprint: "sarif-x:abc", title: "SQL injection in search", severity: "high", category: "sql-injection", tool: "foxguard", description: "d", path: "src/db.ts", startLine: 10 };

describe("pull request conventions: parsing", () => {
  it("accepts every setting", () => {
    const parsed = parsePullRequestConventions({ titleTemplate: "SEC-1 {severity}: {title}", branchPrefix: "sec/fix-", labels: ["security", "needs review"], draft: "always", bodyFooter: "Ticket SEC-1", reviewers: ["alice", "acme/appsec"], commitMessageTemplate: "SEC-1 fix {id}" });
    expect(parsed).toMatchObject({ branchPrefix: "sec/fix-", draft: "always", reviewers: ["alice", "acme/appsec"] });
  });
  it("rejects unknown settings, unknown placeholders and stray braces", () => {
    expect(() => parsePullRequestConventions({ title: "x" })).toThrow(/not a setting/);
    expect(() => parsePullRequestConventions({ titleTemplate: "{title} {env}" })).toThrow(/Use only/);
    expect(() => parsePullRequestConventions({ titleTemplate: "{env.HOME}" })).toThrow(/stray brace/);
    expect(() => parsePullRequestConventions({ titleTemplate: "{{title}" })).toThrow(/stray brace/);
    expect(() => parsePullRequestConventions({ titleTemplate: "a\nb" })).toThrow(/one line/);
    expect(() => parsePullRequestConventions({ titleTemplate: "x".repeat(300) })).toThrow(/longer/);
  });
  it("rejects a bad branch prefix, label, reviewer and draft rule", () => {
    for (const branchPrefix of ["-x", "a..b", "a b", "/a", "a;rm", "x".repeat(50)]) expect(() => parsePullRequestConventions({ branchPrefix })).toThrow(/branchPrefix/);
    expect(() => parsePullRequestConventions({ labels: ["ok", "bad;label"] })).toThrow(/label name/);
    expect(() => parsePullRequestConventions({ reviewers: ["alice bob"] })).toThrow(/user name or org\/team/);
    expect(() => parsePullRequestConventions({ reviewers: ["--add-reviewer=x"] })).toThrow(/user name/);
    expect(() => parsePullRequestConventions({ draft: "sometimes" })).toThrow(/always, on-failure or never/);
    expect(isReviewerName("acme/appsec")).toBe(true);
    expect(isReviewerName("a/b/c")).toBe(false);
  });
  it("reads the settings from a policy file without handing them to the model", () => {
    const { policy, conventions } = parseFixPolicyDocument(JSON.stringify({ rules: ["use parameterized queries"], pullRequest: { labels: ["security"] } }));
    expect(policy).toEqual({ rules: ["use parameterized queries"] });
    expect(conventions).toEqual({ labels: ["security"] });
    expect(() => parseFixPolicyDocument(JSON.stringify({ pullRequest: { reviewers: ["x y"] } }), "p.json")).toThrow(/reviewers/);
  });
});

describe("pull request conventions: rendering", () => {
  it("fills placeholders and nothing else", () => {
    expect(pullRequestTitle(finding, { titleTemplate: "SEC-9 [{severity}] {title} ({category}) {path} {id}" })).toBe("SEC-9 [high] SQL injection in search (sql-injection) src/db.ts f-123456");
  });
  it("neutralises values, so a finding title cannot mention people, link issues or add markup", () => {
    const text = renderTemplate("{title}", { ...finding, title: "ping @victim, see #12 <b>x</b> `y`\nnext" });
    expect(text).not.toMatch(/@(?!​)/);
    expect(text).not.toMatch(/#(?!​)\d/);
    expect(text).not.toMatch(/[<>`\n]/);
  });
  it("does not run template text: braces in a title are inert", () => {
    expect(renderTemplate("{title}", { ...finding, title: "{path} ${HOME} $(id)" })).toBe("{path} ${HOME} $(id)");
  });
  it("caps the length", () => {
    expect(renderTemplate("{title}", { ...finding, title: "x".repeat(1000) }).length).toBe(MAX_RENDERED_CHARS);
  });
  it("falls back to the plain defaults when nothing is set", () => {
    expect(pullRequestTitle(finding)).toBe("fix: SQL injection in search");
    expect(commitSubject(finding, {})).toBe("fix: SQL injection in search");
    expect(isDraft(false)).toBe(true);
    expect(isDraft(true)).toBe(false);
    expect(footerText({})).toBeUndefined();
  });
  it("applies the draft rule", () => {
    expect(isDraft(true, { draft: "always" })).toBe(true);
    expect(isDraft(false, { draft: "never" })).toBe(false);
    expect(isDraft(false, { draft: "on-failure" })).toBe(true);
  });
  it("appends a neutralised footer to the body only when one is set", () => {
    const footer = footerText({ bodyFooter: "Ticket SEC-9 @owner\n<script>x</script>" })!;
    expect(footer).not.toMatch(/<script>|@(?!​)/);
    expect(pullRequestBody(finding, "done", [], footer).endsWith(footer)).toBe(true);
    expect(pullRequestBody(finding, "done", [])).toBe(pullRequestBody(finding, "done", [], undefined));
  });
});

function harness(conventions: PullRequestConventions | undefined, extra: { fromRepo?: boolean; failReviewers?: boolean; labelsInRepo?: string } = {}) {
  const calls: string[] = [];
  const warnings: string[] = [];
  const bodies: string[] = [];
  const client = { request: async (method: string, path: string) => {
    if (method === "POST" && path.endsWith("/sessions")) return { session: { id: "t1" } };
    if (method === "GET") return { snapshot: { session: { status: "ready" }, messages: [{ role: "assistant", content: [{ type: "text", text: "Fixed." }] }], usage: { costUsd: 0.1 } } };
    return {};
  } };
  const deps: FixDeps = {
    open: async () => client as never, err: text => { warnings.push(text); }, sleep: async () => {}, startConsole: async () => () => {}, out: () => {},
    git: async (_cwd, args) => {
      calls.push(`git ${args.join(" ")}`);
      if (args[0] === "rev-parse" && args[1] === "--show-toplevel") return "/repo\n";
      if (args[0] === "symbolic-ref") return "origin/main\n";
      if (args[0] === "status") return " M src/db.ts\n";
      return "";
    },
    gh: async (_cwd, args) => {
      calls.push(`gh ${args.join(" ")}`);
      if (args[0] === "pr" && args[1] === "list") return "[]";
      if (args[0] === "pr" && args[1] === "create") return "https://github.com/o/r/pull/7\n";
      if (args[0] === "repo") return "o/r\n";
      if (args[0] === "api" && args.includes("--paginate")) return extra.labelsInRepo ?? "";
      if (args[0] === "api" && args.includes("POST")) throw new Error("HTTP 403: forbidden");
      if (args[0] === "pr" && args[1] === "edit" && extra.failReviewers && args.some(arg => arg.startsWith("--add-reviewer"))) throw new Error("not a collaborator");
      return "";
    },
    check: async (_cwd, command) => ({ command, code: 0, output: "" }),
    loadFinding: () => finding,
    loadPolicy: () => conventions ? { policy: {}, conventions, source: "/ops/p.json", fromRepo: extra.fromRepo ?? false } as LoadedFixPolicy : undefined,
    makeTemp: () => "/tmp/x", removeTemp: () => {}, writeFile: (_p, text) => { bodies.push(text); },
  };
  return { deps, calls, warnings, bodies };
}
const options = (extra: Partial<FixOptions> = {}): FixOptions => ({ budget: "3", timeout: "60", pr: true, ...extra });

describe("0 findings fix with conventions", () => {
  const all: PullRequestConventions = { titleTemplate: "SEC-9 {severity}: {title}", branchPrefix: "sec/fix-", labels: ["security", "exists"], draft: "always", bodyFooter: "Tracked in SEC-9", reviewers: ["alice", "acme/appsec"], commitMessageTemplate: "SEC-9 fix {id}: {title}" };

  it("names the branch, commit, title, draft state, footer, labels and reviewers from the policy", async () => {
    const h = harness(all, { labelsInRepo: "exists\n" });
    const branch = fixBranchName(finding.fingerprint, "sec/fix-");
    const outcome = await runFix("f-1", options({ test: ["pnpm test"] }), h.deps);
    expect(outcome).toMatchObject({ branch, pullRequest: { created: true, draft: true } });
    expect(branch.startsWith("sec/fix-")).toBe(true);
    expect(h.calls.find(c => c.startsWith("git worktree add"))).toContain(`-B ${branch}`);
    expect(h.calls.find(c => c.startsWith("git push"))).toContain(`${branch}:${branch}`);
    expect(h.calls.find(c => c.startsWith("git") && c.includes(" commit "))).toContain("SEC-9 fix f-123456: SQL injection in search");
    const create = h.calls.find(c => c.startsWith("gh pr create"))!;
    expect(create).toContain("--title SEC-9 high: SQL injection in search");
    expect(create).toContain("--draft");
    expect(h.bodies[0]!.endsWith("Tracked in SEC-9")).toBe(true);
    expect(h.calls).toContain("gh pr edit 7 --add-label=exists");
    expect(h.calls).toContain("gh pr edit 7 --add-reviewer=alice --add-reviewer=acme/appsec");
    // The label that does not exist could not be created: a warning, not a failure.
    expect(h.warnings.some(w => /could not create label 'security'/.test(w))).toBe(true);
  });

  it("warns and carries on when reviewers cannot be requested", async () => {
    const h = harness({ reviewers: ["alice"] }, { failReviewers: true });
    const outcome = await runFix("f-1", options(), h.deps);
    expect(outcome?.pullRequest?.url).toContain("/pull/7");
    expect(h.warnings.some(w => /reviewers were not requested/.test(w))).toBe(true);
  });

  it("changes nothing when no conventions are set", async () => {
    const h = harness(undefined);
    const outcome = await runFix("f-1", options({ test: ["pnpm test"] }), h.deps);
    expect(outcome?.branch).toBe(fixBranchName(finding.fingerprint));
    expect(h.calls.find(c => c.startsWith("gh pr create"))).toContain("--title fix: SQL injection in search");
    expect(h.calls.find(c => c.startsWith("gh pr create"))).not.toContain("--draft");
    expect(h.calls.some(c => c.startsWith("gh pr edit") || c.startsWith("gh api"))).toBe(false);
    expect(h.calls.find(c => c.startsWith("git") && c.includes(" commit "))).toContain("fix: SQL injection in search");
  });

  it("ignores conventions that come from the repository under fix", async () => {
    const h = harness(all, { fromRepo: true });
    const outcome = await runFix("f-1", options({ test: ["pnpm test"] }), h.deps);
    expect(outcome?.branch).toBe(fixBranchName(finding.fingerprint));
    expect(h.calls.some(c => c.startsWith("gh pr edit"))).toBe(false);
  });

  it("with --no-pr the commit still follows the template and nothing is pushed", async () => {
    const h = harness(all);
    const outcome = await runFix("f-1", options({ pr: false }), h.deps);
    expect(outcome).toMatchObject({ committed: true, branch: fixBranchName(finding.fingerprint, "sec/fix-") });
    expect(h.calls.some(c => c.startsWith("git push") || c.startsWith("gh "))).toBe(false);
    expect(h.calls.find(c => c.startsWith("git") && c.includes(" commit "))).toContain("SEC-9 fix f-123456");
  });
});
