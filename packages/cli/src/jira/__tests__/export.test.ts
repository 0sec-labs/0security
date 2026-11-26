import { afterEach, describe, expect, it } from "vitest";
import { runJiraExport, type JiraExportDeps } from "../export.js";
import { startFakeJira, type FakeJira } from "./fake-jira.js";

const TOKEN = "jira-secret-token-123";
const scan = JSON.stringify({ findings: [
  { id: "f-1", title: "SQL injection in login", severity: "high", status: "confirmed", category: "sql-injection", description: "User input reaches a query.", location: { path: "src/login.ts", startLine: 12 }, impact: { rationale: "Account takeover." }, remediation: { summary: "Use parameterised queries.", steps: ["Replace string concatenation", "Add a test"], references: [] } },
  { id: "f-2", title: "Weak hash", severity: "low", status: "reported", category: "crypto", description: "MD5.", location: { path: "src/h.ts", startLine: 3 } },
  { id: "f-3", title: "Not real", severity: "high", status: "false-positive", category: "x", description: "n" },
  { id: "f-4", title: "Already fixed", severity: "high", status: "fixed", category: "x", description: "n" },
  { id: "f-5", title: "Accepted risk", severity: "medium", status: "reported", triageStatus: "suppressed", category: "x", description: "n" },
] });

let fake: FakeJira | undefined;
afterEach(async () => { await fake?.close(); fake = undefined; });

const deps = (env: Record<string, string>): JiraExportDeps => ({ env, fetch: (url, init) => fetch(url, init), readText: () => scan });
const cloudAuth = `Basic ${Buffer.from(`me@example.com:${TOKEN}`).toString("base64")}`;

describe("jira export", () => {
  it("creates one issue per open finding on Cloud, then creates nothing on a rerun", async () => {
    fake = await startFakeJira("jira-cloud", cloudAuth);
    const env = { JIRA_TOKEN: TOKEN, JIRA_EMAIL: "me@example.com" };
    const options = { to: "jira-cloud" as const, project: "SEC", issueType: "Bug", labels: ["team-a"], url: fake.url };
    const first = await runJiraExport("scan.json", options, deps(env));
    expect(first.created.map(c => c.key)).toEqual(["SEC-1", "SEC-2"]);
    expect(first.skipped).toBe(3);
    const issue = fake.issues[0]!.fields;
    expect(issue.summary).toBe("SQL injection in login");
    expect(issue.issuetype).toEqual({ name: "Bug" });
    expect(issue.labels).toEqual(["0security", "high", "0-finding-f-1", "team-a"]);
    expect(JSON.stringify(issue.description)).toContain("src/login.ts:12");
    expect(JSON.stringify(issue.description)).toContain("1. Replace string concatenation");
    expect(JSON.stringify(issue.description)).toContain("Account takeover.");
    expect(issue.description.type).toBe("doc");
    const second = await runJiraExport("scan.json", options, deps(env));
    expect(second.created).toEqual([]);
    expect(second.existing.map(e => e.key)).toEqual(["SEC-1", "SEC-2"]);
    expect(fake.issues).toHaveLength(2);
  });

  it("uses a bearer token and plain-text description on Data Center", async () => {
    fake = await startFakeJira("jira-dc", `Bearer ${TOKEN}`);
    const result = await runJiraExport("scan.json", { to: "jira-dc", project: "SEC", url: fake.url }, deps({ JIRA_TOKEN: TOKEN }));
    expect(result.created).toHaveLength(2);
    expect(fake.issues[0]!.fields.issuetype).toEqual({ name: "Task" });
    expect(typeof fake.issues[0]!.fields.description).toBe("string");
    expect(fake.requests[0]!.path).toBe("/ctx/rest/api/2/search");
  });

  it("dry run sends nothing and needs no token", async () => {
    const result = await runJiraExport("scan.json", { to: "jira-cloud", project: "SEC", dryRun: true }, { ...deps({}), fetch: () => { throw new Error("no network in a dry run"); } });
    expect(result.dryRun).toBe(true);
    expect(result.planned).toHaveLength(2);
    expect(result.skipped).toBe(3);
  });

  it("refuses without a token, without Cloud email, and under ZERO_ENTERPRISE", async () => {
    await expect(runJiraExport("scan.json", { to: "jira-dc", project: "SEC", url: "https://jira.internal" }, deps({}))).rejects.toThrow(/JIRA_TOKEN/);
    await expect(runJiraExport("scan.json", { to: "jira-cloud", project: "SEC", url: "https://jira.internal" }, deps({ JIRA_TOKEN: TOKEN }))).rejects.toThrow(/JIRA_EMAIL/);
    let called = false;
    await expect(runJiraExport("scan.json", { to: "jira-dc", project: "SEC", url: "https://jira.internal" }, { ...deps({ JIRA_TOKEN: TOKEN, ZERO_ENTERPRISE: "1" }), fetch: async () => { called = true; return { ok: true, status: 200, text: async () => "{}" }; } })).rejects.toThrow(/Jira/);
    expect(called).toBe(false);
    await expect(runJiraExport("scan.json", { to: "jira-dc", project: "SEC", url: "http://jira.internal" }, deps({ JIRA_TOKEN: TOKEN }))).rejects.toThrow(/plain HTTP/);
    await expect(runJiraExport("scan.json", { to: "jira-dc", project: "bad key!", url: "https://j" }, deps({ JIRA_TOKEN: TOKEN }))).rejects.toThrow(/project/);
  });

  it("never echoes the token or credentials in errors", async () => {
    fake = await startFakeJira("jira-cloud", cloudAuth);
    fake.failCreateWith = 400;
    const error = await runJiraExport("scan.json", { to: "jira-cloud", project: "SEC", url: fake.url }, deps({ JIRA_TOKEN: TOKEN, JIRA_EMAIL: "me@example.com" })).catch(e => e as Error);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toContain("400");
    expect((error as Error).message).not.toContain(TOKEN);
    expect((error as Error).message).not.toContain(cloudAuth.slice(6));
  });
  it("leaves info-level findings out by default and honours --jira-min-severity", async () => {
    const mixed = JSON.stringify({ findings: [
      { id: "m-1", title: "Reachable advisory", severity: "critical", status: "reported", category: "supply-chain", description: "Called.", location: { path: "pom.xml", startLine: 5 } },
      { id: "m-2", title: "Not-reached advisory", severity: "info", status: "reported", category: "supply-chain", description: "Never imported.", location: { path: "pom.xml", startLine: 6 } },
      { id: "m-3", title: "Medium note", severity: "medium", status: "reported", category: "x", description: "n" },
    ] });
    const run = (minSeverity?: "critical" | "high" | "medium" | "low" | "info") => runJiraExport("scan.json", { to: "jira-cloud", project: "SEC", dryRun: true, ...(minSeverity ? { minSeverity } : {}) }, { ...deps({}), readText: () => mixed });
    const byDefault = await run();
    expect(byDefault.planned!.map(i => i.findingId)).toEqual(["m-1", "m-3"]);
    expect(byDefault.belowMinimum).toBe(1);
    expect((await run("info")).planned!.map(i => i.findingId)).toEqual(["m-1", "m-2", "m-3"]);
    const high = await run("high");
    expect(high.planned!.map(i => i.findingId)).toEqual(["m-1"]);
    expect(high.belowMinimum).toBe(2);
    await expect(run("urgent" as never)).rejects.toThrow(/--jira-min-severity is one of/);
  });
});
