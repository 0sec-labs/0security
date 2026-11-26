import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { buildCodeInsights, dedupeFindings, planRequests, postCodeInsights, readInsightFindings, type FetchLike, type InsightFinding } from "./code-insights.js";
import { runBitbucketUpload, type UploadDeps } from "./commands/findings-upload.js";

const fixture = (name: string) => readFileSync(new URL(`./__fixtures__/code-insights/${name}`, import.meta.url), "utf8");
const SHA = "a".repeat(40);
const target = { owner: "acme", repo: "app", commit: SHA, baseUrl: "https://bitbucket.example.com/" };
const finding = (over: Partial<InsightFinding> = {}): InsightFinding => ({ ruleId: "r", severity: "low", title: "t", path: "f.py", line: 1, cwe: "CWE-1", description: "d", ...over });

describe("Code Insights payloads", () => {
  const findings = readInsightFindings(fixture("scan.json"));

  it("matches the recorded Bitbucket Cloud request shape", () => {
    const payload = buildCodeInsights(findings, "bitbucket-cloud");
    expect({ payload, requests: planRequests(payload, target) }).toEqual(JSON.parse(fixture("cloud.json")));
  });

  it("matches the recorded Data Center request shape", () => {
    const payload = buildCodeInsights(findings, "bitbucket-dc");
    expect({ payload, requests: planRequests(payload, target) }).toEqual(JSON.parse(fixture("data-center.json")));
  });

  it("carries rule id, CWE, verdict, rationale and fix guidance, and dedupes by path, line and CWE keeping the highest severity", () => {
    expect(findings).toHaveLength(5);
    const annotations = (buildCodeInsights(findings, "bitbucket-cloud").batches[0] as Array<Record<string, string>>);
    expect(annotations).toHaveLength(4);
    const sql = annotations[0]!;
    expect(sql).toMatchObject({ severity: "CRITICAL", path: "app/db.py", line: 12, annotation_type: "VULNERABILITY" });
    for (const text of ["Rule: injection", "CWE: CWE-89", "Verdict: verified, confidence 92%", "Rationale: Any unauthenticated", "Fix: Suggested replacement"]) expect(sql.details).toContain(text);
  });

  it("reads the fix explanation, puts it first in the fix text and keeps it inside the length caps", () => {
    const document = JSON.stringify({ findings: [{ category: "injection", severity: "high", title: "t", description: "d", location: { path: "a.py", startLine: 3 }, suggestedFix: { replacement: "run(q, [n])", explanation: "Bind n as a parameter so it is never read as SQL." } }] });
    const [item] = readInsightFindings(document);
    expect(item!.fixExplanation).toBe("Bind n as a parameter so it is never read as SQL.");
    const cloud = (buildCodeInsights([item!], "bitbucket-cloud").batches[0] as Array<Record<string, string>>)[0]!;
    expect(cloud.details).toContain("Fix: Bind n as a parameter so it is never read as SQL.\n\nSuggested replacement:\nrun(q, [n])");
    const long = { ...item!, fix: `Suggested replacement:\n${"x".repeat(5000)}` };
    const dc = (buildCodeInsights([long], "bitbucket-dc").batches[0] as { annotations: Array<Record<string, string>> }).annotations[0]!;
    expect(dc.message!.length).toBeLessThanOrEqual(2000);
    expect(dc.message).toContain("Fix: Bind n as a parameter");
  });

  it("has no CRITICAL in Data Center and respects its field limits", () => {
    const payload = buildCodeInsights([finding({ severity: "critical", description: "x".repeat(5000) }), finding({ line: 2, severity: "info" })], "bitbucket-dc");
    const annotations = (payload.batches[0] as { annotations: Array<Record<string, string>> }).annotations;
    expect(annotations.map(a => a.severity)).toEqual(["HIGH", "LOW"]);
    expect(annotations[0]!.message!.length).toBeLessThanOrEqual(2000);
    expect((payload.report.data as unknown[]).length).toBeLessThanOrEqual(6);
  });

  it("sends at most 100 annotations per Cloud request and 1000 per report, keeps the most severe and reports the dropped count", () => {
    const many = Array.from({ length: 1105 }, (_, index) => finding({ line: index + 1 }));
    many.push(finding({ ruleId: "crit", severity: "critical", path: "g.py", cwe: "CWE-2" }));
    const payload = buildCodeInsights(many, "bitbucket-cloud");
    const batches = payload.batches as unknown[][];
    expect(batches).toHaveLength(10);
    expect(batches.every(batch => batch.length <= 100)).toBe(true);
    expect(payload).toMatchObject({ total: 1106, emitted: 1000, dropped: 106 });
    expect(batches[0]![0]).toMatchObject({ severity: "CRITICAL", path: "g.py" });
    expect(payload.report.details).toContain("106 less severe findings");
  });

  it("dedupes without a CWE by rule and passes when there is nothing", () => {
    expect(dedupeFindings([finding({ cwe: undefined, ruleId: "a" }), finding({ cwe: undefined, ruleId: "b" })])).toHaveLength(2);
    expect(buildCodeInsights([], "bitbucket-cloud").report.result).toBe("PASSED");
    expect(buildCodeInsights([], "bitbucket-dc").report.result).toBe("PASS");
  });

  it("reads SARIF too", () => {
    const sarif = JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: "x", rules: [{ id: "r1", properties: { tags: ["external/cwe/cwe-79"] } }] } }, results: [{ ruleId: "r1", level: "error", message: { text: "bad" }, locations: [{ physicalLocation: { artifactLocation: { uri: "src/a.js" }, region: { startLine: 3 } } }] }] }] });
    expect(readInsightFindings(sarif)).toMatchObject([{ ruleId: "r1", severity: "high", path: "src/a.js", line: 3, cwe: "CWE-79" }]);
  });
});

describe("posting", () => {
  const ok = { ok: true, status: 200, text: async () => "" };
  it("PUTs the report then POSTs each batch, with the token only in the header", async () => {
    const calls: Array<{ url: string; method: string; headers: Record<string, string> }> = [];
    const fetcher: FetchLike = async (url, init) => { calls.push({ url, method: init.method, headers: init.headers }); return ok; };
    const many = Array.from({ length: 150 }, (_, index) => finding({ line: index + 1 }));
    await postCodeInsights(buildCodeInsights(many, "bitbucket-cloud"), target, "s3cret", fetcher);
    expect(calls.map(call => call.method)).toEqual(["PUT", "POST", "POST"]);
    expect(calls[0]!.url).toBe(`https://api.bitbucket.org/2.0/repositories/acme/app/commit/${SHA}/reports/0-security`);
    expect(calls[1]!.url).toBe(`${calls[0]!.url}/annotations`);
    expect(calls[0]!.headers.Authorization).toBe("Bearer s3cret");
    expect(calls.some(call => call.url.includes("s3cret"))).toBe(false);
  });

  it("uses the Data Center insights path under the server's base URL", async () => {
    const urls: string[] = [];
    await postCodeInsights(buildCodeInsights([finding()], "bitbucket-dc"), target, "t", async url => { urls.push(url); return ok; });
    expect(urls[0]).toBe(`https://bitbucket.example.com/rest/insights/latest/projects/acme/repos/app/commits/${SHA}/reports/0-security`);
    expect(urls[1]).toBe(`${urls[0]}/annotations`);
  });

  it("reports a refusal without leaking the token", async () => {
    const failing: FetchLike = async () => ({ ok: false, status: 403, text: async () => "denied for s3cret" });
    const error = await postCodeInsights(buildCodeInsights([finding()], "bitbucket-cloud"), target, "s3cret", failing).catch((caught: Error) => caught);
    expect((error as Error).message).toContain("403");
    expect((error as Error).message).not.toContain("s3cret");
  });
});

describe("0 findings upload --to bitbucket-*", () => {
  const deps = (env: Record<string, string>, fetcher?: FetchLike) => {
    const out = vi.fn(); const err = vi.fn();
    const value: UploadDeps = { out, err, sleep: async () => {}, readText: () => fixture("scan.json"), gh: async () => "", git: async () => `${SHA}\n`, env, ...(fetcher ? { fetch: fetcher } : {}) };
    return { value, out, err };
  };

  it("prints the payload when there is no token", async () => {
    const { value, out } = deps({});
    const result = await runBitbucketUpload("scan.json", { wait: false, to: "bitbucket-cloud" }, value);
    expect(result.published).toBe(false);
    expect(JSON.parse(out.mock.calls[0]![0])).toMatchObject({ platform: "bitbucket-cloud", annotationsEmitted: 4 });
  });

  it("posts with a token and the Pipelines environment", async () => {
    const urls: string[] = [];
    const { value } = deps({ BITBUCKET_TOKEN: "tok", BITBUCKET_WORKSPACE: "acme", BITBUCKET_REPO_SLUG: "app", BITBUCKET_COMMIT: SHA }, async url => { urls.push(url); return { ok: true, status: 200, text: async () => "" }; });
    expect(await runBitbucketUpload("scan.json", { wait: false, to: "bitbucket-cloud" }, value)).toMatchObject({ published: true, requests: 2 });
    expect(urls[0]).toContain("/repositories/acme/app/commit/");
  });

  it("asks for what Data Center needs", async () => {
    const { value } = deps({ BITBUCKET_TOKEN: "tok" });
    await expect(runBitbucketUpload("scan.json", { wait: false, to: "bitbucket-dc", repo: "PRJ/app" }, value)).rejects.toThrow("--url");
    await expect(runBitbucketUpload("scan.json", { wait: false, to: "bitbucket-dc", url: "https://b.example.com" }, value)).rejects.toThrow("--repo");
  });

  it("refuses to send the token over plaintext HTTP unless told to, and allows loopback", async () => {
    const calls: string[] = [];
    const ok: FetchLike = async url => { calls.push(url); return { ok: true, status: 200, text: async () => "" }; };
    const { value } = deps({ BITBUCKET_TOKEN: "tok" }, ok);
    const base = { wait: false, to: "bitbucket-dc", repo: "PRJ/app" };
    await expect(runBitbucketUpload("scan.json", { ...base, url: "http://bitbucket.example.com" }, value)).rejects.toThrow("plaintext HTTP");
    expect(calls).toHaveLength(0);
    await expect(runBitbucketUpload("scan.json", { ...base, url: "http://bitbucket.example.com", allowInsecureHttp: true }, value)).resolves.toMatchObject({ published: true });
    await expect(runBitbucketUpload("scan.json", { ...base, url: "http://localhost:7990" }, value)).resolves.toMatchObject({ published: true });
    await expect(runBitbucketUpload("scan.json", { ...base, url: "https://bitbucket.example.com" }, value)).resolves.toMatchObject({ published: true });
  });

  it("refuses a file that is neither scan JSON nor SARIF", async () => {
    const { value } = deps({});
    await expect(runBitbucketUpload("x", { wait: false, to: "bitbucket-cloud" }, { ...value, readText: () => "{}" })).rejects.toThrow("0security scan --format json");
  });
});
