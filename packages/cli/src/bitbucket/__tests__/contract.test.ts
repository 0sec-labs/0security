/**
 * Checks what this code sends and reads against the vendors' published API descriptions, kept as pinned excerpts in
 * `__fixtures__/bitbucket` (see SOURCES.md there). This proves the request shapes match the documents. It does not
 * prove a live Bitbucket accepts them.
 */
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import { buildCodeInsights, CLOUD_BATCH_SIZE, MAX_ANNOTATIONS, planRequests, type InsightFinding } from "../../code-insights.js";
import { BitbucketClient } from "../client.js";
import { parseDelivery, verifySignature, PULL_REQUEST_EVENTS } from "../events.js";
import { cloudPr, dcPr, startFakeBitbucket, type FakeBitbucket } from "./fake-bitbucket.js";

const fixture = (name: string) => JSON.parse(readFileSync(new URL(`../../__fixtures__/bitbucket/${name}`, import.meta.url), "utf8")) as Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const cloud = fixture("cloud-contract.json");
const dc = fixture("dc-contract.json");

type Schema = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

/** A small JSON-schema check: enough for type, enum, required, pattern, length and item limits, $ref and allOf. */
function check(schema: Schema, value: unknown, refs: Record<string, Schema>, path = "$"): string[] {
  // A reference the excerpt does not carry (a base type or an account object) puts no limit on the value.
  if (schema["$ref"]) { const target = refs[String(schema["$ref"]).split("/").pop()!]; return target ? check(target, value, refs, path) : []; }
  if (schema["allOf"]) return (schema["allOf"] as Schema[]).flatMap(part => check(part, value, refs, path));
  const errors: string[] = [];
  const type = schema["type"];
  if (type === "object" && !schema["properties"]) return []; // "any value", as the documents write the data item value
  if (type === "object" || (!type && schema["properties"])) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return [`${path}: expected an object`];
    for (const name of (schema["required"] ?? []) as string[]) if (!(name in (value as object))) errors.push(`${path}.${name}: required`);
    for (const [name, sub] of Object.entries((schema["properties"] ?? {}) as Record<string, Schema>)) {
      if (name in (value as object)) errors.push(...check(sub, (value as Record<string, unknown>)[name], refs, `${path}.${name}`));
    }
    return errors;
  }
  if (type === "array") {
    if (!Array.isArray(value)) return [`${path}: expected an array`];
    if (schema["maxItems"] !== undefined && value.length > schema["maxItems"]) errors.push(`${path}: more than ${schema["maxItems"]} items`);
    if (schema["minItems"] !== undefined && value.length < schema["minItems"]) errors.push(`${path}: fewer than ${schema["minItems"]} items`);
    value.forEach((item, index) => errors.push(...check(schema["items"] ?? {}, item, refs, `${path}[${index}]`)));
    return errors;
  }
  if (type === "string") {
    if (typeof value !== "string") return [`${path}: expected a string`];
    if (schema["maxLength"] !== undefined && value.length > schema["maxLength"]) errors.push(`${path}: longer than ${schema["maxLength"]}`);
    if (schema["pattern"] && !new RegExp(`^(?:${schema["pattern"]})$`).test(value)) errors.push(`${path}: ${value} does not match ${schema["pattern"]}`);
  }
  if (type === "integer" || type === "number") {
    if (typeof value !== "number") return [`${path}: expected a number`];
    if (schema["minimum"] !== undefined && value < schema["minimum"]) errors.push(`${path}: below ${schema["minimum"]}`);
  }
  if (schema["enum"] && !schema["enum"].includes(value)) errors.push(`${path}: ${String(value)} is not one of ${schema["enum"].join(", ")}`);
  return errors;
}

const finding = (over: Partial<InsightFinding> = {}): InsightFinding => ({ ruleId: "rule", severity: "high", title: "A title", path: "src/a.py", line: 3, cwe: "CWE-89", description: "text", verdict: "confirmed", rationale: "because", fix: "Suggested replacement:\nx", ...over });
const many = (count: number, severity: InsightFinding["severity"] = "low") => Array.from({ length: count }, (_, index) => finding({ severity, line: index + 1, cwe: undefined, ruleId: `rule-${index}` }));

describe("the pinned contracts", () => {
  it("describe every endpoint this code calls", () => {
    for (const [name, op] of Object.entries(cloud["methods"] as Record<string, { exists: boolean }>)) expect(op.exists, `Cloud ${name}`).toBe(true);
    for (const [name, op] of Object.entries(dc["operations"] as Record<string, { exists: boolean }>)) expect(op.exists, `Data Center ${name}`).toBe(true);
    expect(cloud["securitySchemes"]).toEqual(expect.arrayContaining(["oauth2", "basic"]));
  });
  it("name the pagination fields the client follows", () => {
    expect(Object.keys(cloud["definitions"]["paginated_pullrequests"]["properties"])).toEqual(expect.arrayContaining(["next", "values", "pagelen"]));
    expect(dc["pullRequestPage"]["pageFields"]).toEqual(expect.arrayContaining(["isLastPage", "nextPageStart", "values", "start", "limit"]));
    expect(dc["operations"]["activitiesGet"]["parameters"]).toEqual(expect.arrayContaining(["start", "limit"]));
    expect(dc["operations"]["pullRequestsGet"]["parameters"]).toEqual(expect.arrayContaining(["state", "start", "limit"]));
    expect(dc["operations"]["commentDelete"]["parameters"]).toContain("version");
  });
});

describe("Bitbucket Cloud request bodies", () => {
  const defs = cloud["definitions"] as Record<string, Schema>;
  const target = { owner: "ws", repo: "app", commit: "a".repeat(40) };

  it("make a report and annotations the published schema accepts", () => {
    const payload = buildCodeInsights([finding(), finding({ severity: "critical", line: 9, cwe: "CWE-79" }), finding({ severity: "info", line: 11, cwe: undefined, path: undefined })], "bitbucket-cloud");
    expect(check(defs["report"]!, payload.report, defs)).toEqual([]);
    const batch = payload.batches[0] as unknown[];
    expect(check(cloud["bodies"]["annotationsPost"], batch, defs)).toEqual([]);
    const [put, post] = planRequests(payload, target);
    expect(put!.url).toBe("https://api.bitbucket.org/2.0/repositories/ws/app/commit/" + "a".repeat(40) + "/reports/0-security");
    expect(post!.url).toBe(`${put!.url}/annotations`);
  });

  it("stay within 100 annotations per request, 1000 per report and 10 data items", () => {
    const payload = buildCodeInsights(many(1500), "bitbucket-cloud");
    expect(payload.emitted).toBe(MAX_ANNOTATIONS);
    expect(payload.dropped).toBe(500);
    expect(payload.batches).toHaveLength(10);
    for (const batch of payload.batches) expect(check(cloud["bodies"]["annotationsPost"], batch, defs)).toEqual([]);
    expect(CLOUD_BATCH_SIZE).toBe(cloud["bodies"]["annotationsPost"]["maxItems"]);
    expect(check(defs["report"]!, payload.report, defs)).toEqual([]);
  });

  it("send pull request comments the published schema accepts", async () => {
    const fake = await startFakeBitbucket("bitbucket-cloud");
    try {
      const client = new BitbucketClient({ platform: "bitbucket-cloud", token: fake.token, cloudApiUrl: `${fake.url}/2.0` });
      await client.addComment({ owner: "ws", repo: "app", id: 7 }, "general");
      await client.addComment({ owner: "ws", repo: "app", id: 7 }, "inline", { path: "a.py", line: 4, kind: "ADDED" });
      const bodies = fake.requests.filter(request => request.method === "POST").map(request => request.body);
      for (const body of bodies) expect(check(defs["pullrequest_comment"]!, body, defs)).toEqual([]);
      expect(bodies[1]).toMatchObject({ inline: { path: "a.py", to: 4 } });
      expect(fake.requests[0]!.headers["authorization"]).toBe(`Bearer ${fake.token}`);
    } finally { await fake.close(); }
  });
});

describe("Bitbucket Data Center request bodies", () => {
  const schemas = dc["schemas"] as Record<string, Schema>;
  const refs = { ...schemas } as Record<string, Schema>;
  const comp = (name: string) => ({ $ref: `#/components/schemas/${name}` });

  it("make a report and annotations the published schema accepts", () => {
    const payload = buildCodeInsights([finding(), finding({ severity: "critical", line: 9, cwe: "CWE-79" }), finding({ severity: "info", line: 12, cwe: undefined })], "bitbucket-dc");
    expect(check(schemas["RestSetInsightReportRequest"]!, payload.report, refs)).toEqual([]);
    for (const batch of payload.batches) expect(check(schemas["RestBulkAddInsightAnnotationRequest"]!, batch, { ...refs, RestSingleAddInsightAnnotationRequest: schemas["RestSingleAddInsightAnnotationRequest"]! })).toEqual([]);
    const severities = (payload.batches as Array<{ annotations: Array<{ severity: string }> }>).flatMap(batch => batch.annotations.map(item => item.severity));
    expect(severities).not.toContain("CRITICAL");
    const requests = planRequests(payload, { owner: "PRJ", repo: "app", commit: "a".repeat(40), baseUrl: "https://bb.example.com/ctx" });
    expect(requests[0]!.url).toBe(`https://bb.example.com/ctx/rest/insights/latest/projects/PRJ/repos/app/commits/${"a".repeat(40)}/reports/0-security`);
    expect(dc["operations"]["reportPut"]["path"]).toBe("/insights/latest/projects/{projectKey}/repos/{repositorySlug}/commits/{commitId}/reports/{key}");
  });

  it("keep a long message and a long external id inside the limits", () => {
    const payload = buildCodeInsights([finding({ description: "x".repeat(5000), rationale: "y".repeat(5000) })], "bitbucket-dc");
    for (const batch of payload.batches) expect(check(schemas["RestBulkAddInsightAnnotationRequest"]!, batch, refs)).toEqual([]);
    expect(((payload.batches[0] as { annotations: Array<{ message: string }> }).annotations[0]!.message).length).toBeLessThanOrEqual(2000);
    expect(check(schemas["RestSetInsightReportRequest"]!, buildCodeInsights(many(1200), "bitbucket-dc").report, refs)).toEqual([]);
  });

  it("send pull request comments the published schema accepts", async () => {
    const fake = await startFakeBitbucket("bitbucket-dc");
    try {
      const client = new BitbucketClient({ platform: "bitbucket-dc", token: fake.token, baseUrl: fake.url });
      await client.addComment({ owner: "PRJ", repo: "app", id: 7 }, "general");
      await client.addComment({ owner: "PRJ", repo: "app", id: 7 }, "inline", { path: "a.py", line: 4, kind: "CONTEXT" });
      const bodies = fake.requests.filter(request => request.method === "POST").map(request => request.body);
      // The published schema types anchor.path as an object (components, name, parent), the shape the server returns.
      // The request sends the path as a plain string, the form common examples use. That one field is not checked
      // against the schema, and no live server confirmed it.
      const lenient = structuredClone(schemas["RestComment"]!);
      lenient["properties"]["anchor"]["properties"]["path"] = { type: "string" };
      for (const body of bodies) expect(check(comp("RestComment"), body, { RestComment: lenient })).toEqual([]);
      expect(bodies[1]).toMatchObject({ anchor: { diffType: "EFFECTIVE", fileType: "TO", lineType: "CONTEXT", line: 4, path: "a.py" } });
    } finally { await fake.close(); }
  });

  it("read the page fields the published description gives", async () => {
    const fake: FakeBitbucket = await startFakeBitbucket("bitbucket-dc");
    try {
      fake.smallPages = true;
      fake.pullRequests.push(dcPr(1), dcPr(2));
      const client = new BitbucketClient({ platform: "bitbucket-dc", token: fake.token, baseUrl: fake.url });
      expect(await client.listOpenPullRequests("PRJ", "app")).toHaveLength(2);
      const list = fake.requests.filter(request => request.path.endsWith("/pull-requests"));
      expect(list.map(request => request.query.get("start"))).toEqual(["0", "1"]);
      expect(list[0]!.query.get("state")).toBe("OPEN");
    } finally { await fake.close(); }
  });
});

describe("webhooks", () => {
  afterEach(() => undefined);

  it("verify the signature with the vendor's published test vector", () => {
    const signature = "sha256=a4771c39fbe90f317c7824e83ddef3caae9cb3d976c214ace1f2937e133263c9";
    expect(verifySignature("It's a Secret to Everybody", "Hello World!", signature)).toBe(true);
    expect(verifySignature("It's a Secret to Everybody", "Hello World?", signature)).toBe(false);
    expect(verifySignature("another secret", "Hello World!", signature)).toBe(false);
    expect(verifySignature("It's a Secret to Everybody", "Hello World!", signature.replace("sha256=", "sha1="))).toBe(false);
    expect(verifySignature("It's a Secret to Everybody", "Hello World!", undefined)).toBe(false);
    expect(verifySignature("", "Hello World!", signature)).toBe(false);
  });

  it("read the Data Center pr:from_ref_updated sample from the documentation", () => {
    const sample = fixture("dc-pr-from-ref-updated.json");
    const parsed = parseDelivery("bitbucket-dc", "pr:from_ref_updated", sample);
    expect(parsed).toMatchObject({ ok: true, pr: { owner: "GIT", repo: "dvcs", id: 2, headSha: "aab847db240ccae221f8036605b00f777eba95d2", headBranch: "pr-webhook", baseBranch: "master", draft: false, fork: false, open: true } });
  });

  it("read the Cloud pullrequest:created shape from the documentation", () => {
    const sample = fixture("cloud-pullrequest-created.json");
    const parsed = parseDelivery("bitbucket-cloud", "pullrequest:created", sample);
    expect(parsed).toMatchObject({ ok: true, pr: { owner: "workspace", repo: "repo", id: 1, headSha: "d3022fc0ca3d", headBranch: "branch2", baseBranch: "main", fork: false, open: true } });
  });

  it("ignore other events and bad shapes, and see a fork", () => {
    expect(PULL_REQUEST_EVENTS["bitbucket-cloud"]).toContain("pullrequest:updated");
    expect(parseDelivery("bitbucket-cloud", "repo:push", fixture("cloud-pullrequest-created.json"))).toEqual({ ok: false, reason: "event_not_handled" });
    expect(parseDelivery("bitbucket-dc", "pr:opened", { pullRequest: {} })).toEqual({ ok: false, reason: "payload_shape" });
    expect(parseDelivery("bitbucket-cloud", "pullrequest:created", "text")).toEqual({ ok: false, reason: "payload_shape" });
    const fork = fixture("cloud-pullrequest-created.json");
    fork["pullrequest"]["source"]["repository"]["full_name"] = "someone/fork";
    expect(parseDelivery("bitbucket-cloud", "pullrequest:created", fork)).toMatchObject({ ok: true, pr: { fork: true } });
    const dcFork = fixture("dc-pr-from-ref-updated.json");
    dcFork["pullRequest"]["fromRef"]["repository"]["id"] = 99;
    expect(parseDelivery("bitbucket-dc", "pr:opened", dcFork)).toMatchObject({ ok: true, pr: { fork: true } });
    expect(cloudPr(1)).toBeTruthy();
  });
});
