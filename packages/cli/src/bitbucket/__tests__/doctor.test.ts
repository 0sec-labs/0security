import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { renderDoctor, remoteRepo, runDoctor, type DoctorDeps, type DoctorOptions } from "../doctor.js";
import type { Exec } from "../runner.js";
import type { Http } from "../client.js";

const TOKEN = "doctor-secret-token-1234";
const model = async () => ({ configured: true, valid: true, label: "TestAI" });
const noModel = async () => ({ configured: false, valid: false, label: "none" });

const byId = (report: Awaited<ReturnType<typeof runDoctor>>, id: string) => report.checks.find(check => check.id === id)!;

/** A scripted Http: routes by "METHOD path-suffix" and records every call. */
function scripted(routes: Record<string, number | { status: number; body?: unknown }>): { http: Http; calls: string[] } {
  const calls: string[] = [];
  const http: Http = async (url, init) => {
    const path = new URL(url).pathname + new URL(url).search;
    calls.push(`${init.method} ${path}`);
    const key = Object.keys(routes).find(route => { const [method, suffix] = route.split(" "); return method === init.method && path.includes(suffix!); });
    const hit = key ? routes[key]! : 404;
    const { status, body } = typeof hit === "number" ? { status: hit, body: undefined } : hit;
    const text = body === undefined ? "" : JSON.stringify(body);
    return { ok: status < 300, status, headers: { get: () => null }, text: async () => text };
  };
  return { http, calls };
}

const COMMIT = "c".repeat(40);
const cloudOk = {
  "GET /commits": { status: 200, body: { values: [{ hash: COMMIT }] } },
  "GET /pullrequests": { status: 200, body: { values: [] } },
  "GET /repositories/ws/app": { status: 200, body: { full_name: "ws/app" } },
  "PUT /reports/": 200,
  "DELETE /reports/": 204,
};
const base: DoctorOptions = { platform: "cloud", repo: "ws/app" };
const deps = (extra: DoctorDeps = {}): DoctorDeps => ({ env: { BITBUCKET_TOKEN: TOKEN }, modelStatus: model, suffix: () => "abcd1234", ...extra });

describe("bitbucket doctor", () => {
  it("passes every required check on a healthy Cloud repository and never prints the token", async () => {
    const { http, calls } = scripted(cloudOk);
    const report = await runDoctor(base, deps({ http }));
    expect(report.ok).toBe(true);
    expect(report.checks.filter(check => check.status === "FAIL")).toEqual([]);
    expect(byId(report, "token").detail).toBe(`set, ${TOKEN.length} chars`);
    expect(byId(report, "insights")).toMatchObject({ status: "PASS" });
    expect(byId(report, "insights").detail).toContain("0-doctor-abcd1234");
    expect(byId(report, "comment").status).toBe("SKIP");
    expect(calls.some(call => call.startsWith("PUT ") && call.includes("/reports/0-doctor-abcd1234"))).toBe(true);
    expect(calls.some(call => call.startsWith("DELETE ") && call.includes("/reports/0-doctor-abcd1234"))).toBe(true);
    expect(JSON.stringify(report) + renderDoctor(report)).not.toContain(TOKEN);
    expect(renderDoctor(report)).toContain("Next step: Everything required passed");
  });

  it("explains 401, 403 and 404 in plain words and skips what depends on them", async () => {
    for (const [status, words, next] of [[401, "wrong or expired", "new token"], [403, "not allowed", "permission"], [404, "cannot see", "--repo"]] as const) {
      const { http, calls } = scripted({ "GET /repositories/ws/app": status });
      const report = await runDoctor(base, deps({ http }));
      expect(report.ok).toBe(false);
      expect(byId(report, "repo").status).toBe("FAIL");
      expect(byId(report, "repo").detail).toContain(`HTTP ${status}`);
      expect(byId(report, "repo").detail).toContain(words);
      expect(report.next).toContain(next);
      expect(byId(report, "pulls").status).toBe("SKIP");
      expect(byId(report, "insights").status).toBe("SKIP");
      expect(calls).toHaveLength(1);
    }
  });

  it("skips the network checks and fails when the token is missing", async () => {
    const { http, calls } = scripted({});
    const report = await runDoctor(base, deps({ http, env: {} }));
    expect(byId(report, "token")).toMatchObject({ status: "FAIL", detail: "not set" });
    expect(byId(report, "repo").status).toBe("SKIP");
    expect(calls).toEqual([]);
    expect(report.next).toContain("BITBUCKET_TOKEN");
  });

  it("names the write scope when the Code Insights write is refused, and still cleans up", async () => {
    const { http, calls } = scripted({ ...cloudOk, "PUT /reports/": 403 });
    const report = await runDoctor(base, deps({ http }));
    expect(byId(report, "pulls").status).toBe("PASS");
    expect(byId(report, "insights")).toMatchObject({ status: "FAIL" });
    expect(byId(report, "insights").next).toContain("repositories: write");
    expect(report.ok).toBe(false);
    expect(calls.some(call => call.startsWith("DELETE "))).toBe(true);
  });

  it("flags a test report that could not be deleted without hiding that writing worked", async () => {
    const { http } = scripted({ ...cloudOk, "DELETE /reports/": 403 });
    const report = await runDoctor(base, deps({ http }));
    expect(byId(report, "insights").status).toBe("PASS");
    expect(byId(report, "insights").detail).toContain("could not be deleted");
  });

  it("skips the write test with --read-only and when the repository has no commit", async () => {
    const readOnly = scripted(cloudOk);
    const one = await runDoctor({ ...base, readOnly: true }, deps({ http: readOnly.http }));
    expect(byId(one, "insights").status).toBe("SKIP");
    expect(byId(one, "insights").detail).toContain("--read-only");
    expect(readOnly.calls.filter(call => !call.startsWith("GET "))).toEqual([]);
    const empty = scripted({ ...cloudOk, "GET /commits": { status: 200, body: { values: [] } } });
    const two = await runDoctor(base, deps({ http: empty.http }));
    expect(byId(two, "insights")).toMatchObject({ status: "SKIP" });
    expect(two.ok).toBe(true);
  });

  it("posts and deletes the marker comment on Data Center only when --pr is given", async () => {
    const routes = {
      "GET /projects/PRJ/repos/app/commits": { status: 200, body: { values: [{ id: COMMIT }] } },
      "GET /pull-requests?": { status: 200, body: { values: [], isLastPage: true } },
      "POST /pull-requests/5/comments": { status: 201, body: { id: 9, version: 0 } },
      "GET /pull-requests/5/activities": { status: 200, body: { isLastPage: true, values: [{ action: "COMMENTED", comment: { id: 9, version: 0, text: "0-doctor-abcd1234: x" } }] } },
      "DELETE /pull-requests/5/comments/9": 204,
      "GET /projects/PRJ/repos/app": { status: 200, body: { name: "app" } },
    };
    const dcBase = { platform: "dc" as const, repo: "PRJ/app", url: "https://bb.example.com", readOnly: true };
    const without = scripted(routes);
    expect(byId(await runDoctor(dcBase, deps({ http: without.http })), "comment").status).toBe("SKIP");
    expect(without.calls.some(call => call.startsWith("POST "))).toBe(false);
    const withPr = scripted(routes);
    const report = await runDoctor({ ...dcBase, pr: 5 }, deps({ http: withPr.http }));
    expect(byId(report, "comment")).toMatchObject({ status: "PASS" });
    expect(withPr.calls.some(call => call.startsWith("DELETE ") && call.includes("/comments/9?version=0"))).toBe(true);
    expect(report.ok).toBe(true);
  });

  it("cleans the comment up even when deleting needs a second look, and reports a refused post", async () => {
    const { http, calls } = scripted({ ...cloudOk, "POST /comments": 403, "GET /comments": { status: 200, body: { values: [] } } });
    const report = await runDoctor({ ...base, pr: 3 }, deps({ http }));
    expect(byId(report, "comment")).toMatchObject({ status: "FAIL" });
    expect(byId(report, "comment").next).toContain("pull requests: write");
    expect(calls.some(call => call.startsWith("DELETE ") && call.includes("/comments/"))).toBe(false);
  });

  it("checks the clone: origin must match and ls-remote must work, and git never gets the token", async () => {
    const dir = mkdtempSync(join(tmpdir(), "0-doctor-"));
    try {
      const { http } = scripted(cloudOk);
      const seen: Array<{ args: string[]; env: NodeJS.ProcessEnv }> = [];
      const exec = (origin: string, lsRemote: number): Exec => async (_file, args, options) => {
        seen.push({ args, env: options.env });
        const sub = args[2];
        if (sub === "rev-parse") return { stdout: "true\n", code: 0 };
        if (sub === "remote") return { stdout: `${origin}\n`, code: 0 };
        return { stdout: "", code: lsRemote };
      };
      const env = { BITBUCKET_TOKEN: TOKEN, BITBUCKET_WEBHOOK_SECRET: "x".repeat(20) };
      const ok = await runDoctor({ ...base, checkout: dir, readOnly: true }, deps({ http, env, exec: exec("git@bitbucket.org:WS/app.git", 0) }));
      expect(byId(ok, "checkout").status).toBe("PASS");
      expect(seen.length).toBe(3);
      for (const call of seen) { expect(call.env["BITBUCKET_TOKEN"]).toBeUndefined(); expect(call.env["BITBUCKET_WEBHOOK_SECRET"]).toBeUndefined(); expect(call.args.join(" ")).not.toContain(TOKEN); }
      const wrong = await runDoctor({ ...base, checkout: dir, readOnly: true }, deps({ http, exec: exec("https://bitbucket.org/ws/other.git", 0) }));
      expect(byId(wrong, "checkout")).toMatchObject({ status: "FAIL" });
      expect(byId(wrong, "checkout").detail).toContain("ws/other");
      const auth = await runDoctor({ ...base, checkout: dir, readOnly: true }, deps({ http, exec: exec("https://bitbucket.org/ws/app.git", 128) }));
      expect(byId(auth, "checkout").detail).toContain("ls-remote");
      expect(auth.ok).toBe(false);
      const missing = await runDoctor({ ...base, checkout: join(dir, "nope"), readOnly: true }, deps({ http }));
      expect(byId(missing, "checkout").detail).toContain("not a folder");
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it("runs real git in a real clone-less folder and reports it is not a repository", async () => {
    const dir = mkdtempSync(join(tmpdir(), "0-doctor-"));
    try {
      execFileSync("git", ["init", "-q", dir]);
      const { http } = scripted(cloudOk);
      const report = await runDoctor({ ...base, checkout: dir, readOnly: true }, deps({ http }));
      expect(byId(report, "checkout")).toMatchObject({ status: "FAIL" });
      expect(byId(report, "checkout").detail).toContain("origin");
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it("reads remotes of every shape", () => {
    expect(remoteRepo("https://bitbucket.org/Ws/App.git")).toBe("ws/app");
    expect(remoteRepo("git@bitbucket.org:ws/app.git")).toBe("ws/app");
    expect(remoteRepo("ssh://git@host:7999/PRJ/app.git")).toBe("prj/app");
    expect(remoteRepo("https://host/bitbucket/scm/PRJ/app.git")).toBe("prj/app");
    expect(remoteRepo("nonsense")).toBeUndefined();
  });

  it("fails the model check without a provider and passes it with one", async () => {
    const { http } = scripted(cloudOk);
    const bad = await runDoctor({ ...base, readOnly: true }, deps({ http, modelStatus: noModel }));
    expect(byId(bad, "model")).toMatchObject({ status: "FAIL" });
    expect(bad.ok).toBe(false);
    expect(byId(await runDoctor({ ...base, readOnly: true }, deps({ http })), "model").status).toBe("PASS");
  });

  it("checks the webhook secret and the listen address", async () => {
    const { http } = scripted(cloudOk);
    const run = (env: NodeJS.ProcessEnv, listen?: string) => runDoctor({ ...base, readOnly: true, listen }, deps({ http, env: { BITBUCKET_TOKEN: TOKEN, ...env } }));
    expect(byId(await run({}), "webhook-secret").status).toBe("SKIP");
    expect(byId(await run({ BITBUCKET_WEBHOOK_SECRET: "short" }), "webhook-secret").status).toBe("FAIL");
    expect(byId(await run({ BITBUCKET_WEBHOOK_SECRET: "s".repeat(16) }), "webhook-secret").status).toBe("PASS");
    expect(byId(await run({}, "127.0.0.1:7777"), "webhook-secret").status).toBe("FAIL");
    const loop = await run({ BITBUCKET_WEBHOOK_SECRET: "s".repeat(16) }, "127.0.0.1:7777");
    expect(byId(loop, "listen").detail).toContain("this machine only");
    const open = await run({ BITBUCKET_WEBHOOK_SECRET: "s".repeat(16) }, "0.0.0.0:7777");
    expect(byId(open, "listen")).toMatchObject({ status: "PASS" });
    expect(byId(open, "listen").detail).toContain("TLS proxy");
    expect(byId(await run({}, "nonsense"), "listen").status).toBe("FAIL");
  });

  it("says ZERO_ENTERPRISE refuses Bitbucket and makes no request", async () => {
    const { http, calls } = scripted(cloudOk);
    const report = await runDoctor(base, deps({ http, env: { BITBUCKET_TOKEN: TOKEN, ZERO_ENTERPRISE: "1" } }));
    expect(byId(report, "enterprise")).toMatchObject({ status: "FAIL" });
    expect(byId(report, "enterprise").detail).toContain("refused");
    expect(byId(report, "repo").status).toBe("SKIP");
    expect(calls).toEqual([]);
  });

  it("needs a Data Center URL and refuses a plain-http URL to another host", async () => {
    const dc = await runDoctor({ platform: "dc", repo: "PRJ/app" }, deps());
    expect(byId(dc, "server")).toMatchObject({ status: "FAIL" });
    expect(dc.next).toContain("--url");
    const http = await runDoctor({ platform: "dc", repo: "PRJ/app", url: "http://bitbucket.example.com" }, deps());
    expect(byId(http, "server").status).toBe("FAIL");
    expect(byId(http, "server").detail).toContain("plain HTTP");
  });
});
