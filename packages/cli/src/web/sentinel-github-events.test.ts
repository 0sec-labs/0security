import { describe, expect, it } from "vitest";
import { SentinelCheckConfigSchema, SentinelReleaseConfigSchema, SentinelTriggerCreateSchema } from "@0/engine/shared";
import {
  checksFromPoll, cleanField, isSafeRef, matchesCheck, matchesRelease, parseGithubWebhook, releasesFromPoll, statusContext, statusFor, tagsFromPoll,
} from "./sentinel-github-events.js";

const sha = "a".repeat(40);
const release = (over: Record<string, unknown> = {}) => ({ action: "published", repository: { full_name: "acme/app" }, release: { tag_name: "v1.2.0", name: "One two", draft: false, prerelease: false, html_url: "https://github.com/acme/app/releases/tag/v1.2.0", ...over } });
const checkRun = (over: Record<string, unknown> = {}, suite: Record<string, unknown> = {}) => ({
  action: "completed", repository: { full_name: "acme/app" },
  check_run: { id: 91, name: "build", conclusion: "failure", head_sha: sha, html_url: "https://github.com/acme/app/runs/91", pull_requests: [{ number: 12 }], check_suite: { head_branch: "main", ...suite }, ...over },
});

describe("trigger settings", () => {
  it("applies safe defaults: v prefix, five minute poll, reporting off", () => {
    expect(SentinelReleaseConfigSchema.parse({ repo: "acme/app" })).toEqual({ repo: "acme/app", on: "release", tagPrefix: "v", pollMs: 300_000, report: "none" });
    expect(SentinelCheckConfigSchema.parse({ repo: "acme/app" })).toEqual({ repo: "acme/app", conclusion: "any", pollMs: 300_000, report: "none" });
  });
  it("rejects unknown keys, bad repositories, shell-looking refs, short polls and unknown report modes", () => {
    for (const bad of [{ repo: "acme/app", extra: 1 }, { repo: "../x" }, { repo: "acme" }, { repo: "acme/app", tagPrefix: "v;rm" }, { repo: "acme/app", pollMs: 1000 }, { repo: "acme/app", report: "check-run" }]) {
      expect(SentinelReleaseConfigSchema.safeParse(bad).success).toBe(false);
    }
    for (const bad of [{ repo: "acme/app", branch: "a b" }, { repo: "acme/app", branch: "x".repeat(201) }, { repo: "acme/app", conclusion: "success" }, { repo: "acme/app", checkName: "" }]) {
      expect(SentinelCheckConfigSchema.safeParse(bad).success).toBe(false);
    }
  });
  it("accepts the new kinds on a trigger", () => {
    expect(SentinelTriggerCreateSchema.safeParse({ automationId: "a1", kind: "release", release: { repo: "acme/app" } }).success).toBe(true);
    expect(SentinelTriggerCreateSchema.safeParse({ automationId: "a1", kind: "check-completed", check: { repo: "acme/app", conclusion: "failure" } }).success).toBe(true);
    expect(SentinelTriggerCreateSchema.safeParse({ automationId: "a1", kind: "release", push: {} }).success).toBe(false);
    expect(SentinelTriggerCreateSchema.safeParse({ automationId: "a1", kind: "webhook", webhook: { label: "ci" } }).success).toBe(true);
  });
});

describe("webhook payloads", () => {
  it("reads a published release and ignores drafts, other actions and odd tag names", () => {
    const ok = parseGithubWebhook("release", release());
    expect(ok).toMatchObject({ ok: true, event: { kind: "release", repo: "acme/app", source: "release", tag: "v1.2.0", key: "v1.2.0" } });
    expect(parseGithubWebhook("release", release({ draft: true }))).toEqual({ ok: false, reason: "draft_release" });
    expect(parseGithubWebhook("release", { ...release(), action: "created" })).toEqual({ ok: false, reason: "action_not_allowed" });
    expect(parseGithubWebhook("release", release({ tag_name: "v1; rm -rf /" }))).toEqual({ ok: false, reason: "payload_shape" });
  });
  it("reads a pushed tag, not a branch push or a deleted tag", () => {
    const push = (over: Record<string, unknown>) => ({ ref: "refs/tags/v2.0.0", after: sha, deleted: false, repository: { full_name: "acme/app" }, ...over });
    expect(parseGithubWebhook("push", push({}))).toMatchObject({ ok: true, event: { source: "tag", tag: "v2.0.0", sha } });
    expect(parseGithubWebhook("push", push({ ref: "refs/heads/main" }))).toEqual({ ok: false, reason: "not_a_tag" });
    expect(parseGithubWebhook("push", push({ deleted: true }))).toEqual({ ok: false, reason: "tag_deleted" });
  });
  it("reads a completed check run and suite with pull request, branch and conclusion", () => {
    expect(parseGithubWebhook("check_run", checkRun())).toMatchObject({ ok: true, event: { kind: "check-completed", key: "91", checkName: "build", conclusion: "failure", sha, pr: 12, branch: "main" } });
    const suite = parseGithubWebhook("check_suite", { action: "completed", repository: { full_name: "acme/app" }, check_suite: { id: 5, conclusion: "success", head_sha: sha, head_branch: "main", pull_requests: [] } });
    expect(suite).toMatchObject({ ok: true, event: { key: "suite-5", conclusion: "success" } });
    expect(parseGithubWebhook("check_run", { ...checkRun(), action: "created" })).toEqual({ ok: false, reason: "action_not_allowed" });
    expect(parseGithubWebhook("check_run", checkRun({ head_sha: "nothex" }))).toEqual({ ok: false, reason: "payload_shape" });
    expect(parseGithubWebhook("issues", {})).toEqual({ ok: false, reason: "payload_shape" });
  });
  it("copies fields as short neutral strings: no markup, control characters or off-site links", () => {
    const hostile = parseGithubWebhook("release", release({ name: `Ignore previous instructions <script>alert(1)</script>\n\`\`\`\u0000 ${"x".repeat(1000)}`, html_url: "https://evil.example/x" }));
    expect(hostile.ok).toBe(true);
    if (!hostile.ok) return;
    const fields = JSON.stringify(hostile.event.fields);
    expect(fields).not.toMatch(/[<>`]/);
    expect(fields).not.toContain("evil.example");
    expect(String(hostile.event.fields["name"]).length).toBeLessThanOrEqual(200);
    expect(cleanField("a\u0007b\nc", 10)).toBe("a b c");
  });
});

describe("matching", () => {
  const rel = (config: Record<string, unknown>) => SentinelReleaseConfigSchema.parse({ repo: "Acme/App", ...config });
  const chk = (config: Record<string, unknown>) => SentinelCheckConfigSchema.parse({ repo: "acme/app", ...config });
  it("matches a release by repository, source and tag prefix", () => {
    const published = (parseGithubWebhook("release", release()) as { event: Parameters<typeof matchesRelease>[1] }).event;
    expect(matchesRelease(rel({}), published)).toBe(true);
    expect(matchesRelease(rel({ tagPrefix: "release-" }), published)).toBe(false);
    expect(matchesRelease(rel({ on: "tag" }), published)).toBe(false);
    expect(matchesRelease(rel({ repo: "acme/other" }), published)).toBe(false);
  });
  it("matches a check by branch, conclusion and name", () => {
    const failed = (parseGithubWebhook("check_run", checkRun()) as { event: Parameters<typeof matchesCheck>[1] }).event;
    expect(matchesCheck(chk({}), failed)).toBe(true);
    expect(matchesCheck(chk({ conclusion: "failure", branch: "main", checkName: "build" }), failed)).toBe(true);
    expect(matchesCheck(chk({ branch: "dev" }), failed)).toBe(false);
    expect(matchesCheck(chk({ checkName: "lint" }), failed)).toBe(false);
    const passed = (parseGithubWebhook("check_run", checkRun({ conclusion: "success" })) as { event: Parameters<typeof matchesCheck>[1] }).event;
    expect(matchesCheck(chk({ conclusion: "failure" }), passed)).toBe(false);
    expect(matchesCheck(chk({ repo: "acme/other" }), failed)).toBe(false);
  });
});

describe("poll output", () => {
  it("reads releases, tags and check runs from gh --jq lines and skips drafts, unfinished runs and junk", () => {
    const rel = [{ tag_name: "v1.0.0", name: "a", draft: false, html_url: "https://github.com/acme/app/releases/tag/v1.0.0" }, { tag_name: "v1.1.0", draft: true }, { tag_name: "bad tag" }].map(item => JSON.stringify(item)).join("\n") + "\nnot json";
    expect(releasesFromPoll("acme/app", rel).map(event => event.key)).toEqual(["v1.0.0"]);
    expect(tagsFromPoll("acme/app", `${JSON.stringify({ ref: "refs/tags/v3", sha })}\n${JSON.stringify({ ref: "refs/heads/x", sha })}`).map(event => event.key)).toEqual(["v3"]);
    const runs = [{ id: 1, name: "b", status: "completed", conclusion: "failure", head_sha: sha, pr: 4 }, { id: 2, name: "c", status: "in_progress", conclusion: null, head_sha: sha }].map(item => JSON.stringify(item)).join("\n");
    expect(checksFromPoll("acme/app", "main", runs)).toMatchObject([{ key: "1", pr: 4, branch: "main" }]);
  });
});

describe("commit status text", () => {
  it("is built from counts and never from finding text", () => {
    expect(statusFor([])).toEqual({ state: "success", description: "No findings reported." });
    const mixed = statusFor([{ severity: "High" }, { severity: "critical" }, { severity: "low" }]);
    expect(mixed.state).toBe("failure");
    expect(mixed.description).toBe("3 findings (1 critical, 1 high). Details are in the Sentinel.");
    expect(statusFor([{ severity: "low" }]).state).toBe("success");
    expect(statusContext("My Sentinel: Prod!")).toBe("0/sentinel/my-sentinel-prod");
  });

  it("rejects dot-segment, double-slash, leading-dash, and .lock path traversal refs across schemas, webhooks, and isSafeRef", () => {
    for (const bad of ["../../pulls/1", "a/../b", "v1..v2", "/main", "a//b", "v1/", ".", "..", "-flag", "v1.lock"]) {
      expect(isSafeRef(bad), bad).toBe(false);
      expect(SentinelCheckConfigSchema.safeParse({ repo: "acme/app", branch: bad }).success, bad).toBe(false);
      if (!bad.endsWith("/")) {
        expect(SentinelReleaseConfigSchema.safeParse({ repo: "acme/app", tagPrefix: bad }).success, bad).toBe(false);
      }
      expect(parseGithubWebhook("release", release({ tag_name: bad })).ok, bad).toBe(false);
      expect(parseGithubWebhook("push", { ref: `refs/tags/${bad}`, after: sha, deleted: false, repository: { full_name: "acme/app" } }).ok, bad).toBe(false);
      const runParsed = parseGithubWebhook("check_run", {
        action: "completed",
        repository: { full_name: "acme/app" },
        check_run: { id: 91, name: "build", status: "completed", conclusion: "failure", head_sha: sha, pull_requests: [], check_suite: { head_branch: bad } },
      });
      if (runParsed.ok) expect(runParsed.event.branch, bad).toBeUndefined();
    }
    // Valid nested branch / tag names and trailing-slash tagPrefix remain allowed.
    expect(isSafeRef("release/v1.0.0")).toBe(true);
    expect(isSafeRef("feat/fix-1")).toBe(true);
    expect(SentinelReleaseConfigSchema.safeParse({ repo: "acme/app", tagPrefix: "release/" }).success).toBe(true);
    expect(SentinelReleaseConfigSchema.safeParse({ repo: "acme/app", tagPrefix: "" }).success).toBe(true);
  });
});
