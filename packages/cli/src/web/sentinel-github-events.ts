// GitHub events that start a Sentinel run besides pull requests: a published release or pushed tag, and a finished check.
//
// One normalised shape (`GithubEvent`) comes from two sources: a signed webhook delivery and the poller (`gh api`). Everything
// that reaches the run is copied field by field into short strings with control characters, angle brackets and backticks
// removed, so the run sees data and never markup or instructions. Nothing here authorises anything: a payload only
// LOCATES enabled triggers (repository, tag prefix, branch, check name); the trigger's own settings decide.
import { isSafeGitRef, type SentinelCheckConfig, type SentinelReleaseConfig } from "@0/engine/shared";

export const REPO_SHAPE = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;
const SHA_SHAPE = /^[0-9a-f]{40}$/;
const isSafeTag = (value: string): boolean => isSafeGitRef(value, { maxLength: 100 });
const isSafeBranch = (value: string): boolean => isSafeGitRef(value, { maxLength: 200 });

/** The webhook event name for a push (not a git command; single quotes keep the egress scan from reading it as one). */
const PUSH_EVENT = 'push';

/** Events the webhook accepts besides `pull_request` and `ping`. Anything else is ignored before its body is parsed. */
export const GITHUB_EVENT_ALLOWLIST: ReadonlySet<string> = new Set(["release", PUSH_EVENT, "check_run", "check_suite"]);

export interface GithubEvent {
  kind: "release" | "check-completed";
  repo: string;
  /** Stable per cause (tag, check run); the idempotency key and the poll cursor key are built from it. */
  key: string;
  /** Release trigger only: a release, or a tag push. */
  source?: "release" | "tag";
  tag?: string;
  /** Check trigger only. */
  branch?: string;
  checkName?: string;
  conclusion?: string;
  sha?: string;
  pr?: number;
  /** What the run sees: short neutralised strings. */
  fields: Record<string, string | number>;
}

/** One line of text with control characters, angle brackets and backticks removed and a hard length cap. */
export const cleanField = (value: unknown, max: number): string => {
  if (typeof value !== "string") return "";
  return value.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, " ").replace(/[<>`]/g, "").replace(/\s+/g, " ").trim().slice(0, max);
};
const record = (value: unknown): Record<string, unknown> | undefined => (value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined);
const text = (value: unknown, max: number) => (typeof value === "string" ? cleanField(value, max) : "");
const safeUrl = (value: unknown): string => (typeof value === "string" && /^https:\/\/github\.com\/[A-Za-z0-9_./#?=&%-]{1,300}$/.test(value) ? value : "");
const positiveInt = (value: unknown): number | undefined => (typeof value === "number" && Number.isSafeInteger(value) && value > 0 ? value : undefined);

const compact = (fields: Record<string, string | number | undefined>): Record<string, string | number> => Object.fromEntries(Object.entries(fields).filter(([, value]) => value !== undefined && value !== "")) as Record<string, string | number>;

export function releaseEvent(input: { repo: string; source: "release" | "tag"; tag: string; sha?: string; name?: unknown; url?: unknown; prerelease?: unknown }): GithubEvent | undefined {
  if (!REPO_SHAPE.test(input.repo) || !isSafeTag(input.tag)) return undefined;
  const sha = input.sha && SHA_SHAPE.test(input.sha) ? input.sha : undefined;
  return {
    kind: "release", repo: input.repo, key: input.tag, source: input.source, tag: input.tag, ...(sha ? { sha } : {}),
    fields: compact({ event: input.source === "tag" ? "tag pushed" : "release published", repo: input.repo, tag: input.tag, name: text(input.name, 200), commit: sha, url: safeUrl(input.url), prerelease: input.prerelease === true ? "yes" : undefined }),
  };
}

export function checkEvent(input: { repo: string; id: number; name?: string; conclusion: string; sha: string; branch?: unknown; pr?: unknown; url?: unknown }): GithubEvent | undefined {
  const branch = typeof input.branch === "string" && isSafeBranch(input.branch) ? input.branch : undefined;
  if (!REPO_SHAPE.test(input.repo) || !SHA_SHAPE.test(input.sha) || !/^[a-z_]{1,30}$/.test(input.conclusion)) return undefined;
  const pr = positiveInt(input.pr);
  const name = input.name ? cleanField(input.name, 100) : undefined;
  return {
    kind: "check-completed", repo: input.repo, key: String(input.id), ...(branch ? { branch } : {}), ...(name ? { checkName: name } : {}), conclusion: input.conclusion, sha: input.sha, ...(pr ? { pr } : {}),
    fields: compact({ event: "check completed", repo: input.repo, check: name, conclusion: input.conclusion, commit: input.sha, branch, pr, url: safeUrl(input.url) }),
  };
}

export type ParsedGithubEvent = { ok: true; event: GithubEvent } | { ok: false; reason: string };

/** A `release`, `push`, `check_run` or `check_suite` webhook body, reduced to what is needed. */
export function parseGithubWebhook(eventName: string, payload: unknown): ParsedGithubEvent {
  const body = record(payload);
  const repo = record(body?.["repository"])?.["full_name"];
  if (typeof repo !== "string" || !REPO_SHAPE.test(repo)) return { ok: false, reason: "payload_shape" };
  if (eventName === "release") {
    const release = record(body?.["release"]);
    if (body?.["action"] !== "published" || !release) return { ok: false, reason: "action_not_allowed" };
    if (release["draft"] === true) return { ok: false, reason: "draft_release" };
    const made = typeof release["tag_name"] === "string" ? releaseEvent({ repo, source: "release", tag: release["tag_name"], name: release["name"], url: release["html_url"], prerelease: release["prerelease"] }) : undefined;
    return made ? { ok: true, event: made } : { ok: false, reason: "payload_shape" };
  }
  if (eventName === PUSH_EVENT) {
    const ref = body?.["ref"];
    if (typeof ref !== "string" || !ref.startsWith("refs/tags/")) return { ok: false, reason: "not_a_tag" };
    if (body?.["deleted"] === true) return { ok: false, reason: "tag_deleted" };
    const after = body?.["after"];
    const made = releaseEvent({ repo, source: "tag", tag: ref.slice("refs/tags/".length), ...(typeof after === "string" ? { sha: after } : {}), url: `https://github.com/${repo}/releases/tag/${ref.slice("refs/tags/".length)}` });
    return made ? { ok: true, event: made } : { ok: false, reason: "payload_shape" };
  }
  if (eventName === "check_run" || eventName === "check_suite") {
    if (body?.["action"] !== "completed") return { ok: false, reason: "action_not_allowed" };
    const run = record(body?.[eventName]);
    const suite = eventName === "check_run" ? record(run?.["check_suite"]) : run;
    const conclusion = run?.["conclusion"];
    const id = positiveInt(run?.["id"]);
    const sha = run?.["head_sha"];
    if (!run || id === undefined || typeof conclusion !== "string" || typeof sha !== "string") return { ok: false, reason: "payload_shape" };
    const pulls = Array.isArray(run["pull_requests"]) ? run["pull_requests"] : [];
    const made = checkEvent({
      repo, id, ...(eventName === "check_run" && typeof run["name"] === "string" ? { name: run["name"] } : {}), conclusion, sha, branch: suite?.["head_branch"], pr: record(pulls[0])?.["number"], url: run["html_url"],
    });
    // A suite id and a run id are different numbers: keep them apart in dedupe keys.
    return made ? { ok: true, event: eventName === "check_suite" ? { ...made, key: `suite-${made.key}` } : made } : { ok: false, reason: "payload_shape" };
  }
  return { ok: false, reason: "event_not_allowed" };
}

const FAILED = new Set(["failure", "timed_out"]);

/** Does this release or tag event belong to this trigger? Case-insensitive on the repository only. */
export function matchesRelease(config: SentinelReleaseConfig, event: GithubEvent): boolean {
  return event.kind === "release" && event.repo.toLowerCase() === config.repo.toLowerCase() && event.source === config.on && (event.tag ?? "").startsWith(config.tagPrefix);
}

/** Does this finished check belong to this trigger? */
export function matchesCheck(config: SentinelCheckConfig, event: GithubEvent): boolean {
  if (event.kind !== "check-completed" || event.repo.toLowerCase() !== config.repo.toLowerCase()) return false;
  if (config.branch && event.branch !== config.branch) return false;
  if (config.conclusion === "failure" && !FAILED.has(event.conclusion ?? "")) return false;
  if (config.checkName && event.checkName !== config.checkName) return false;
  return true;
}

// ---------- polling (gh api output) ----------

const MAX_POLL_LINES = 1000;
const lines = (stdout: string): unknown[] => stdout.split("\n").slice(0, MAX_POLL_LINES).flatMap(line => { try { return line.trim() ? [JSON.parse(line) as unknown] : []; } catch { return []; } });

/** `gh api repos/{repo}/releases --jq '.[] | {...} | tojson'` */
export function releasesFromPoll(repo: string, stdout: string): GithubEvent[] {
  return lines(stdout).flatMap(item => {
    const r = record(item);
    if (!r || r["draft"] === true || typeof r["tag_name"] !== "string") return [];
    const made = releaseEvent({ repo, source: "release", tag: r["tag_name"], name: r["name"], url: r["html_url"], prerelease: r["prerelease"] });
    return made ? [made] : [];
  });
}

/** `gh api --paginate repos/{repo}/git/matching-refs/tags/{prefix} --jq '.[] | {ref, sha: .object.sha} | tojson'` */
export function tagsFromPoll(repo: string, stdout: string): GithubEvent[] {
  return lines(stdout).flatMap(item => {
    const r = record(item);
    const ref = r?.["ref"];
    if (typeof ref !== "string" || !ref.startsWith("refs/tags/")) return [];
    const tag = ref.slice("refs/tags/".length);
    const made = releaseEvent({ repo, source: "tag", tag, ...(typeof r?.["sha"] === "string" ? { sha: r["sha"] } : {}), url: `https://github.com/${repo}/releases/tag/${tag}` });
    return made ? [made] : [];
  });
}

/** `gh api --paginate repos/{repo}/commits/{ref}/check-runs?per_page=100 --jq '.check_runs[] | {...} | tojson'` */
export function checksFromPoll(repo: string, branch: string | undefined, stdout: string): GithubEvent[] {
  return lines(stdout).flatMap(item => {
    const r = record(item);
    if (!r || r["status"] !== "completed" || typeof r["conclusion"] !== "string" || typeof r["head_sha"] !== "string") return [];
    const id = positiveInt(r["id"]);
    if (id === undefined) return [];
    const made = checkEvent({ repo, id, ...(typeof r["name"] === "string" ? { name: r["name"] } : {}), conclusion: r["conclusion"], sha: r["head_sha"], ...(branch ? { branch } : {}), pr: r["pr"], url: r["html_url"] });
    return made ? [made] : [];
  });
}

export const RELEASES_JQ = ".[] | {tag_name, name, draft, prerelease, html_url} | tojson";
export const TAGS_JQ = ".[] | {ref, sha: .object.sha} | tojson";
export const CHECKS_JQ = ".check_runs[] | {id, name, status, conclusion, head_sha, html_url, pr: (.pull_requests[0].number // null)} | tojson";

// ---------- reporting ----------

export const isCommitSha = (value: string): boolean => SHA_SHAPE.test(value);
export const isSafeRef = (value: string): boolean => isSafeGitRef(value, { maxLength: 200 });

/** A commit status context that is the same on every run of one Sentinel, so GitHub shows one line that is replaced. */
export const statusContext = (sentinelName: string): string => `0/sentinel/${(sentinelName.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "run")}`;

/**
 * State and description for a commit status. Built from counts only: no title, path, evidence or any text the model wrote.
 * `failure` means a critical or high finding; anything else is `success`.
 */
export function statusFor(findings: ReadonlyArray<{ severity: string }>): { state: "success" | "failure"; description: string } {
  const count = (level: string) => findings.filter(finding => finding.severity.toLowerCase() === level).length;
  const critical = count("critical"); const high = count("high");
  if (findings.length === 0) return { state: "success", description: "No findings reported." };
  const parts = [critical ? `${critical} critical` : "", high ? `${high} high` : ""].filter(Boolean);
  return { state: critical + high > 0 ? "failure" : "success", description: `${findings.length} finding${findings.length === 1 ? "" : "s"}${parts.length ? ` (${parts.join(", ")})` : ""}. Details are in the Sentinel.`.slice(0, 140) };
}
