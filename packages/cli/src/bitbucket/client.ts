/**
 * A small client for the parts of the Bitbucket Cloud and Data Center REST APIs the pull request review needs: list open
 * pull requests, read a diff, and read and write pull request comments. Code Insights go through `code-insights.ts`.
 *
 * Contracts used (pinned excerpts are in `__fixtures__/bitbucket`):
 * - Cloud, https://api.bitbucket.org/swagger.json: `GET /repositories/{workspace}/{repo}/pullrequests?state=OPEN`
 *   (paginated with `next`), `GET .../pullrequests/{id}/diff` (302 to the repository diff), comments at
 *   `.../pullrequests/{id}/comments` (`{content:{raw}, inline:{path,to}}`).
 * - Data Center 9.6, https://dac-static.atlassian.com/server/bitbucket/9.6.swagger.v3.json:
 *   `GET /rest/api/latest/projects/{key}/repos/{slug}/pull-requests?state=OPEN` (paginated with `isLastPage` and
 *   `nextPageStart`), `.../pull-requests/{id}.diff`, comments at `.../comments` (`{text, anchor}`) and, for reading
 *   them, `.../activities` (the comments endpoint needs a file path).
 *
 * Every request carries the token as a bearer token, goes through `assertEgressAllowed`, and never follows a redirect
 * to another origin. The token never appears in an error message.
 */
import { assertEgressAllowed } from "@0/engine";
import { postCodeInsights, type CodeInsightsPayload, type CodeInsightsPlatform } from "../code-insights.js";

export type Platform = CodeInsightsPlatform;

export interface HttpInit { method: string; headers: Record<string, string>; body?: string; redirect: "manual"; signal?: AbortSignal }
export type Http = (url: string, init: HttpInit) => Promise<{ ok: boolean; status: number; headers: { get(name: string): string | null }; text(): Promise<string> }>;

export interface PullRequest {
  platform: Platform;
  /** Cloud: workspace. Data Center: project key. */
  owner: string;
  repo: string;
  id: number;
  title: string;
  draft: boolean;
  fork: boolean;
  open: boolean;
  /** Cloud may give an abbreviated hash; Data Center gives all 40 characters. */
  headSha: string;
  headBranch: string;
  baseBranch: string;
}

export interface PullRequestComment { id: string; text: string; version?: number }

export interface ClientOptions {
  platform: Platform;
  token: string;
  /** Data Center server, for example https://bitbucket.example.com (a context path is kept). */
  baseUrl?: string;
  /** Cloud API root; default https://api.bitbucket.org/2.0. */
  cloudApiUrl?: string;
  http?: Http;
  allowInsecureHttp?: boolean;
  timeoutMs?: number;
}

export const MAX_DIFF_BYTES = 8 * 1024 * 1024;
const MAX_PULL_REQUESTS = 1000;
const MAX_COMMENT_PAGES = 20;
const PAGE = 50;
const SLUG = /^[A-Za-z0-9._~-]{1,200}$/;

export class BitbucketError extends Error {
  constructor(message: string, readonly status?: number) { super(message); }
}

const isRecord = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);
const text = (value: unknown): string => (typeof value === "string" ? value : "");
const num = (value: unknown): number | undefined => (typeof value === "number" && Number.isSafeInteger(value) ? value : undefined);
const part = encodeURIComponent;

/** Refuse a server URL that would send the token over plain HTTP to another machine. */
export function checkServerUrl(url: string, allowInsecureHttp: boolean): URL {
  let parsed: URL;
  try { parsed = new URL(url); } catch { throw new BitbucketError("The Bitbucket URL is not valid."); }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") throw new BitbucketError("The Bitbucket URL must start with https://.");
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
  if (parsed.protocol === "http:" && !loopback && !allowInsecureHttp) throw new BitbucketError("Refusing to send the Bitbucket token over plain HTTP. Use an https:// URL, or pass --allow-insecure-http on a network you trust.");
  if (parsed.username || parsed.password) throw new BitbucketError("Put no credentials in the Bitbucket URL.");
  return parsed;
}

export class BitbucketClient {
  readonly platform: Platform;
  readonly #token: string;
  readonly #root: string;
  readonly #origin: string;
  readonly #http: Http;
  readonly #timeout: number;
  readonly #baseUrl: string | undefined;
  readonly #cloudApiUrl: string | undefined;

  constructor(options: ClientOptions) {
    this.platform = options.platform;
    this.#token = options.token;
    if (options.platform === "bitbucket-dc" && !options.baseUrl) throw new BitbucketError("Data Center needs the server's base URL (--url or BITBUCKET_URL).");
    const root = options.platform === "bitbucket-cloud" ? options.cloudApiUrl ?? "https://api.bitbucket.org/2.0" : `${options.baseUrl!.replace(/\/+$/, "")}/rest/api/latest`;
    const parsed = checkServerUrl(root, options.allowInsecureHttp === true);
    this.#root = root.replace(/\/+$/, "");
    this.#origin = parsed.origin;
    this.#http = options.http ?? ((url, init) => fetch(url, init));
    this.#timeout = options.timeoutMs ?? 30_000;
    this.#baseUrl = options.baseUrl;
    this.#cloudApiUrl = options.cloudApiUrl;
  }

  #clean(message: string): string { return message.split(this.#token).join("***"); }

  async #send(method: string, url: string, body?: unknown, redirects = 0): Promise<{ status: number; body: string }> {
    if (new URL(url).origin !== this.#origin) throw new BitbucketError("Refusing to send the token to a different host than the Bitbucket server.");
    assertEgressAllowed("Bitbucket");
    let response;
    try {
      response = await this.#http(url, {
        method, redirect: "manual", signal: AbortSignal.timeout(this.#timeout),
        headers: { Authorization: `Bearer ${this.#token}`, Accept: "application/json", ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
    } catch (error) {
      throw new BitbucketError(this.#clean(`${method} ${new URL(url).pathname} failed: ${error instanceof Error ? error.message : String(error)}`));
    }
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      if (!location || redirects >= 3) throw new BitbucketError(`Bitbucket redirected ${method} ${new URL(url).pathname} too many times.`, response.status);
      return this.#send(method, new URL(location, url).toString(), body, redirects + 1);
    }
    const raw = await response.text().catch(() => "");
    if (!response.ok) throw new BitbucketError(this.#clean(`Bitbucket answered ${response.status} to ${method} ${new URL(url).pathname}: ${raw.replace(/\s+/g, " ").slice(0, 300)}`), response.status);
    return { status: response.status, body: raw };
  }

  async #json(method: string, url: string, body?: unknown): Promise<Record<string, unknown>> {
    const { body: raw } = await this.#send(method, url, body);
    if (!raw.trim()) return {};
    try {
      const parsed: unknown = JSON.parse(raw);
      return isRecord(parsed) ? parsed : {};
    } catch { throw new BitbucketError(`Bitbucket sent an answer that is not JSON for ${method} ${new URL(url).pathname}.`); }
  }

  #repoPath(owner: string, repo: string): string {
    if (!SLUG.test(owner) || !SLUG.test(repo)) throw new BitbucketError("The repository name has characters Bitbucket does not allow.");
    return this.platform === "bitbucket-cloud" ? `${this.#root}/repositories/${part(owner)}/${part(repo)}` : `${this.#root}/projects/${part(owner)}/repos/${part(repo)}`;
  }
  #prPath(pr: Pick<PullRequest, "owner" | "repo" | "id">): string {
    return `${this.#repoPath(pr.owner, pr.repo)}/${this.platform === "bitbucket-cloud" ? "pullrequests" : "pull-requests"}/${pr.id}`;
  }

  async getPullRequest(owner: string, repo: string, id: number): Promise<PullRequest | undefined> {
    if (!Number.isSafeInteger(id) || id < 1) throw new BitbucketError("The pull request number must be a positive integer.");
    const raw = await this.#json("GET", this.#prPath({ owner, repo, id }));
    return this.platform === "bitbucket-cloud" ? cloudPullRequest(raw, owner, repo) : dcPullRequest(raw, owner, repo);
  }

  /** Publish a Code Insights report for a commit (all 40 characters of its hash). */
  async publishInsights(payload: CodeInsightsPayload, target: { owner: string; repo: string; commit: string }): Promise<void> {
    this.#repoPath(target.owner, target.repo);
    const fetcher: Parameters<typeof postCodeInsights>[3] = (url, init) => {
      if (new URL(url).origin !== this.#origin) throw new BitbucketError("Refusing to send the token to a different host than the Bitbucket server.");
      assertEgressAllowed("Bitbucket");
      return this.#http(url, { ...init, signal: AbortSignal.timeout(this.#timeout) });
    };
    await postCodeInsights(payload, { ...target, ...(this.#baseUrl ? { baseUrl: this.#baseUrl } : {}), ...(this.#cloudApiUrl ? { cloudApiUrl: this.#cloudApiUrl } : {}) }, this.#token, fetcher);
  }

  /** Open pull requests of one repository, at most 1000. */
  async listOpenPullRequests(owner: string, repo: string): Promise<PullRequest[]> {
    const found: PullRequest[] = [];
    if (this.platform === "bitbucket-cloud") {
      let url: string | undefined = `${this.#repoPath(owner, repo)}/pullrequests?state=OPEN&pagelen=${PAGE}`;
      while (url && found.length < MAX_PULL_REQUESTS) {
        const page = await this.#json("GET", url);
        for (const raw of Array.isArray(page["values"]) ? page["values"] : []) {
          const pr = cloudPullRequest(raw, owner, repo);
          if (pr) found.push(pr);
        }
        url = text(page["next"]) || undefined;
      }
    } else {
      let start = 0;
      for (;;) {
        const page = await this.#json("GET", `${this.#repoPath(owner, repo)}/pull-requests?state=OPEN&limit=${PAGE}&start=${start}`);
        for (const raw of Array.isArray(page["values"]) ? page["values"] : []) {
          const pr = dcPullRequest(raw, owner, repo);
          if (pr) found.push(pr);
        }
        const next = num(page["nextPageStart"]);
        if (page["isLastPage"] !== false || next === undefined || found.length >= MAX_PULL_REQUESTS) break;
        start = next;
      }
    }
    return found.slice(0, MAX_PULL_REQUESTS);
  }

  /** The pull request's diff as text; `truncated` when it is over the size cap. */
  async diff(pr: Pick<PullRequest, "owner" | "repo" | "id">): Promise<{ text: string; truncated: boolean }> {
    const url = this.platform === "bitbucket-cloud" ? `${this.#prPath(pr)}/diff` : `${this.#repoPath(pr.owner, pr.repo)}/pull-requests/${pr.id}.diff`;
    const { body } = await this.#send("GET", url);
    return Buffer.byteLength(body) > MAX_DIFF_BYTES ? { text: body.slice(0, MAX_DIFF_BYTES), truncated: true } : { text: body, truncated: false };
  }

  /** Comments whose text contains `needle`. Replies are not read. */
  async findComments(pr: Pick<PullRequest, "owner" | "repo" | "id">, needle: string): Promise<PullRequestComment[]> {
    const found: PullRequestComment[] = [];
    if (this.platform === "bitbucket-cloud") {
      let url: string | undefined = `${this.#prPath(pr)}/comments?pagelen=100`;
      for (let pages = 0; url && pages < MAX_COMMENT_PAGES; pages++) {
        const page = await this.#json("GET", url);
        for (const raw of Array.isArray(page["values"]) ? page["values"] : []) {
          if (!isRecord(raw) || raw["deleted"] === true) continue;
          const body = isRecord(raw["content"]) ? text(raw["content"]["raw"]) : "";
          const id = num(raw["id"]);
          if (id !== undefined && body.includes(needle)) found.push({ id: String(id), text: body });
        }
        url = text(page["next"]) || undefined;
      }
      return found;
    }
    let start = 0;
    for (let pages = 0; pages < MAX_COMMENT_PAGES; pages++) {
      const page = await this.#json("GET", `${this.#prPath(pr)}/activities?limit=100&start=${start}`);
      for (const raw of Array.isArray(page["values"]) ? page["values"] : []) {
        const comment = isRecord(raw) && raw["action"] === "COMMENTED" && isRecord(raw["comment"]) ? raw["comment"] : undefined;
        const id = num(comment?.["id"]);
        const body = text(comment?.["text"]);
        if (comment && id !== undefined && body.includes(needle)) { const version = num(comment["version"]); found.push({ id: String(id), text: body, ...(version !== undefined ? { version } : {}) }); }
      }
      const next = num(page["nextPageStart"]);
      if (page["isLastPage"] !== false || next === undefined) break;
      start = next;
    }
    return found;
  }

  /** A comment on the pull request, or on a line of the new file when `inline` is given. */
  async addComment(pr: Pick<PullRequest, "owner" | "repo" | "id">, body: string, inline?: { path: string; line: number; kind: "ADDED" | "CONTEXT" }): Promise<void> {
    const url = `${this.#prPath(pr)}/comments`;
    if (this.platform === "bitbucket-cloud") await this.#json("POST", url, { content: { raw: body }, ...(inline ? { inline: { path: inline.path, to: inline.line } } : {}) });
    else await this.#json("POST", url, { text: body, ...(inline ? { anchor: { diffType: "EFFECTIVE", fileType: "TO", path: inline.path, line: inline.line, lineType: inline.kind } } : {}) });
  }

  async updateComment(pr: Pick<PullRequest, "owner" | "repo" | "id">, comment: PullRequestComment, body: string): Promise<void> {
    const url = `${this.#prPath(pr)}/comments/${part(comment.id)}`;
    if (this.platform === "bitbucket-cloud") await this.#json("PUT", url, { content: { raw: body } });
    else await this.#json("PUT", url, { text: body, version: comment.version ?? 0 });
  }

  async deleteComment(pr: Pick<PullRequest, "owner" | "repo" | "id">, comment: PullRequestComment): Promise<void> {
    const url = `${this.#prPath(pr)}/comments/${part(comment.id)}${this.platform === "bitbucket-dc" ? `?version=${comment.version ?? 0}` : ""}`;
    await this.#send("DELETE", url);
  }
}

/** A Cloud pull request object (API or webhook), reduced to what the review needs. */
export function cloudPullRequest(raw: unknown, owner: string, repo: string): PullRequest | undefined {
  if (!isRecord(raw)) return undefined;
  const id = num(raw["id"]);
  const source = isRecord(raw["source"]) ? raw["source"] : {};
  const destination = isRecord(raw["destination"]) ? raw["destination"] : {};
  const headSha = isRecord(source["commit"]) ? text(source["commit"]["hash"]) : "";
  const headBranch = isRecord(source["branch"]) ? text(source["branch"]["name"]) : "";
  const baseBranch = isRecord(destination["branch"]) ? text(destination["branch"]["name"]) : "";
  const from = isRecord(source["repository"]) ? text(source["repository"]["full_name"]) : "";
  const to = isRecord(destination["repository"]) ? text(destination["repository"]["full_name"]) : "";
  if (id === undefined || id < 1 || !/^[0-9a-f]{7,40}$/.test(headSha) || !headBranch || !baseBranch) return undefined;
  return {
    platform: "bitbucket-cloud", owner, repo, id, title: text(raw["title"]).slice(0, 300), draft: raw["draft"] === true,
    // A pull request without a source repository (deleted fork) counts as a fork.
    fork: !from || (!!to && from.toLowerCase() !== to.toLowerCase()), open: raw["state"] === "OPEN", headSha, headBranch, baseBranch,
  };
}

/** A Data Center pull request object (API or webhook). */
export function dcPullRequest(raw: unknown, owner: string, repo: string): PullRequest | undefined {
  if (!isRecord(raw)) return undefined;
  const id = num(raw["id"]);
  const from = isRecord(raw["fromRef"]) ? raw["fromRef"] : {};
  const to = isRecord(raw["toRef"]) ? raw["toRef"] : {};
  const headSha = text(from["latestCommit"]);
  const headBranch = text(from["displayId"]);
  const baseBranch = text(to["displayId"]);
  if (id === undefined || id < 1 || !/^[0-9a-f]{40}$/.test(headSha) || !headBranch || !baseBranch) return undefined;
  const fromRepo = isRecord(from["repository"]) ? num(from["repository"]["id"]) : undefined;
  const toRepo = isRecord(to["repository"]) ? num(to["repository"]["id"]) : undefined;
  return {
    platform: "bitbucket-dc", owner, repo, id, title: text(raw["title"]).slice(0, 300), draft: raw["draft"] === true,
    fork: fromRepo === undefined || toRepo === undefined || fromRepo !== toRepo, open: raw["state"] === "OPEN", headSha, headBranch, baseBranch,
  };
}
