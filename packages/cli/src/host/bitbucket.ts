/** Bitbucket fix PRs: REST requests follow Atlassian Cloud and Data Center 9.6 OpenAPI.
 * https://api.bitbucket.org/swagger.json
 * https://dac-static.atlassian.com/server/bitbucket/9.6.swagger.v3.json
 * Git uses the operator's existing credentials; the API token never enters git arguments.
 */
import { readFileSync } from "node:fs";
import { isSafeGitRef } from "@0/engine/shared";
import { checkServerUrl, assertBitbucketDestination } from "../bitbucket/client.js";
import type { Host, IssueTracker, PullRequest, PullRequestState } from "./index.js";

export interface BitbucketHostOptions {
  platform: "bitbucket-cloud" | "bitbucket-dc";
  owner: string; repo: string; token: string;
  baseUrl?: string;
  git: (args: string[]) => Promise<string>;
  fetch?: typeof fetch;
}
type Json = Record<string, any>;
const slug = /^(?!\.{1,2}$)[A-Za-z0-9._~-]{1,200}$/;
const id = (value: number): number => { if (!Number.isSafeInteger(value) || value < 1) throw new Error("Invalid pull request number."); return value; };
const unsupported = (): never => { throw new Error("This operation is not supported by the Bitbucket fix host."); };
const branch = (value: string): string => { if (!isSafeGitRef(value) || value.startsWith("refs/")) throw new Error("Invalid branch name."); return value; };

export class BitbucketHost implements Host {
  readonly name: string;
  private readonly root: string;
  private readonly web: string;
  private readonly request: typeof fetch;
  constructor(private readonly options: BitbucketHostOptions) {
    this.name = options.platform;
    if (!slug.test(options.owner) || !slug.test(options.repo)) throw new Error("Invalid Bitbucket repository.");
    if (!options.token.trim() || /[\r\n]/.test(options.token)) throw new Error("Set BITBUCKET_TOKEN to a Bitbucket access token with pull request write permission.");
    const base = options.platform === "bitbucket-cloud" ? "https://bitbucket.org" : options.baseUrl;
    if (!base) throw new Error("Bitbucket Data Center needs --bitbucket-url or BITBUCKET_URL.");
    const parsed = checkServerUrl(base, false);
    if (parsed.search || parsed.hash) throw new Error("The Bitbucket server URL must have no query or fragment.");
    this.web = base.replace(/\/+$/, "");
    const repoPath = `${encodeURIComponent(options.owner)}/${encodeURIComponent(options.repo)}`;
    this.root = options.platform === "bitbucket-cloud" ? `https://api.bitbucket.org/2.0/repositories/${repoPath}` : `${this.web}/rest/api/latest/projects/${encodeURIComponent(options.owner)}/repos/${encodeURIComponent(options.repo)}`;
    this.request = options.fetch ?? fetch;
  }
  isValidRepo(value: string): boolean { const parts = value.split("/"); return parts.length === 2 && parts.every(part => slug.test(part)); }
  async currentRepo(): Promise<string> { return `${this.options.owner}/${this.options.repo}`; }
  private prPath(number?: number): string { return `${this.options.platform === "bitbucket-cloud" ? "pullrequests" : "pull-requests"}${number === undefined ? "" : `/${id(number)}`}`; }
  private async json(method: string, path: string, body?: Json): Promise<Json> {
    const url = new URL(path, `${this.root}/`);
    if (url.origin !== new URL(this.root).origin || !url.pathname.startsWith(`${new URL(this.root).pathname}/`)) throw new Error("Refusing a Bitbucket request outside this repository.");
    assertBitbucketDestination(url.toString());
    try {
      const response = await this.request(url.toString(), { method, redirect: "manual", signal: AbortSignal.timeout(30_000), headers: { Authorization: `Bearer ${this.options.token}`, Accept: "application/json", ...(body ? { "Content-Type": "application/json" } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
      if (!response.ok) throw new Error(`Bitbucket ${method} failed (${response.status}); check access rights and server version.`);
      const text = await response.text();
      if (text.length > 8 * 1024 * 1024) throw new Error("Bitbucket response exceeds 8 MB.");
      const value: unknown = text ? JSON.parse(text) : {};
      if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid Bitbucket response.");
      return value as Json;
    } catch (error) {
      const message = error instanceof Error ? error.message : "request failed";
      throw new Error(message.split(this.options.token).join("***"));
    }
  }
  private url(number: number): string {
    return this.options.platform === "bitbucket-cloud" ? `${this.web}/${this.options.owner}/${this.options.repo}/pull-requests/${id(number)}` : `${this.web}/projects/${this.options.owner}/repos/${this.options.repo}/pull-requests/${id(number)}`;
  }
  async findOpenPullRequest(head: string, base?: string): Promise<PullRequest | undefined> {
    branch(head); if (base) branch(base);
    let path = `${this.prPath()}?state=OPEN&${this.options.platform === "bitbucket-cloud" ? "pagelen" : "limit"}=100`;
    const seen = new Set<string>();
    for (let page = 0; page < 100; page++) {
      if (seen.has(path)) throw new Error("Bitbucket repeated a pull request page.");
      seen.add(path);
      const result = await this.json("GET", path);
      for (const pr of Array.isArray(result.values) ? result.values : []) {
        const matches = this.options.platform === "bitbucket-cloud"
          ? pr.source?.branch?.name === head && String(pr.source?.repository?.full_name ?? "").toLowerCase() === `${this.options.owner}/${this.options.repo}`.toLowerCase()
          : pr.fromRef?.id === `refs/heads/${head}` && String(pr.fromRef?.repository?.slug ?? "").toLowerCase() === this.options.repo.toLowerCase() && String(pr.fromRef?.repository?.project?.key ?? "").toLowerCase() === this.options.owner.toLowerCase();
        if (matches && (!base || (this.options.platform === "bitbucket-cloud" ? pr.destination?.branch?.name === base : pr.toRef?.id === `refs/heads/${base}`)) && pr.state === "OPEN") return { number: id(pr.id), url: this.url(pr.id), isDraft: pr.draft === true };
      }
      if (this.options.platform === "bitbucket-cloud") { if (!result.next) return undefined; path = result.next; }
      else { if (result.isLastPage === true) return undefined; if (!Number.isSafeInteger(result.nextPageStart)) throw new Error("Invalid Bitbucket pagination."); path = `${this.prPath()}?state=OPEN&limit=100&start=${result.nextPageStart}`; }
    }
    throw new Error("Too many Bitbucket pull request pages; refusing to create a possible duplicate.");
  }
  async createPullRequest(input: { base: string; head: string; title: string; bodyFile: string; draft: boolean }): Promise<string> {
    branch(input.base); branch(input.head);
    if (input.base === input.head) throw new Error("Refusing a pull request to the fix branch itself.");
    const repository = { slug: this.options.repo, project: { key: this.options.owner } };
    const body = { title: input.title, description: readFileSync(input.bodyFile, "utf8"), draft: input.draft,
      ...(this.options.platform === "bitbucket-cloud" ? { source: { branch: { name: input.head } }, destination: { branch: { name: input.base } }, close_source_branch: false } : { fromRef: { id: `refs/heads/${input.head}`, repository }, toRef: { id: `refs/heads/${input.base}`, repository } }) };
    const result = await this.json("POST", this.prPath(), body);
    if (result.draft !== input.draft) throw new Error("Bitbucket did not preserve the requested draft state; inspect the created pull request before proceeding.");
    return this.url(id(result.id));
  }
  private async update(number: number, fields: Json): Promise<Json> {
    if (this.options.platform === "bitbucket-cloud") return this.json("PUT", this.prPath(number), fields);
    const current = await this.json("GET", this.prPath(number));
    if (!Number.isSafeInteger(current.version)) throw new Error("Bitbucket returned no pull request version; refusing to overwrite it.");
    return this.json("PUT", this.prPath(number), { version: current.version, ...fields });
  }
  async updatePullRequestBody(number: number, bodyFile: string): Promise<void> { await this.update(number, { description: readFileSync(bodyFile, "utf8") }); }
  async setPullRequestReady(number: number, ready: boolean): Promise<void> {
    const result = await this.update(number, { draft: !ready });
    if (result.draft !== !ready) throw new Error("Bitbucket did not preserve the requested draft state.");
  }
  async editPullRequest(number: number, change: { addLabels?: string[]; addReviewers?: string[] }): Promise<void> {
    if (change.addLabels?.length) throw new Error("Bitbucket pull requests do not support GitHub labels; configure reviewers without labels.");
    if (!change.addReviewers?.length) return;
    const current = await this.json("GET", this.prPath(number));
    const reviewers = Array.isArray(current.reviewers) ? current.reviewers : [];
    for (const reviewer of change.addReviewers) {
      if (this.options.platform === "bitbucket-cloud") {
        if (!/^\{[a-f0-9-]{36}\}$/i.test(reviewer)) throw new Error("Bitbucket Cloud reviewers must be account UUIDs in braces.");
        if (!reviewers.some((item: Json) => item.uuid === reviewer)) reviewers.push({ uuid: reviewer });
      } else if (!reviewers.some((item: Json) => item.user?.name === reviewer)) reviewers.push({ user: { name: reviewer } });
    }
    await this.update(number, { reviewers });
  }
  async pullRequestState(url: string): Promise<PullRequestState> {
    const expected = this.url(1).replace(/1$/, "");
    if (!url.startsWith(expected) || !/^[1-9][0-9]*$/.test(url.slice(expected.length))) throw new Error("Not a pull request URL for this Bitbucket repository.");
    const number = id(Number(url.slice(expected.length)));
    const pr = await this.json("GET", this.prPath(number));
    let commits = 0;
    let path = `${this.prPath(number)}/commits?${this.options.platform === "bitbucket-cloud" ? "pagelen" : "limit"}=100`;
    for (let page = 0; page < 100; page++) {
      const result = await this.json("GET", path);
      commits += Array.isArray(result.values) ? result.values.length : 0;
      if (this.options.platform === "bitbucket-cloud") { if (!result.next) return { state: pr.state === "MERGED" ? "merged" : pr.state === "OPEN" ? "open" : "closed", draft: pr.draft === true, commits }; path = result.next; }
      else { if (result.isLastPage === true) return { state: pr.state === "MERGED" ? "merged" : pr.state === "OPEN" ? "open" : "closed", draft: pr.draft === true, commits }; if (!Number.isSafeInteger(result.nextPageStart)) throw new Error("Invalid Bitbucket pagination."); path = `${this.prPath(number)}/commits?limit=100&start=${result.nextPageStart}`; }
    }
    throw new Error("Too many Bitbucket commit pages.");
  }
  async pullRequestChecks(url: string): Promise<import("./index.js").PullRequestChecks> {
    const expected = this.url(1).replace(/1$/, "");
    if (!url.startsWith(expected) || !/^[1-9][0-9]*$/.test(url.slice(expected.length))) throw new Error("Not a pull request URL for this Bitbucket repository.");
    const number = id(Number(url.slice(expected.length)));
    const pr = await this.json("GET", this.prPath(number));
    let path: string;
    if (this.options.platform === "bitbucket-cloud") path = `${this.prPath(number)}/statuses?pagelen=100`;
    else {
      const sha = pr.fromRef?.latestCommit;
      if (typeof sha !== "string" || !/^[a-f0-9]{40,64}$/.test(sha)) throw new Error("Bitbucket returned no head commit for CI status.");
      path = `commits/${sha}/builds?limit=100`;
    }
    const states: string[] = [];
    for (let page = 0; page < 100; page++) {
      const result = await this.json("GET", path);
      for (const check of Array.isArray(result.values) ? result.values : []) states.push(String(check.state ?? "UNKNOWN"));
      if (this.options.platform === "bitbucket-cloud") { if (!result.next) break; path = result.next; }
      else { if (result.isLastPage === true) break; if (!Number.isSafeInteger(result.nextPageStart)) throw new Error("Invalid Bitbucket pagination."); path = `commits/${pr.fromRef.latestCommit}/builds?limit=100&start=${result.nextPageStart}`; }
      if (page === 99) throw new Error("Too many Bitbucket status pages.");
    }
    return { status: !states.length ? "none" : states.some(state => ["FAILED", "STOPPED", "CANCELLED"].includes(state)) ? "failing" : states.every(state => state === "SUCCESSFUL") ? "passing" : "pending", url };
  }
  async pushBranch(value: string): Promise<void> {
    branch(value);
    assertBitbucketDestination(`${this.root}/`);
    await this.options.git(["-c", "http.followRedirects=false", "-c", "protocol.ext.allow=never", "-c", "core.hooksPath=/dev/null", "push", "--force-with-lease", "--set-upstream", "origin", `refs/heads/${value}:refs/heads/${value}`]);
  }
  issues(): IssueTracker { return unsupported(); }
  async uploadSarif(): Promise<{ id?: string }> { return unsupported(); }
  async sarifStatus(): Promise<{ processing_status?: string; errors?: string[] }> { return unsupported(); }
}
