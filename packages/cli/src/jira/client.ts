/**
 * A small Jira client: look up issues by label, create an issue. Jira Cloud (REST v3, Atlassian Document Format,
 * email + API token as basic auth) and Jira Data Center (REST v2, plain text, personal access token as bearer).
 * The token is only ever put in the Authorization header and is scrubbed from every error message.
 */
import { assertEgressAllowed } from "@0/engine";
import type { FetchLike } from "../code-insights.js";

export type JiraPlatform = "jira-cloud" | "jira-dc";

export class JiraError extends Error {
  constructor(message: string, readonly status?: number) { super(message); }
}

export interface JiraClientOptions {
  platform: JiraPlatform;
  /** Site root, e.g. the Cloud site or the Data Center server (with its context path, if any). */
  baseUrl: string;
  token: string;
  /** Cloud only: the account email for basic auth. */
  email?: string;
  fetch: FetchLike;
  allowInsecureHttp?: boolean;
  env?: NodeJS.ProcessEnv;
}

export interface JiraIssueInput { project: string; issueType: string; summary: string; labels: string[]; paragraphs: string[] }

const SEARCH_BATCH = 25;

export class JiraClient {
  readonly #token: string;
  readonly #root: string;
  readonly #auth: string;
  readonly #cloud: boolean;
  readonly #fetch: FetchLike;
  readonly #env: NodeJS.ProcessEnv;

  constructor(options: JiraClientOptions) {
    this.#cloud = options.platform === "jira-cloud";
    this.#token = options.token;
    this.#fetch = options.fetch;
    this.#env = options.env ?? process.env;
    let parsed: URL;
    try { parsed = new URL(options.baseUrl); } catch { throw new JiraError("The Jira URL is not valid."); }
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") throw new JiraError("The Jira URL must start with https://.");
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
    if (parsed.protocol === "http:" && !loopback && !options.allowInsecureHttp) throw new JiraError("Refusing to send the Jira token over plain HTTP. Use an https:// URL, or pass --allow-insecure-http on a network you trust.");
    if (parsed.search || parsed.hash || parsed.username || parsed.password) throw new JiraError("The Jira URL must not contain a query, fragment or credentials.");
    this.#root = `${parsed.origin}${parsed.pathname.replace(/\/+$/, "")}/rest/api/${this.#cloud ? "3" : "2"}`;
    if (this.#cloud) {
      if (!options.email) throw new JiraError("Jira Cloud needs the account email (JIRA_EMAIL) next to the API token.");
      this.#auth = `Basic ${Buffer.from(`${options.email}:${options.token}`).toString("base64")}`;
    } else this.#auth = `Bearer ${options.token}`;
  }

  #clean(message: string): string {
    let out = message.split(this.#token).join("***");
    const encoded = this.#auth.replace(/^\w+ /, "");
    if (encoded) out = out.split(encoded).join("***");
    return out;
  }

  async #send(path: string, body: unknown): Promise<unknown> {
    const url = `${this.#root}${path}`;
    assertEgressAllowed("Jira", this.#env);
    let response;
    try {
      response = await this.#fetch(url, { method: "POST", headers: { Authorization: this.#auth, "Content-Type": "application/json", Accept: "application/json" }, body: JSON.stringify(body), redirect: "manual" });
    } catch (error) { throw new JiraError(this.#clean(`POST ${new URL(url).pathname} failed: ${error instanceof Error ? error.message : String(error)}`)); }
    const text = await response.text().catch(() => "");
    if (!response.ok) throw new JiraError(this.#clean(`Jira answered ${response.status} to POST ${new URL(url).pathname}${text ? `: ${text.replace(/\s+/g, " ").slice(0, 300)}` : ""}`), response.status);
    try { return text ? JSON.parse(text) : {}; } catch { throw new JiraError("Jira answered with something that is not JSON."); }
  }

  /** Which of these labels already sit on an issue in the project, mapped to that issue's key. Closed issues count. */
  async findExisting(project: string, labels: string[]): Promise<Map<string, string>> {
    const found = new Map<string, string>();
    for (let start = 0; start < labels.length; start += SEARCH_BATCH) {
      const batch = labels.slice(start, start + SEARCH_BATCH);
      const jql = `project = "${project}" AND labels in (${batch.map(label => `"${label}"`).join(", ")})`;
      const request = this.#cloud ? { jql, fields: ["labels"], maxResults: 100 } : { jql, fields: ["labels"], maxResults: 100, startAt: 0 };
      const answer = await this.#send(this.#cloud ? "/search/jql" : "/search", request) as { issues?: Array<{ key?: string; fields?: { labels?: string[] } }> };
      for (const issue of answer.issues ?? []) {
        for (const label of issue.fields?.labels ?? []) if (batch.includes(label) && issue.key && !found.has(label)) found.set(label, issue.key);
      }
    }
    return found;
  }

  async createIssue(input: JiraIssueInput): Promise<string> {
    const description = this.#cloud
      ? { type: "doc", version: 1, content: input.paragraphs.map(text => ({ type: "paragraph", content: [{ type: "text", text }] })) }
      : input.paragraphs.join("\n\n");
    const answer = await this.#send("/issue", { fields: { project: { key: input.project }, issuetype: { name: input.issueType }, summary: input.summary, labels: input.labels, description } }) as { key?: string };
    if (!answer.key) throw new JiraError("Jira created the issue but returned no key.");
    return answer.key;
  }
}
