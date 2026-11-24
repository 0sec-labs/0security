/** GitHub through the `gh` CLI: arguments are arrays, never a shell string. */
import type { Host, HostRun, IssueDraft, IssueTracker, PullRequest, PullRequestState, SarifUpload, TrackerIssue } from "./index.js";

export const REPO = /^(?!\.{1,2}\/)[A-Za-z0-9_.-]{1,100}\/(?!\.{1,2}$)[A-Za-z0-9_.-]{1,100}$/;
/** The pull request URLs `0 findings fix` records. */
export const PULL_URL = /^https:\/\/github\.com\/[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}\/pull\/[0-9]{1,9}$/;
const MARKER = /<!-- 0-finding:([A-Za-z0-9:_.-]{1,80}) -->/;
const COLOURS: Record<string, string> = { security: "d73a4a", critical: "b60205", high: "d93f0b", medium: "fbca04", low: "0e8a16", info: "c5def5" };

const errorLine = (error: unknown): string => (error instanceof Error ? error.message : String(error)).split("\n")[0]!.slice(0, 160);

/** GitHub Issues through the `gh` CLI. */
export class GitHubIssueTracker implements IssueTracker {
  constructor(private readonly repo: string, private readonly gh: HostRun) {}

  async list(): Promise<TrackerIssue[]> {
    // Only issues labelled `security` are managed: adding that label needs triage rights, so a stranger cannot
    // point this command at an issue just by pasting a marker. Pull requests share the issues API; skip them.
    const jq = '.[] | select(.pull_request | not) | {number, title, body: (.body // ""), open: (.state == "open"), labels: [.labels[].name]}';
    const text = await this.gh(["api", "--paginate", `repos/${this.repo}/issues?state=all&labels=security&per_page=100`, "--jq", jq]);
    const issues: TrackerIssue[] = [];
    for (const line of text.split("\n")) {
      if (!line.trim()) continue;
      const row = JSON.parse(line) as Omit<TrackerIssue, "key">;
      const key = MARKER.exec(row.body)?.[1];
      if (key) issues.push({ ...row, key });
    }
    return issues;
  }

  async ensureLabels(labels: string[]): Promise<{ usable: string[]; warnings: string[] }> {
    let existing: Set<string>;
    try { existing = new Set((await this.gh(["api", "--paginate", `repos/${this.repo}/labels?per_page=100`, "--jq", ".[].name"])).split("\n").map(line => line.trim()).filter(Boolean)); }
    catch (error) { return { usable: [], warnings: [`could not read the repository's labels (${errorLine(error)}); changing issues without labels`] }; }
    const usable: string[] = []; const warnings: string[] = [];
    for (const name of labels) {
      if (existing.has(name)) { usable.push(name); continue; }
      const colour = COLOURS[name.startsWith("severity:") ? name.slice(9) : name] ?? "ededed";
      try {
        await this.gh(["api", "--method", "POST", `repos/${this.repo}/labels`, "--input", "-"], JSON.stringify({ name, color: colour, description: name === "security" ? "Mirrored from 0security findings" : "Severity of a mirrored 0 finding" }));
        usable.push(name);
      } catch (error) { warnings.push(`could not create label '${name}' (${errorLine(error)}); skipping it`); }
    }
    return { usable, warnings };
  }

  async create(draft: IssueDraft): Promise<number> {
    const created = JSON.parse(await this.gh(["api", "--method", "POST", `repos/${this.repo}/issues`, "--input", "-"], JSON.stringify(draft))) as { number?: number };
    if (!created.number) throw new Error("GitHub created the issue but returned no number.");
    return created.number;
  }

  async update(issue: TrackerIssue, draft: IssueDraft): Promise<void> {
    await this.patch(issue.number, { title: draft.title, body: draft.body });
    await this.syncLabels(issue, draft.labels);
  }

  async close(issue: TrackerIssue, comment: string, completed: boolean, draft?: IssueDraft): Promise<void> {
    await this.comment(issue.number, comment);
    await this.patch(issue.number, { state: "closed", state_reason: completed ? "completed" : "not_planned", ...(draft ? { body: draft.body } : {}) });
  }

  async reopen(issue: TrackerIssue, comment: string): Promise<void> {
    await this.patch(issue.number, { state: "open" });
    await this.comment(issue.number, comment);
  }

  private patch(number: number, body: Record<string, string>): Promise<string> {
    return this.gh(["api", "--method", "PATCH", `repos/${this.repo}/issues/${number}`, "--input", "-"], JSON.stringify(body));
  }
  private comment(number: number, body: string): Promise<string> {
    return this.gh(["api", "--method", "POST", `repos/${this.repo}/issues/${number}/comments`, "--input", "-"], JSON.stringify({ body }));
  }
  /** Add the labels the issue lacks and drop an outdated severity label, leaving labels people added alone. */
  private async syncLabels(issue: TrackerIssue, wanted: string[]): Promise<void> {
    const missing = wanted.filter(label => !issue.labels.includes(label));
    if (missing.length) await this.gh(["api", "--method", "POST", `repos/${this.repo}/issues/${issue.number}/labels`, "--input", "-"], JSON.stringify({ labels: missing }));
    for (const label of issue.labels) if (label.startsWith("severity:") && !wanted.includes(label)) await this.gh(["api", "--method", "DELETE", `repos/${this.repo}/issues/${issue.number}/labels/${encodeURIComponent(label)}`]);
  }
}

export class GitHubHost implements Host {
  readonly name = "github";
  constructor(private readonly gh: HostRun, private readonly git?: (args: string[]) => Promise<string>) {}

  isValidRepo(name: string): boolean { return REPO.test(name); }

  async currentRepo(): Promise<string> {
    return (await this.gh(["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"]).catch(() => "")).trim();
  }

  async findOpenPullRequest(branch: string): Promise<PullRequest | undefined> {
    const found = JSON.parse((await this.gh(["pr", "list", "--head", branch, "--state", "open", "--json", "number,url,isDraft"])) || "[]") as PullRequest[];
    return found[0];
  }

  async createPullRequest(input: { base: string; head: string; title: string; bodyFile: string; draft: boolean }): Promise<string> {
    return (await this.gh(["pr", "create", "--base", input.base, "--head", input.head, "--title", input.title, "--body-file", input.bodyFile, ...(input.draft ? ["--draft"] : [])])).trim().split("\n").pop() ?? "";
  }

  async updatePullRequestBody(number: number, bodyFile: string): Promise<void> {
    await this.gh(["pr", "edit", String(number), "--body-file", bodyFile]);
  }

  async setPullRequestReady(number: number, ready: boolean): Promise<void> {
    await this.gh(ready ? ["pr", "ready", String(number)] : ["pr", "ready", "--undo", String(number)]);
  }

  async pullRequestState(url: string): Promise<PullRequestState> {
    if (!PULL_URL.test(url)) throw new Error("Not a GitHub pull request URL.");
    const raw = JSON.parse(await this.gh(["pr", "view", url, "--json", "state,isDraft,commits", "--jq", "{state, isDraft, commits: (.commits | length)}"])) as { state?: string; isDraft?: boolean; commits?: number };
    const state = raw.state === "MERGED" ? "merged" : raw.state === "CLOSED" ? "closed" : "open";
    return { state, draft: raw.isDraft === true, commits: typeof raw.commits === "number" ? raw.commits : 0 };
  }

  async editPullRequest(number: number, change: { addLabels?: string[]; addReviewers?: string[] }): Promise<void> {
    const args = [...(change.addLabels ?? []).flatMap(label => [`--add-label=${label}`]), ...(change.addReviewers ?? []).flatMap(name => [`--add-reviewer=${name}`])];
    if (args.length) await this.gh(["pr", "edit", String(number), ...args]);
  }

  async pushBranch(branch: string): Promise<void> {
    if (!this.git) throw new Error("pushBranch needs a git runner.");
    // The branch is ours and only ours: never the base, always with a lease so a person's later push is not overwritten.
    await this.git(["push", "--force-with-lease", "--set-upstream", "origin", `${branch}:${branch}`]);
  }

  issues(repo: string): IssueTracker { return new GitHubIssueTracker(repo, this.gh); }

  async uploadSarif(repo: string, upload: SarifUpload): Promise<{ id?: string }> {
    const body = JSON.stringify({ commit_sha: upload.commit, ref: upload.ref, sarif: upload.sarif, ...(upload.tool ? { tool_name: upload.tool } : {}) });
    return JSON.parse(await this.gh(["api", "--method", "POST", `repos/${repo}/code-scanning/sarifs`, "--input", "-"], body)) as { id?: string };
  }

  async sarifStatus(repo: string, id: string): Promise<{ processing_status?: string; errors?: string[] }> {
    return JSON.parse(await this.gh(["api", `repos/${repo}/code-scanning/sarifs/${encodeURIComponent(id)}`])) as { processing_status?: string; errors?: string[] };
  }
}
