/**
 * `0security findings upload <scan.json> --to jira-cloud|jira-dc`: one Jira issue per open finding. Each issue carries a
 * `0-finding-<id>` label; before creating, the project is searched for that label, so running it again creates only
 * what is new. Issues that were closed in Jira still hold their label, so a closed issue is not reopened or recreated.
 */
import { JiraClient, type JiraPlatform } from "./client.js";
import { findingLabel, readJiraFindings, type JiraFinding } from "./findings.js";
import type { FetchLike } from "../code-insights.js";
import { UsageError } from "../commands/output.js";

export interface JiraExportOptions {
  to: JiraPlatform;
  project?: string;
  issueType?: string;
  labels?: string[];
  url?: string;
  dryRun?: boolean;
  allowInsecureHttp?: boolean;
}
export interface JiraExportDeps { env: Record<string, string | undefined>; fetch: FetchLike; readText(path: string): string }

export interface PlannedIssue { findingId: string; label: string; summary: string; labels: string[]; paragraphs: string[] }
export interface JiraExportResult {
  dryRun: boolean;
  created: Array<{ findingId: string; key?: string; summary: string }>;
  existing: Array<{ findingId: string; key: string }>;
  skipped: number;
  planned?: PlannedIssue[];
}

const PROJECT = /^[A-Za-z][A-Za-z0-9_]{1,19}$/;
const LABEL = /^[^\s"\\]{1,255}$/;
const SUMMARY_MAX = 255;
const DESCRIPTION_MAX = 30_000;
const truncate = (text: string, max: number): string => (text.length <= max ? text : `${text.slice(0, max - 3)}...`);

export function planIssue(finding: JiraFinding, extraLabels: string[]): PlannedIssue {
  const paragraphs = [
    `Severity: ${finding.severity}`,
    `Location: ${finding.location}`,
    ...(finding.cwe ? [`Weakness: ${finding.cwe}`] : []),
    `Rule: ${finding.ruleId}`,
    ...(finding.description ? [`Description: ${finding.description}`] : []),
    ...(finding.impact && finding.impact !== finding.description ? [`Impact: ${finding.impact}`] : []),
    ...(finding.fix ? [`Suggested fix: ${finding.fix}`] : []),
    `0security finding id: ${finding.id}`,
  ];
  let total = 0;
  const kept: string[] = [];
  for (const paragraph of paragraphs) { const text = truncate(paragraph, DESCRIPTION_MAX - total); total += text.length; kept.push(text); if (total >= DESCRIPTION_MAX) break; }
  const label = findingLabel(finding.id);
  return { findingId: finding.id, label, summary: truncate(finding.title.replace(/\s+/g, " "), SUMMARY_MAX), labels: [...new Set(["0security", finding.severity, label, ...extraLabels])], paragraphs: kept };
}

export async function runJiraExport(file: string, options: JiraExportOptions, deps: JiraExportDeps): Promise<JiraExportResult> {
  const platform = options.to;
  const project = options.project?.trim() || deps.env.JIRA_PROJECT?.trim() || "";
  if (!PROJECT.test(project)) throw new UsageError("Name the Jira project with --jira-project KEY (or JIRA_PROJECT).");
  const issueType = (options.issueType ?? "").trim() || "Task";
  if (/["\\\n\r]/.test(issueType)) throw new UsageError("--jira-issue-type holds a plain issue type name such as Bug or Task.");
  const extra = (options.labels ?? []).map(label => label.trim()).filter(Boolean);
  for (const label of extra) if (!LABEL.test(label)) throw new UsageError(`Jira labels hold no spaces or quotes: ${label.slice(0, 40)}`);

  let parsed;
  try { parsed = readJiraFindings(deps.readText(file)); }
  catch (error) { if (error instanceof UsageError) throw error; throw new UsageError(`${error instanceof Error ? error.message : String(error)} Make one with \`0security scan --format json -o scan.json\`.`); }
  const planned = parsed.open.map(finding => planIssue(finding, extra));

  if (options.dryRun) {
    return { dryRun: true, created: planned.map(issue => ({ findingId: issue.findingId, summary: issue.summary })), existing: [], skipped: parsed.skipped, planned };
  }

  const token = (deps.env.JIRA_TOKEN ?? "").trim();
  if (!token) throw new UsageError("JIRA_TOKEN is not set. Set it (and JIRA_EMAIL for Jira Cloud), or add --dry-run to see what would be created.");
  const baseUrl = (options.url || deps.env.JIRA_URL || "").trim();
  if (!baseUrl) throw new UsageError("Name the Jira site with --url (or JIRA_URL).");
  const email = (deps.env.JIRA_EMAIL ?? "").trim();
  if (platform === "jira-cloud" && !email) throw new UsageError("Jira Cloud needs JIRA_EMAIL (the account the API token belongs to) next to JIRA_TOKEN.");

  const client = new JiraClient({ platform, baseUrl, token, ...(email ? { email } : {}), fetch: deps.fetch, ...(options.allowInsecureHttp ? { allowInsecureHttp: true } : {}), env: deps.env as NodeJS.ProcessEnv });
  const known = planned.length ? await client.findExisting(project, planned.map(issue => issue.label)) : new Map<string, string>();
  const result: JiraExportResult = { dryRun: false, created: [], existing: [], skipped: parsed.skipped };
  for (const issue of planned) {
    const key = known.get(issue.label);
    if (key) { result.existing.push({ findingId: issue.findingId, key }); continue; }
    const created = await client.createIssue({ project, issueType, summary: issue.summary, labels: issue.labels, paragraphs: issue.paragraphs });
    result.created.push({ findingId: issue.findingId, key: created, summary: issue.summary });
  }
  return result;
}
