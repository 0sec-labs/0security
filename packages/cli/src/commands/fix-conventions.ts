/**
 * Pull request conventions for `0 findings fix` and `burndown`: the title, branch prefix, commit subject, labels,
 * reviewers, draft rule and footer an organisation wants on every fix pull request.
 *
 * They come from the operator's fix policy file (`pullRequest` key), never from the repository being fixed. The
 * template language is placeholders only: {id} {title} {severity} {category} {path}. Nothing is evaluated.
 */
import { shortFindingId } from "../finding-id.js";
import { UsageError } from "./output.js";

export type DraftRule = "always" | "on-failure" | "never";
export interface PullRequestConventions {
  titleTemplate?: string;
  branchPrefix?: string;
  labels?: string[];
  draft?: DraftRule;
  bodyFooter?: string;
  reviewers?: string[];
  commitMessageTemplate?: string;
}

/** What a template can mention about a finding. */
export interface ConventionFinding { id: string; title: string; severity: string; category: string; path?: string }

export const PLACEHOLDERS = ["id", "title", "severity", "category", "path"] as const;
export const MAX_TEMPLATE_CHARS = 200;
export const MAX_RENDERED_CHARS = 200;
export const MAX_FOOTER_CHARS = 1000;
export const MAX_LABELS = 10;
export const MAX_REVIEWERS = 10;
const BRANCH_PREFIX_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,39}$/;
const LABEL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 _.:/-]{0,49}$/;
const USER_PATTERN = /^(?!-)[A-Za-z0-9_.-]{1,39}$/;
const TEAM_PATTERN = /^(?!-)[A-Za-z0-9_.-]{1,39}\/(?!-)[A-Za-z0-9_.-]{1,100}$/;
const KNOWN_KEYS = new Set(["titleTemplate", "branchPrefix", "labels", "draft", "bodyFooter", "reviewers", "commitMessageTemplate"]);
const CONTROL = /[\u0000-\u001f\u007f\u2028\u2029]/;

export const isReviewerName = (name: string): boolean => USER_PATTERN.test(name) || TEAM_PATTERN.test(name);

function template(name: string, value: unknown): string {
  if (typeof value !== "string" || !value.trim()) throw new UsageError(`pullRequest.${name} must be a non-empty string.`);
  if (value.length > MAX_TEMPLATE_CHARS) throw new UsageError(`pullRequest.${name} is longer than ${MAX_TEMPLATE_CHARS} characters.`);
  if (CONTROL.test(value)) throw new UsageError(`pullRequest.${name} must be one line.`);
  const stripped = value.replace(/\{(\w+)\}/g, (whole, key: string) => {
    if (!(PLACEHOLDERS as readonly string[]).includes(key)) throw new UsageError(`pullRequest.${name} uses {${key}}. Use only ${PLACEHOLDERS.map(p => `{${p}}`).join(", ")}.`);
    return "";
  });
  if (/[{}]/.test(stripped)) throw new UsageError(`pullRequest.${name} has a stray brace. Write placeholders as {id}, {title}, {severity}, {category} or {path}.`);
  return value;
}

function list(name: string, value: unknown, max: number, valid: (item: string) => boolean, shape: string): string[] {
  if (!Array.isArray(value) || value.some(item => typeof item !== "string")) throw new UsageError(`pullRequest.${name} must be a list of strings.`);
  if (value.length > max) throw new UsageError(`pullRequest.${name} has more than ${max} entries.`);
  for (const item of value as string[]) if (!valid(item)) throw new UsageError(`pullRequest.${name} entry '${item.slice(0, 40).replace(CONTROL, " ")}' is not ${shape}.`);
  return [...new Set(value as string[])];
}

/** Validate the `pullRequest` object of a policy file. Throws a usage error naming the first problem. */
export function parsePullRequestConventions(raw: unknown): PullRequestConventions {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new UsageError("pullRequest must be an object.");
  const obj = raw as Record<string, unknown>;
  for (const key of Object.keys(obj)) if (!KNOWN_KEYS.has(key)) throw new UsageError(`pullRequest.${key} is not a setting. Use ${[...KNOWN_KEYS].join(", ")}.`);
  const out: PullRequestConventions = {};
  if (obj.titleTemplate !== undefined) out.titleTemplate = template("titleTemplate", obj.titleTemplate);
  if (obj.commitMessageTemplate !== undefined) out.commitMessageTemplate = template("commitMessageTemplate", obj.commitMessageTemplate);
  if (obj.branchPrefix !== undefined) {
    const prefix = obj.branchPrefix;
    if (typeof prefix !== "string" || !BRANCH_PREFIX_PATTERN.test(prefix) || prefix.includes("..") || prefix.includes("//") || prefix.endsWith(".lock")) throw new UsageError("pullRequest.branchPrefix must be letters, digits, '.', '_', '-' and '/', start with a letter or digit, and be at most 40 characters, for example sec/fix-.");
    out.branchPrefix = prefix;
  }
  if (obj.labels !== undefined) out.labels = list("labels", obj.labels, MAX_LABELS, item => LABEL_PATTERN.test(item), "a label name (letters, digits, space, '_', '.', ':', '/', '-')");
  if (obj.reviewers !== undefined) out.reviewers = list("reviewers", obj.reviewers, MAX_REVIEWERS, isReviewerName, "a user name or org/team");
  if (obj.draft !== undefined) {
    if (obj.draft !== "always" && obj.draft !== "on-failure" && obj.draft !== "never") throw new UsageError("pullRequest.draft must be always, on-failure or never.");
    out.draft = obj.draft;
  }
  if (obj.bodyFooter !== undefined) {
    if (typeof obj.bodyFooter !== "string") throw new UsageError("pullRequest.bodyFooter must be a string.");
    if (obj.bodyFooter.length > MAX_FOOTER_CHARS) throw new UsageError(`pullRequest.bodyFooter is longer than ${MAX_FOOTER_CHARS} characters.`);
    out.bodyFooter = obj.bodyFooter;
  }
  return out;
}

/** Text that goes to GitHub: one line, no markup, no mentions, no issue references. */
export function neutralise(text: string): string {
  return text.replace(CONTROL, " ").replace(/\s+/g, " ").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/@/g, "@​").replace(/(^|[^\w])#(\d)/g, "$1#​$2").replace(/`/g, "'").trim();
}

/** Fill a template. Every value is neutralised and the result is cut to MAX_RENDERED_CHARS; unknown placeholders stay out. */
export function renderTemplate(templateText: string, finding: ConventionFinding): string {
  const values: Record<string, string> = { id: shortFindingId(finding.id), title: finding.title, severity: finding.severity, category: finding.category, path: finding.path ?? "unknown" };
  const text = templateText.replace(/\{(\w+)\}/g, (_whole, key: string) => neutralise(values[key] ?? ""));
  return text.length > MAX_RENDERED_CHARS ? `${text.slice(0, MAX_RENDERED_CHARS - 1)}…` : text;
}

export const defaultTitle = (finding: ConventionFinding): string => `fix: ${finding.title.slice(0, 120)}`;

/** The pull request title: the template when one is set, otherwise `fix: <title>`. */
export const pullRequestTitle = (finding: ConventionFinding, conventions?: PullRequestConventions): string =>
  conventions?.titleTemplate ? renderTemplate(conventions.titleTemplate, finding) : defaultTitle(finding);

/** The first line of the commit message; the finding id follows in the body either way. */
export const commitSubject = (finding: ConventionFinding, conventions?: PullRequestConventions): string =>
  conventions?.commitMessageTemplate ? renderTemplate(conventions.commitMessageTemplate, finding) : defaultTitle(finding);

/** Whether the pull request is a draft: `on-failure` (the default) drafts when a check failed. */
export function isDraft(verified: boolean, conventions?: PullRequestConventions): boolean {
  const rule = conventions?.draft ?? "on-failure";
  return rule === "always" ? true : rule === "never" ? false : !verified;
}

/** The operator's footer, neutralised line by line and ready to append to the body. */
export function footerText(conventions?: PullRequestConventions): string | undefined {
  const footer = conventions?.bodyFooter;
  if (!footer?.trim()) return undefined;
  return footer.replace(/\r/g, "").split("\n").map(line => neutralise(line.replace(CONTROL, " "))).join("\n").trim().slice(0, MAX_FOOTER_CHARS) || undefined;
}
