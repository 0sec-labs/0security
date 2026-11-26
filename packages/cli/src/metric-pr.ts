import { createHash } from "node:crypto";

/** Actual host PR identity only. No credentials, query, fragment, local paths or arbitrary web links. */
export function metricPullRequest(value: unknown): { pullRequestUrl: string; repositoryId: string } | undefined {
  if (typeof value !== "string" || value.length > 1000) return undefined;
  try {
    const url = new URL(value);
    if (url.username || url.password || url.search || url.hash || (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)))) return undefined;
    if (["github.com", "bitbucket.org"].includes(url.hostname) && url.port) return undefined;
    const slug = "[A-Za-z0-9_~.-]{1,200}";
    let repository: string | undefined;
    if (url.hostname === "github.com" && new RegExp(`^/${slug}/${slug}/pull/[1-9][0-9]{0,9}$`).test(url.pathname)) repository = url.pathname.replace(/\/pull\/\d+$/, "");
    else if (url.hostname === "bitbucket.org" && new RegExp(`^/${slug}/${slug}/pull-requests/[1-9][0-9]{0,9}$`).test(url.pathname)) repository = url.pathname.replace(/\/pull-requests\/\d+$/, "");
    else if (new RegExp(`^(?:/${slug})*/projects/${slug}/repos/${slug}/pull-requests/[1-9][0-9]{0,9}$`).test(url.pathname)) repository = url.pathname.replace(/\/pull-requests\/\d+$/, "");
    if (!repository || repository.split("/").some(part => part === "." || part === "..")) return undefined;
    // GitHub and Cloud repository names are case-insensitive; retain Data Center context-path case.
    const canonical = url.hostname === "github.com" || url.hostname === "bitbucket.org" ? repository.toLowerCase() : repository;
    const suffix = url.pathname.slice(repository.length);
    return { pullRequestUrl: `${url.origin}${canonical}${suffix}`, repositoryId: createHash("sha256").update(`${url.origin}${canonical}`).digest("hex") };
  } catch { return undefined; }
}

/** Resolve the named checkout's configured origin without storing its local folder. */
export function metricRepositoryFromOrigin(origin: string, bitbucketUrl?: string): string | undefined {
  try {
    const ssh = /^(?:[^@/:]+@)?([^/:]+):(.+)$/.exec(origin);
    const url = new URL(origin.includes("://") ? origin : ssh ? `ssh://${ssh[1]}/${ssh[2]}` : origin);
    if (!["https:", "http:", "ssh:"].includes(url.protocol)) return undefined;
    if (["github.com", "bitbucket.org"].includes(url.hostname) && (url.protocol === "http:" || (url.port && !(url.protocol === "ssh:" && url.port === "22")))) return undefined;
    if (url.password || (url.protocol !== "ssh:" && url.username) || url.search || url.hash) return undefined;
    const path = url.pathname.replace(/\.git$/, "");
    if (url.hostname === "github.com" || url.hostname === "bitbucket.org") return metricPullRequest(`https://${url.hostname}${path}/${url.hostname === "github.com" ? "pull" : "pull-requests"}/1`)?.repositoryId;
    if (!bitbucketUrl) return undefined;
    const base = new URL(bitbucketUrl);
    if (base.username || base.password || base.search || base.hash) return undefined;
    if (base.hostname !== url.hostname || (url.protocol !== "ssh:" && base.origin !== url.origin)) return undefined;
    const context = base.pathname.replace(/\/+$/, "");
    const repo = url.protocol === "ssh:" ? path.replace(/^\//, "") : path.startsWith(`${context}/scm/`) ? path.slice(`${context}/scm/`.length) : "";
    const parts = repo.split("/");
    if (parts.length !== 2) return undefined;
    return metricPullRequest(`${base.origin}${context}/projects/${parts[0]}/repos/${parts[1]}/pull-requests/1`)?.repositoryId;
  } catch { return undefined; }
}
