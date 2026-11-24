// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// Repository scope. A scan target names a repository when it is a GitHub URL or "owner/name".
// Local paths and other targets name no repository, so a scoped account never sees them.

/** "owner/name" for a GitHub URL, an ssh address or "owner/name" itself. Null when the target names no repository. */
export function repoOfTarget(target: string): string | null {
  const text = target.trim();
  let m = /^(?:https?:\/\/|ssh:\/\/git@)(?:www\.)?github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?(?:[#?].*)?$/i.exec(text);
  if (!m) m = /^git@github\.com:([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?$/i.exec(text);
  if (!m && !/^[./~]/.test(text)) m = /^([A-Za-z0-9_][A-Za-z0-9_.-]*)\/([A-Za-z0-9_.-]+)$/.exec(text);
  return m ? `${m[1]}/${m[2]}`.toLowerCase() : null;
}

function globToRegExp(pattern: string): RegExp {
  const escaped = pattern.toLowerCase().replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*");
  return new RegExp(`^${escaped}$`);
}

/** True when the repository ("owner/name") matches one of the patterns. `*` matches within one path part. */
export function repoMatches(repo: string, patterns: readonly string[]): boolean {
  const name = repo.toLowerCase();
  return patterns.some((pattern) => globToRegExp(pattern.includes("/") ? pattern : `${pattern}/*`).test(name));
}

/**
 * A filter for scan targets. `patterns` null means no scope: everything passes.
 * With a scope, only targets that name a matching repository pass.
 */
export function targetFilter(patterns: readonly string[] | null): ((target: string) => boolean) | undefined {
  if (patterns === null) return undefined;
  return (target: string) => {
    const repo = repoOfTarget(target);
    return repo !== null && repoMatches(repo, patterns);
  };
}
