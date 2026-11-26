import { enterpriseMode } from "@0/engine";
import { assertBitbucketDestination } from "../bitbucket/client.js";
import { UsageError } from "../commands/output.js";
import { GitHubHost } from "./github.js";
import { BitbucketHost } from "./bitbucket.js";
import { type Host, type HostOptions } from "./index.js";

export interface FixHostOptions extends HostOptions { bitbucketUrl?: string; env?: NodeJS.ProcessEnv; fetch?: typeof fetch }

/** Resolve only the configured origin. A different push URL is refused before any change or network write. */
export async function selectFixHost(options: FixHostOptions): Promise<Host> {
  if (!options.git) throw new UsageError("The fix host needs a git runner.");
  const env = options.env ?? process.env;
  const rejectRewrites = async () => {
    const names = await options.git!(["config", "--list", "--name-only"]);
    if (/^url\..*\.(insteadof|pushinsteadof)$/im.test(names)) throw new UsageError("Git insteadOf/pushInsteadOf URL rewriting is not supported for fix publishing.");
  };
  await rejectRewrites();
  const origin = (await options.git(["remote", "get-url", "origin"])).trim();
  const push = (await options.git(["remote", "get-url", "--push", "--all", "origin"])).trim().split("\n");
  if (push.length !== 1 || push[0] !== origin) throw new UsageError("The origin push URL must match its fetch URL and have one destination.");
  const ssh = /^(?:[^@/:]+@)?([^/:]+):(.+)$/.exec(origin);
  let url: URL;
  try { url = new URL(origin.includes("://") ? origin : ssh ? `ssh://${ssh[1]}/${ssh[2]}` : origin); } catch { throw new UsageError("Cannot identify origin's code host."); }
  if (!["https:", "http:", "ssh:"].includes(url.protocol) || url.password || (url.protocol !== "ssh:" && url.username) || url.search || url.hash) throw new UsageError("Use an HTTPS or SSH origin without embedded credentials.");
  const safeGit = async (args: string[]) => {
    if (args.includes("push")) {
      await rejectRewrites();
      const currentOrigin = (await options.git!(["remote", "get-url", "origin"])).trim();
      const currentPush = (await options.git!(["remote", "get-url", "--push", "--all", "origin"])).trim();
      if (currentOrigin !== origin || currentPush !== origin) throw new UsageError("Origin changed during the fix; refusing to push.");
      if (enterpriseMode(env)) {
        if (url.protocol !== "https:") throw new UsageError("Restricted fix publishing requires an allowlisted HTTPS git origin; SSH is not permitted.");
        assertBitbucketDestination(currentPush, env);
      }
    }
    return options.git!(args);
  };
  const wanted = options.host ?? (url.hostname === "bitbucket.org" ? "bitbucket-cloud" : url.hostname === "github.com" ? "github" : "bitbucket-dc");
  if (wanted === "github") {
    if (url.hostname !== "github.com") throw new UsageError("--host github does not match origin.");
    const repository = url.pathname.replace(/^\//, "").replace(/\.git$/, "");
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) throw new UsageError("Invalid GitHub origin repository.");
    const run: HostOptions["run"] = (args, input) => options.run(args[0] === "pr" ? [...args, "--repo", repository] : args, input);
    return new GitHubHost(run, safeGit, repository);
  }
  if (wanted !== "bitbucket-cloud" && wanted !== "bitbucket-dc") throw new UsageError(`Unsupported code host '${wanted}'.`);
  const base = options.bitbucketUrl ?? env.BITBUCKET_URL;
  let repository: string;
  if (wanted === "bitbucket-cloud") {
    if (url.hostname !== "bitbucket.org") throw new UsageError("Bitbucket Cloud does not match origin.");
    repository = url.pathname.replace(/^\//, "");
  } else {
    if (!base) throw new UsageError("Set --bitbucket-url or BITBUCKET_URL for this Bitbucket Data Center origin.");
    let configured: URL;
    try { configured = new URL(base); } catch { throw new UsageError("Invalid Bitbucket server URL."); }
    if (configured.hostname !== url.hostname || (url.protocol !== "ssh:" && configured.origin !== url.origin)) throw new UsageError("The Bitbucket server URL does not match origin.");
    const context = configured.pathname.replace(/\/+$/, "");
    if (url.protocol === "ssh:") repository = url.pathname.replace(/^\//, "");
    else {
      const prefix = `${context}/scm/`;
      if (!url.pathname.startsWith(prefix)) throw new UsageError("The Bitbucket origin must use the configured server's /scm/project/repo clone URL.");
      repository = url.pathname.slice(prefix.length);
    }
  }
  const parts = repository.replace(/\.git$/, "").split("/");
  if (parts.length !== 2 || !parts.every(part => /^(?!\.{1,2}$)[A-Za-z0-9._~-]{1,200}$/.test(part))) throw new UsageError("Invalid Bitbucket origin repository.");
  if (enterpriseMode(env)) {
    if (url.protocol !== "https:") throw new UsageError("Restricted fix publishing requires an allowlisted HTTPS git origin; SSH is not permitted.");
    assertBitbucketDestination(origin, env);
  }
  return new BitbucketHost({ platform: wanted, owner: parts[0]!, repo: parts[1]!, token: env.BITBUCKET_TOKEN ?? "", ...(wanted === "bitbucket-dc" ? { baseUrl: base } : {}), git: safeGit, ...(options.fetch ? { fetch: options.fetch } : {}) });
}
