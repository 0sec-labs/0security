/**
 * `0 findings upload <file> --to https://findings.example.com`: send a SARIF log or the findings JSON from
 * `0 scan --format json` to a shared findings server you run. The destination is the one you named; the key comes
 * from ZERO_FINDINGS_API_KEY (a `write:findings` key from `0 findings keys create --scope write`).
 */
import { UNTRUSTED_GIT_BASE_CONFIG } from "@0/engine";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { UsageError } from "./output.js";

const exec = promisify(execFile);
type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; body: string; redirect: "manual"; signal?: AbortSignal }) => Promise<{ ok: boolean; status: number; text(): Promise<string> }>;
export const FINDINGS_API_KEY_ENV = "ZERO_FINDINGS_API_KEY";
const KEY = /^0_find_[A-Za-z0-9_-]{43}$/;
const REPO = /^[A-Za-z0-9._-]{1,100}(?:\/[A-Za-z0-9._-]{1,100}){1,2}$/;

export interface ServerUploadOptions { to: string; repo?: string; source?: string; commit?: string; ref?: string; allowInsecureHttp?: boolean; includeOutOfScope?: boolean }
export interface ServerUploadDeps {
  /** HTTP; tests replace it. */
  fetch?: FetchLike;
  env?: Record<string, string | undefined>;
  git(args: string[]): Promise<string>;
}
export const serverUploadDefaults: Pick<ServerUploadDeps, "git"> = { git: async args => (await exec("git", [...UNTRUSTED_GIT_BASE_CONFIG, ...args], { timeout: 10_000 })).stdout };

export interface ServerUploadResult { repo: string; source: string; format: string; total: number; created: number; known: number; alreadyImported: boolean }

/** `owner/name` from a git remote URL such as https://host/owner/name.git or git@host:owner/name.git. */
export function repoFromRemote(remote: string): string | undefined {
  const match = /[:/]([A-Za-z0-9._-]+\/[A-Za-z0-9._-]+?)(?:\.git)?\/?$/.exec(remote.trim());
  return match?.[1];
}

export function isServerTarget(to: string | undefined): boolean {
  return typeof to === "string" && /^https?:\/\//i.test(to);
}

export function ingestEndpoint(to: string, allowInsecureHttp = false): URL {
  let base: URL;
  try { base = new URL(to); } catch { throw new UsageError("--to is not a valid URL."); }
  if (base.username || base.password) throw new UsageError("Put no credentials in the URL; the key comes from the environment.");
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(base.hostname);
  if (base.protocol === "http:" && !loopback && !allowInsecureHttp) throw new UsageError("Refusing to send the key over plaintext HTTP. Use an https:// URL, or pass --allow-insecure-http for a network you trust.");
  base.search = ""; base.hash = "";
  if (!base.pathname.endsWith("/")) base.pathname += "/";
  return new URL("api/v1/findings/ingest", base);
}

/** The text is sent as it is; the server reads SARIF 2.1.0 and findings JSON. Nothing in the file is run. */
export async function runServerUpload(text: string, options: ServerUploadOptions, deps: ServerUploadDeps = serverUploadDefaults): Promise<ServerUploadResult> {
  const env = deps.env ?? process.env;
  const key = (env[FINDINGS_API_KEY_ENV] ?? "").trim();
  if (!key) throw new UsageError(`Set ${FINDINGS_API_KEY_ENV} to a write key (0security findings keys create <name> --scope write on the server).`);
  if (!KEY.test(key)) throw new UsageError(`${FINDINGS_API_KEY_ENV} is not a findings API key.`);
  const endpoint = ingestEndpoint(options.to, options.allowInsecureHttp);

  const remote = options.repo ?? env.GITHUB_REPOSITORY ?? repoFromRemote(await deps.git(["remote", "get-url", "origin"]).catch(() => ""));
  if (!remote || !REPO.test(remote)) throw new UsageError("Name the repository with --repo owner/name (or run this inside its clone).");
  const commit = (options.commit || env.GITHUB_SHA || (await deps.git(["rev-parse", "HEAD"]).catch(() => ""))).trim();
  let ref = options.ref || env.GITHUB_REF || "";
  if (!ref) { const branch = (await deps.git(["rev-parse", "--abbrev-ref", "HEAD"]).catch(() => "")).trim(); ref = branch && branch !== "HEAD" ? branch : ""; }
  endpoint.searchParams.set("repo", remote);
  if (options.source) endpoint.searchParams.set("source", options.source);
  if (/^[0-9a-f]{7,64}$/i.test(commit)) endpoint.searchParams.set("commit", commit);
  if (ref && /^[A-Za-z0-9._/@+-]{1,200}$/.test(ref)) endpoint.searchParams.set("ref", ref);

  const send = deps.fetch ?? ((url, init) => fetch(url, init));
  let response;
  try {
    response = await send(endpoint.toString(), { method: "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" }, body: text, redirect: "manual", signal: AbortSignal.timeout(120_000) });
  } catch (error) {
    throw new Error(`Could not reach ${endpoint.host}: ${error instanceof Error ? error.message : String(error)}`);
  }
  const raw = await response.text();
  let body: Record<string, unknown> = {};
  try { body = JSON.parse(raw) as Record<string, unknown>; } catch { /* Not JSON. */ }
  if (!response.ok) {
    const reason = typeof body.error === "string" ? body.error : raw.slice(0, 200) || `HTTP ${response.status}`;
    throw new Error(`The server refused the upload (${response.status}): ${reason}`);
  }
  return {
    repo: String(body.repo ?? remote), source: String(body.source ?? ""), format: String(body.format ?? ""),
    total: Number(body.total ?? 0), created: Number(body.created ?? 0), known: Number(body.known ?? 0), alreadyImported: body.alreadyImported === true,
  };
}
