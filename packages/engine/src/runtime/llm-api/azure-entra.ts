import { readFileSync } from "node:fs";
import { assertEgressAllowed } from "../../policy/enterprise.js";

/**
 * Microsoft Entra ID tokens for Azure OpenAI, with no stored key.
 *
 * Opt in with `AZURE_OPENAI_AUTH=entra`. The token comes from the identity of
 * the machine or pod, in this order:
 *  1. Workload identity (`AZURE_FEDERATED_TOKEN_FILE`, `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`).
 *  2. A managed identity endpoint injected by the host (`IDENTITY_ENDPOINT`, `IDENTITY_HEADER`).
 *  3. The instance metadata service of an Azure VM.
 *
 * Tokens live in memory only. Errors never include response bodies, token
 * values or the assertion file contents.
 */

export const AZURE_AUTH_ENV = "AZURE_OPENAI_AUTH";
/** Stand-in for the API key so the rest of the runtime sees a configured provider. It is not a secret. */
export const AZURE_ENTRA_PLACEHOLDER = "entra-id";

const SCOPE_RESOURCE = "https://cognitiveservices.azure.com";
const DEFAULT_AUTHORITY = "https://login.microsoftonline.com";
const IMDS_URL = "http://169.254.169.254/metadata/identity/oauth2/token";
const REQUEST_TIMEOUT_MS = 5000;
/** Refresh this long before expiry. */
const EXPIRY_SKEW_MS = 5 * 60 * 1000;
const FALLBACK_LIFETIME_MS = 30 * 60 * 1000;

export type AzureEntraSource = "workload-identity" | "managed-identity-endpoint" | "instance-metadata";

export function azureEntraEnabled(env: Readonly<NodeJS.ProcessEnv>): boolean {
  return env[AZURE_AUTH_ENV]?.trim().toLowerCase() === "entra";
}

export function azureEntraSource(env: Readonly<NodeJS.ProcessEnv>): AzureEntraSource {
  if (env.AZURE_FEDERATED_TOKEN_FILE && env.AZURE_CLIENT_ID && env.AZURE_TENANT_ID) return "workload-identity";
  if (env.IDENTITY_ENDPOINT && env.IDENTITY_HEADER) return "managed-identity-endpoint";
  return "instance-metadata";
}

interface TokenResponse {
  access_token?: unknown;
  expires_in?: unknown;
  expires_on?: unknown;
}

function expiryOf(body: TokenResponse, now: number): number {
  const inSeconds = Number(body.expires_in);
  if (Number.isFinite(inSeconds) && inSeconds > 0) return now + inSeconds * 1000;
  const on = Number(body.expires_on);
  if (Number.isFinite(on) && on > 1e9) return on * 1000;
  return now + FALLBACK_LIFETIME_MS;
}

function authorityOf(env: Readonly<NodeJS.ProcessEnv>): string {
  const configured = env.AZURE_AUTHORITY_HOST?.trim();
  // Enterprise mode only talks to an identity authority the operator named.
  if (!configured) assertEgressAllowed("login.microsoftonline.com (Entra token)", env as NodeJS.ProcessEnv);
  const url = new URL(configured || DEFAULT_AUTHORITY);
  if (url.protocol !== "https:") throw new Error("AZURE_AUTHORITY_HOST must be an https URL.");
  return url.origin;
}

function localEndpoint(raw: string, name: string): URL {
  const url = new URL(raw);
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error(`${name} must be an http or https URL.`);
  return url;
}

export interface AzureEntraOptions {
  env?: Readonly<NodeJS.ProcessEnv>;
  fetchImpl?: typeof fetch;
  now?: () => number;
}

export interface AzureEntraTokenProvider {
  getToken(signal?: AbortSignal): Promise<string>;
}

export function createAzureEntraTokenProvider(options: AzureEntraOptions = {}): AzureEntraTokenProvider {
  const env = options.env ?? process.env;
  const doFetch = options.fetchImpl ?? fetch;
  const now = options.now ?? Date.now;
  let cached: { token: string; expiresAt: number } | undefined;
  let inflight: Promise<{ token: string; expiresAt: number }> | undefined;

  async function request(url: URL, init: RequestInit, signal?: AbortSignal): Promise<TokenResponse> {
    const timeout = AbortSignal.timeout(REQUEST_TIMEOUT_MS);
    const res = await doFetch(url, { ...init, redirect: "error", signal: signal ? AbortSignal.any([signal, timeout]) : timeout });
    if (!res.ok) throw new Error(`Entra ID token request failed with HTTP ${res.status}. Check the identity's access to the Azure OpenAI resource.`);
    return await res.json() as TokenResponse;
  }

  async function fetchToken(signal?: AbortSignal): Promise<{ token: string; expiresAt: number }> {
    const source = azureEntraSource(env);
    let body: TokenResponse;
    try {
      if (source === "workload-identity") {
        const assertion = readFileSync(env.AZURE_FEDERATED_TOKEN_FILE as string, "utf8").trim();
        const form = new URLSearchParams({
          client_id: env.AZURE_CLIENT_ID as string,
          scope: `${SCOPE_RESOURCE}/.default`,
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          client_assertion: assertion,
          grant_type: "client_credentials",
        });
        const url = new URL(`${authorityOf(env)}/${encodeURIComponent(env.AZURE_TENANT_ID as string)}/oauth2/v2.0/token`);
        body = await request(url, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: form }, signal);
      } else if (source === "managed-identity-endpoint") {
        const url = localEndpoint(env.IDENTITY_ENDPOINT as string, "IDENTITY_ENDPOINT");
        url.searchParams.set("api-version", "2019-08-01");
        url.searchParams.set("resource", SCOPE_RESOURCE);
        if (env.AZURE_CLIENT_ID) url.searchParams.set("client_id", env.AZURE_CLIENT_ID);
        body = await request(url, { method: "GET", headers: { "X-IDENTITY-HEADER": env.IDENTITY_HEADER as string } }, signal);
      } else {
        const url = new URL(IMDS_URL);
        url.searchParams.set("api-version", "2018-02-01");
        url.searchParams.set("resource", SCOPE_RESOURCE);
        if (env.AZURE_CLIENT_ID) url.searchParams.set("client_id", env.AZURE_CLIENT_ID);
        body = await request(url, { method: "GET", headers: { Metadata: "true" } }, signal);
      }
    } catch (error) {
      if (error instanceof Error && /^(?:Entra ID|AZURE_|IDENTITY_)/.test(error.message)) throw error;
      if (error instanceof Error && error.name === "EnterpriseEgressError") throw error;
      throw new Error(`Entra ID token request via ${source} failed. Check the identity setup for Azure OpenAI.`);
    }
    if (typeof body.access_token !== "string" || body.access_token.length === 0) {
      throw new Error("Entra ID token response had no access token.");
    }
    return { token: body.access_token, expiresAt: expiryOf(body, now()) };
  }

  return {
    async getToken(signal) {
      if (cached && cached.expiresAt - EXPIRY_SKEW_MS > now()) return cached.token;
      inflight ??= fetchToken(signal).then(
        (value) => { cached = value; inflight = undefined; return value; },
        (error) => { inflight = undefined; throw error; },
      );
      return (await inflight).token;
    },
  };
}
