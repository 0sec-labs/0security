import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LlmApiRuntime } from "../llm-api.js";
import { azureEntraEnabled, azureEntraSource, createAzureEntraTokenProvider } from "./azure-entra.js";
import { detectProvider } from "./provider-detect.js";

// Response bodies follow the documented shapes:
//  - Entra client-credentials v2 token response:
//    https://learn.microsoft.com/entra/identity-platform/v2-oauth2-client-creds-grant-flow#successful-response
//  - Azure VM instance metadata token response (expires_in and expires_on are strings):
//    https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/how-to-use-vm-token
const ENTRA_BODY = { token_type: "Bearer", expires_in: 3599, ext_expires_in: 3599, access_token: "synthetic-entra-token" };
const IMDS_BODY = { access_token: "synthetic-imds-token", client_id: "00000000-0000-0000-0000-000000000000", expires_in: "86400", expires_on: "1506484173", ext_expires_in: "86400", not_before: "1506397473", resource: "https://cognitiveservices.azure.com", token_type: "Bearer" };

const fixtures = mkdtempSync(join(tmpdir(), "azure-entra-test-"));
const assertionFile = join(fixtures, "federated-token");
writeFileSync(assertionFile, "synthetic-assertion\n");

const wiEnv = { AZURE_OPENAI_AUTH: "entra", AZURE_FEDERATED_TOKEN_FILE: assertionFile, AZURE_CLIENT_ID: "client-1", AZURE_TENANT_ID: "tenant-1", AZURE_AUTHORITY_HOST: "https://login.example.test/" };

describe("azure entra token provider", () => {
  it("selects the identity source from the environment", () => {
    expect(azureEntraEnabled({ AZURE_OPENAI_AUTH: " Entra " })).toBe(true);
    expect(azureEntraEnabled({ AZURE_OPENAI_AUTH: "key" })).toBe(false);
    expect(azureEntraSource(wiEnv)).toBe("workload-identity");
    expect(azureEntraSource({ IDENTITY_ENDPOINT: "http://127.0.0.1:42356/msi/token", IDENTITY_HEADER: "h" })).toBe("managed-identity-endpoint");
    expect(azureEntraSource({})).toBe("instance-metadata");
  });

  it("exchanges the federated assertion for a token (workload identity)", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(Response.json(ENTRA_BODY));
    const token = await createAzureEntraTokenProvider({ env: wiEnv, fetchImpl }).getToken();
    expect(token).toBe("synthetic-entra-token");
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(String(url)).toBe("https://login.example.test/tenant-1/oauth2/v2.0/token");
    expect(init?.method).toBe("POST");
    expect(Object.fromEntries(new URLSearchParams(String(init?.body)))).toEqual({
      client_id: "client-1",
      scope: "https://cognitiveservices.azure.com/.default",
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: "synthetic-assertion",
      grant_type: "client_credentials",
    });
  });

  it("reads the instance metadata service with the Metadata header", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(Response.json(IMDS_BODY));
    const token = await createAzureEntraTokenProvider({ env: { AZURE_OPENAI_AUTH: "entra", AZURE_CLIENT_ID: "uami-1" }, fetchImpl }).getToken();
    expect(token).toBe("synthetic-imds-token");
    const [url, init] = fetchImpl.mock.calls[0]!;
    const parsed = new URL(String(url));
    expect(parsed.origin + parsed.pathname).toBe("http://169.254.169.254/metadata/identity/oauth2/token");
    expect(parsed.searchParams.get("resource")).toBe("https://cognitiveservices.azure.com");
    expect(parsed.searchParams.get("client_id")).toBe("uami-1");
    expect(new Headers(init?.headers).get("Metadata")).toBe("true");
  });

  it("uses the host-injected managed identity endpoint", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(Response.json(IMDS_BODY));
    await createAzureEntraTokenProvider({ env: { AZURE_OPENAI_AUTH: "entra", IDENTITY_ENDPOINT: "http://127.0.0.1:42356/msi/token", IDENTITY_HEADER: "synthetic-header" }, fetchImpl }).getToken();
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(String(url)).toContain("http://127.0.0.1:42356/msi/token?api-version=2019-08-01");
    expect(new Headers(init?.headers).get("X-IDENTITY-HEADER")).toBe("synthetic-header");
  });

  it("caches until shortly before expiry, then refreshes", async () => {
    let clock = 0;
    const fetchImpl = vi.fn<typeof fetch>().mockImplementation(async () => Response.json({ access_token: `t${fetchImpl.mock.calls.length}`, expires_in: 3600 }));
    const provider = createAzureEntraTokenProvider({ env: wiEnv, fetchImpl, now: () => clock });
    expect(await provider.getToken()).toBe("t1");
    clock = 3000 * 1000;
    expect(await provider.getToken()).toBe("t1");
    clock = 3400 * 1000;
    expect(await provider.getToken()).toBe("t2");
  });

  it("shares one request between concurrent callers", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockImplementation(async () => Response.json(ENTRA_BODY));
    const provider = createAzureEntraTokenProvider({ env: wiEnv, fetchImpl });
    await Promise.all([provider.getToken(), provider.getToken(), provider.getToken()]);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("fails with a message that holds no response body or secret", async () => {
    const body = JSON.stringify({ error: "invalid_client", error_description: "AADSTS700024: leaked-detail" });
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(new Response(body, { status: 401 }));
    const error = await createAzureEntraTokenProvider({ env: wiEnv, fetchImpl }).getToken().catch((e: Error) => e);
    expect((error as Error).message).toContain("HTTP 401");
    expect((error as Error).message).not.toContain("leaked-detail");
  });

  it("rejects a response without an access token", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(Response.json({ token_type: "Bearer" }));
    await expect(createAzureEntraTokenProvider({ env: wiEnv, fetchImpl }).getToken()).rejects.toThrow(/no access token/);
  });

  it("hides transport errors behind a fixed message", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockRejectedValue(new Error("connect ECONNREFUSED 10.0.0.1 with synthetic-assertion"));
    const error = await createAzureEntraTokenProvider({ env: wiEnv, fetchImpl }).getToken().catch((e: Error) => e);
    expect((error as Error).message).toContain("workload-identity");
    expect((error as Error).message).not.toContain("synthetic-assertion");
  });

  it("refuses the public authority under ZERO_ENTERPRISE unless the operator named one", async () => {
    const env = { ...wiEnv, ZERO_ENTERPRISE: "1", AZURE_AUTHORITY_HOST: "" };
    const fetchImpl = vi.fn<typeof fetch>();
    await expect(createAzureEntraTokenProvider({ env, fetchImpl }).getToken()).rejects.toThrow(/ZERO_ENTERPRISE/);
    expect(fetchImpl).not.toHaveBeenCalled();
    fetchImpl.mockResolvedValue(Response.json(ENTRA_BODY));
    const named = { ...env, AZURE_AUTHORITY_HOST: "https://login.example.test" };
    await expect(createAzureEntraTokenProvider({ env: named, fetchImpl }).getToken()).resolves.toBe("synthetic-entra-token");
  });

  it("requires an https authority", async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    const env = { ...wiEnv, AZURE_AUTHORITY_HOST: "http://login.example.test" };
    await expect(createAzureEntraTokenProvider({ env, fetchImpl }).getToken()).rejects.toThrow(/https/);
  });
});

describe("azure openai with entra id through the runtime", () => {
  beforeEach(() => {
    for (const key of Object.keys(process.env)) {
      if (/^(?:ZERO_|OPENAI_|OPENROUTER_|ANTHROPIC_|AZURE_|DEEPSEEK_|Z_AI_|KIMI_|QWEN_|XAI_|OPENCODE_|TOGETHER_|IDENTITY_)/.test(key)) vi.stubEnv(key, undefined);
    }
  });
  afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks(); });

  const env = { ...wiEnv, AZURE_OPENAI_BASE_URL: "https://tenant-resource.openai.azure.com/openai/v1", AZURE_OPENAI_MODEL: "gpt-deploy", AZURE_OPENAI_WIRE_API: "chat_completions", ZERO_LLM_FALLBACK: "", ZERO_SUPPRESS_PROVIDER_STARTUP_LOG: "1", ZERO_CODEX_AUTH_JSON_PATH: "/nonexistent/0-test/auth.json" };

  it("detects azure with no key when entra is on", () => {
    const detected = detectProvider(undefined, "gpt-deploy", env, "azure");
    expect(detected.provider).toBe("azure");
  });

  it("sends the bearer token and no api-key header, and reuses the token", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (url) => {
      if (String(url).startsWith("https://login.example.test/")) return Response.json(ENTRA_BODY);
      return Response.json({ choices: [{ message: { content: "ok" }, finish_reason: "stop" }], usage: { prompt_tokens: 3, completion_tokens: 1 } });
    });
    vi.stubGlobal("fetch", fetchMock);
    const rt = new LlmApiRuntime({ type: "api", timeout: 1000, provider: "azure", model: "gpt-deploy", env });
    const msgs = [{ role: "user" as const, content: [{ type: "text" as const, text: "hi" }] }];
    await rt.executeNative("sys", msgs, []);
    await rt.executeNative("sys", msgs, []);
    const model = fetchMock.mock.calls.filter(([u]) => String(u).startsWith("https://tenant-resource.openai.azure.com/"));
    const tokenCalls = fetchMock.mock.calls.filter(([u]) => String(u).startsWith("https://login.example.test/"));
    expect(model).toHaveLength(2);
    expect(tokenCalls).toHaveLength(1);
    const headers = new Headers(model[0]![1]?.headers);
    expect(headers.get("Authorization")).toBe("Bearer synthetic-entra-token");
    expect(headers.has("api-key")).toBe(false);
  });
});
