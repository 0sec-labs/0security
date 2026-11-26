import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { WebOperatorServices, createWebConsoleRuntime } from "./operator-services.js";
import { loadConnectionConfigs } from "./connection-config.js";
import { PROVIDERS } from "../state/provider-status.js";
import { reloadSettings } from "../state/settings-store.js";
vi.mock("../state/model-catalog-sync.js", async original => ({ ...await original<typeof import("../state/model-catalog-sync.js")>(), syncModelCatalog: async () => null }));
let home: string;
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "0-bedrock-ui-")); vi.stubEnv("HOME", home); vi.stubEnv("ZERO_HOME", join(home, ".0"));
  for (const info of PROVIDERS) for (const key of info.envVars) vi.stubEnv(key, undefined);
  for (const key of ["BEDROCK_BASE_URL", "ZERO_BEDROCK_MODEL", "ZERO_MODEL", "ZERO_SELECTED_PROVIDER", "ZERO_FORCE_PROVIDER", "ZERO_WORKBENCH_PROVIDER_PROXY", "ZERO_WORKBENCH_PROVIDER_PROXY_TOKEN"]) vi.stubEnv(key, undefined);
  vi.stubEnv("ZERO_SUPPRESS_PROVIDER_STARTUP_LOG", "1"); vi.stubEnv("ZERO_LLM_FALLBACK", "");
  reloadSettings();
});
afterEach(() => { vi.unstubAllEnvs(); vi.restoreAllMocks(); reloadSettings(); rmSync(home, { recursive: true, force: true }); });
describe("native Bedrock browser configuration", () => {
  it("saves only non-secret configuration and restores a priced picker row without AWS requests", async () => {
    const fetcher = vi.spyOn(globalThis, "fetch").mockImplementation(async () => { throw new Error("must stay offline"); });
    const service = new WebOperatorServices();
    const model = "eu.anthropic.claude-sonnet-4-5-20250929-v1:0";
    const saved = await service.handle("/api/console/connections", "POST", { providerId: "bedrock", action: "configure", region: "eu-central-1", model }, new URLSearchParams());
    expect(saved?.status).toBe(200);
    expect(loadConnectionConfigs().bedrock).toEqual({ region: "eu-central-1", model });
    const provider = (saved!.data as any).providers.find((item: any) => item.id === "bedrock");
    expect(provider).toMatchObject({ methods: ["aws-chain"], configured: true, source: "aws-credential-chain", health: { state: "unknown", checking: false }, configuration: { region: "eu-central-1", model } });
    const inventory = await service.handle("/api/console/models", "GET", undefined, new URLSearchParams("providerId=bedrock&fresh=1"));
    expect(inventory?.data).toMatchObject({ models: [{ id: model, provider: "bedrock", price: "$3/15 per M", source: "configured" }], diagnostics: [] });
    const configuredRuntime = await createWebConsoleRuntime({ providerId: "bedrock", singleModel: true });
    expect(configuredRuntime.runtime.resolvedModel()).toBe(model);
    const selected = await service.handle("/api/console/models/preference", "PATCH", { providerId: "bedrock", model }, new URLSearchParams());
    expect(selected?.status).toBe(200);
    const { runtime } = await createWebConsoleRuntime({ providerId: "bedrock", model, singleModel: true });
    expect(runtime.resolvedProvider()).toBe("bedrock"); expect(runtime.resolvedModel()).toBe(model);
    expect(fetcher).not.toHaveBeenCalled();
    expect(readFileSync(join(home, ".0", "web-connections.json"), "utf8")).not.toMatch(/ACCESS_KEY|SECRET|TOKEN/);
  });
  it("never returns AWS credential values and refuses browser credential submissions", async () => {
    vi.stubEnv("AWS_REGION", "eu-central-1"); vi.stubEnv("AWS_ACCESS_KEY_ID", "synthetic-access"); vi.stubEnv("AWS_SECRET_ACCESS_KEY", "synthetic-secret"); vi.stubEnv("AWS_SESSION_TOKEN", "synthetic-session");
    const service = new WebOperatorServices();
    const result = await service.handle("/api/console/providers", "GET", undefined, new URLSearchParams());
    expect(JSON.stringify(result?.data)).not.toMatch(/synthetic-(access|secret|session)/);
    for (const action of ["connect", "configure"]) {
      const rejected = await service.handle("/api/console/connections", "POST", { providerId: "bedrock", action, apiKey: "synthetic-browser-key", region: "eu-central-1" }, new URLSearchParams());
      expect(rejected?.status).toBe(400);
    }
  });
});
