import { describe, expect, it } from "vitest";
import { arrangeCatalog, providerLabel } from "../model-picker";
import { modelRows } from "./models-model";
import { credentialOrigin, healthBadge } from "@/console/provider-health";

describe("Bedrock selection metadata", () => {
  it("keeps an explicitly configured Bedrock model selectable without a made-up tariff", () => {
    const model = { id: "eu.vendor.model:0", provider: "bedrock", price: "Unknown rate", source: "public-catalog" as const };
    const provider = { id: "bedrock", label: "Amazon Bedrock", configured: true, source: "aws-credential-chain", health: { state: "unknown" as const } };
    expect(providerLabel("bedrock")).toBe("Amazon Bedrock");
    expect(arrangeCatalog({ models: [model], providers: [provider] }).groups[0]).toMatchObject({ id: "bedrock", label: "Amazon Bedrock", models: [model] });
    expect(modelRows([model], [provider])[0]).toMatchObject({ disabled: false, detail: "Unknown rate" });
    expect(healthBadge(provider, true)).toEqual({ label: "AWS chain · unverified", tone: "neutral" });
    expect(credentialOrigin(provider, false)).toContain("service access unverified");
  });
});
