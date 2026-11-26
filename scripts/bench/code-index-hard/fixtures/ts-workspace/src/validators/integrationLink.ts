import { str } from "../lib/validate";

export interface IntegrationLinkInput {
  provider: string;
  externalId: string;
}

export function parseIntegrationLinkInput(body: unknown): IntegrationLinkInput {
  const input = (body ?? {}) as Record<string, unknown>;
  return {
    provider: str(input.provider, 200),
    externalId: str(input.externalId, 200),
  };
}
