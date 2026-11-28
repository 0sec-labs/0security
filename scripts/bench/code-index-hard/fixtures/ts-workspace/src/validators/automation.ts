import { bool, str } from "../lib/validate";

export interface AutomationInput {
  name: string;
  trigger: string;
  enabled: boolean;
}

export function parseAutomationInput(body: unknown): AutomationInput {
  const input = (body ?? {}) as Record<string, unknown>;
  return {
    name: str(input.name, 200),
    trigger: str(input.trigger, 200),
    enabled: bool(input.enabled),
  };
}
