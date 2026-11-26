import { str } from "../lib/validate";

export interface DashboardInput {
  name: string;
  layout: string;
}

export function parseDashboardInput(body: unknown): DashboardInput {
  const input = (body ?? {}) as Record<string, unknown>;
  return {
    name: str(input.name, 200),
    layout: str(input.layout, 200),
  };
}
