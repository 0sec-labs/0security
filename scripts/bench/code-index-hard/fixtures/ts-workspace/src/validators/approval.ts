import { str } from "../lib/validate";

export interface ApprovalInput {
  subject: string;
  state: string;
}

export function parseApprovalInput(body: unknown): ApprovalInput {
  const input = (body ?? {}) as Record<string, unknown>;
  return {
    subject: str(input.subject, 200),
    state: str(input.state, 200),
  };
}
