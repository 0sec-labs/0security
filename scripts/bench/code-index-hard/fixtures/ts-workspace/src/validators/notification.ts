import { str } from "../lib/validate";

export interface NotificationInput {
  title: string;
  channel: string;
}

export function parseNotificationInput(body: unknown): NotificationInput {
  const input = (body ?? {}) as Record<string, unknown>;
  return {
    title: str(input.title, 200),
    channel: str(input.channel, 200),
  };
}
