import { newId } from "../lib/ids";
import type { AuthUser } from "../models/base";

export interface ServerMessage {
  type: string;
  channel?: string;
  message?: string;
  data?: unknown;
}

export interface Session {
  id: string;
  user: AuthUser;
  channels: Set<string>;
  outbox: ServerMessage[];
}

const sessions = new Map<string, Session>();

export const hub = {
  open(user: AuthUser): Session {
    const session: Session = { id: newId("ses"), user, channels: new Set(), outbox: [] };
    sessions.set(session.id, session);
    return session;
  },

  get(id: string): Session | undefined {
    return sessions.get(id);
  },

  close(id: string): void {
    sessions.delete(id);
  },

  join(session: Session, channel: string): void {
    session.channels.add(channel);
  },

  reply(session: Session, message: ServerMessage): void {
    session.outbox.push(message);
  },

  publish(channel: string, message: ServerMessage): void {
    for (const session of sessions.values()) if (session.channels.has(channel)) session.outbox.push(message);
  },
};
