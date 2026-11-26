import { hub } from "./hub";
import type { Session } from "./hub";
import { parseChannel } from "./channels";
import { teamRepo } from "../repositories/teamRepo";
import { ticketCommentRepo, ticketRepo } from "../repositories/ticketRepo";

export interface ClientMessage {
  type?: string;
  channel?: string;
}

export function handleMessage(session: Session, msg: ClientMessage): void {
  if (msg.type === "ping") return hub.reply(session, { type: "pong" });
  if (msg.type === "unsubscribe" && typeof msg.channel === "string") {
    session.channels.delete(msg.channel);
    return;
  }
  if (msg.type !== "subscribe" || typeof msg.channel !== "string") {
    return hub.reply(session, { type: "error", message: "unsupported message" });
  }
  const target = parseChannel(msg.channel);
  if (!target) return hub.reply(session, { type: "error", channel: msg.channel, message: "bad channel" });
  if (target.kind === "ticket") return subscribeTicket(session, msg.channel, target.id);
  if (target.kind === "team") return subscribeTeam(session, msg.channel, target.id);
  hub.reply(session, { type: "error", channel: msg.channel, message: "unknown channel" });
}

function subscribeTicket(session: Session, channel: string, id: string): void {
  const ticket = ticketRepo.findById(id);
  if (!ticket) return hub.reply(session, { type: "error", channel, message: "not found" });
  hub.join(session, channel);
  hub.reply(session, { type: "snapshot", channel, data: { ticket, comments: ticketCommentRepo.forTicket(ticket.id) } });
}

function subscribeTeam(session: Session, channel: string, id: string): void {
  const team = teamRepo.findById(id);
  if (!team || !team.memberIds.includes(session.user.id)) {
    return hub.reply(session, { type: "error", channel, message: "not found" });
  }
  hub.join(session, channel);
  hub.reply(session, { type: "snapshot", channel, data: { team } });
}
