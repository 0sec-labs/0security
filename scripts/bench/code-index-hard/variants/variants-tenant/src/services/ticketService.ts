import { notFound } from "../lib/errors";
import { isoNow, newId } from "../lib/ids";
import { hub } from "../ws/hub";
import { ticketCommentRepo, ticketRepo } from "../repositories/ticketRepo";
import type { AuthUser } from "../models/base";
import type { Ticket, TicketComment } from "../models/support";

export const ticketService = {
  list(user: AuthUser): Ticket[] {
    return ticketRepo.listForOrg(user.orgId);
  },

  get(user: AuthUser, id: string): { ticket: Ticket; comments: TicketComment[] } {
    const ticket = ticketRepo.findForOrg(user.orgId, id);
    if (!ticket) throw notFound("ticket");
    return { ticket, comments: ticketCommentRepo.forTicket(ticket.id) };
  },

  comment(user: AuthUser, id: string, body: string): TicketComment {
    const ticket = ticketRepo.findForOrg(user.orgId, id);
    if (!ticket) throw notFound("ticket");
    const comment = ticketCommentRepo.insert({
      id: newId("tcm"),
      orgId: user.orgId,
      ticketId: ticket.id,
      authorId: user.id,
      body: body.slice(0, 2000),
      createdAt: isoNow(),
    });
    hub.publish("ticket:" + ticket.id, { type: "comment", channel: "ticket:" + ticket.id, data: comment });
    return comment;
  },
};
