import { Repo } from "../lib/store";
import type { Ticket, TicketComment } from "../models/support";

export const ticketRepo = new Repo<Ticket>("ticket");

class CommentRepo extends Repo<TicketComment> {
  forTicket(ticketId: string): TicketComment[] {
    return [...this.rows.values()].filter((comment) => comment.ticketId === ticketId);
  }
}

export const ticketCommentRepo = new CommentRepo("ticketComment");
