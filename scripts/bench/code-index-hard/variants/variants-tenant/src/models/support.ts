import type { OrgRecord } from "./base";

export interface Ticket extends OrgRecord {
  customerId: string;
  subject: string;
  body: string;
  status: "open" | "pending" | "closed";
  priority: "low" | "normal" | "high";
  createdAt: string;
}

export interface TicketComment extends OrgRecord {
  ticketId: string;
  authorId: string;
  body: string;
  createdAt: string;
}

export interface Team extends OrgRecord {
  name: string;
  memberIds: string[];
}
