import { notFound } from "../lib/http";
import { invoiceRepo } from "../repositories/invoiceRepo";
import type { User } from "../models/user";

export const invoiceService = {
  get(user: User, id: string) {
    const invoice = invoiceRepo.get(id);
    if (!invoice || invoice.orgId !== user.orgId) throw notFound();
    return invoice;
  },

  list(user: User) {
    return invoiceRepo.listForOrg(user.orgId);
  },

  markSent(user: User, id: string) {
    const invoice = invoiceService.get(user, id);
    return invoiceRepo.update(invoice.id, { status: "sent" });
  },

  getById(id: string) {
    const invoice = invoiceRepo.get(id);
    if (!invoice) throw notFound();
    return invoice;
  },

  publicView(id: string) {
    const invoice = invoiceService.getById(id);
    return { number: invoice.number, customer: invoice.customer, amountCents: invoice.amountCents, status: invoice.status, lines: invoice.lines };
  },
};
