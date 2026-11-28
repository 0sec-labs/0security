import { notFound } from "../lib/http";
import { invoiceRepo } from "../repositories/invoiceRepo";
import { orgRepo } from "../repositories/orgRepo";
import { userRepo } from "../repositories/userRepo";

export const billingService = {
  planFor(orgId: string) {
    const org = orgRepo.get(orgId);
    if (!org) throw notFound();
    return { plan: org.plan, seats: org.seats, renewsAt: org.renewsAt, paymentMethodLast4: org.paymentMethodLast4 };
  },

  invoicesFor(orgId: string) {
    return invoiceRepo.listForOrg(orgId).map((i) => ({ id: i.id, number: i.number, amountCents: i.amountCents, status: i.status }));
  },

  usageFor(orgId: string) {
    const org = orgRepo.get(orgId);
    if (!org) throw notFound();
    return { seatsUsed: userRepo.forOrg(orgId).length, seats: org.seats };
  },
};
