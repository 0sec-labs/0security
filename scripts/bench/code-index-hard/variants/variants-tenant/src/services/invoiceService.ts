import { badRequest } from "../lib/errors";
import { isoNow, newId } from "../lib/ids";
import { invoiceRepo } from "../repositories/invoiceRepo";
import { customerRepo } from "../repositories/customerRepo";
import type { AuthUser } from "../models/base";
import type { Invoice, InvoiceLine } from "../models/billing";

function readLines(input: unknown): InvoiceLine[] {
  if (!Array.isArray(input) || input.length === 0) throw badRequest("at least one line is required");
  return input.map((line) => {
    const qty = Number(line?.qty);
    const unitPrice = Number(line?.unitPrice);
    if (!Number.isFinite(qty) || !Number.isFinite(unitPrice) || qty <= 0 || unitPrice < 0) throw badRequest("invalid line");
    return { description: String(line.description ?? "").slice(0, 200), qty, unitPrice };
  });
}

export const invoiceService = {
  create(user: AuthUser, body: any): Invoice {
    const customer = customerRepo.findForOrg(user.orgId, String(body?.customerId ?? ""));
    if (!customer) throw badRequest("unknown customer");
    const lines = readLines(body?.lines);
    const count = invoiceRepo.listForOrg(user.orgId).length + 1;
    return invoiceRepo.insert({
      id: newId("inv"),
      orgId: user.orgId,
      customerId: customer.id,
      number: "INV-" + user.orgId.slice(-1).toUpperCase() + "-" + String(1000 + count),
      status: "draft",
      currency: String(body?.currency ?? "EUR").slice(0, 3).toUpperCase(),
      lines,
      total: lines.reduce((sum, line) => sum + line.qty * line.unitPrice, 0),
      dueDate: String(body?.dueDate ?? ""),
      createdAt: isoNow(),
    });
  },
};
