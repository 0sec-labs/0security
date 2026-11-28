import { Repo } from "../lib/store";
import type { Invoice } from "../models/billing";

class InvoiceRepo extends Repo<Invoice> {
  listOpenForOrg(orgId: string): Invoice[] {
    return this.listForOrg(orgId).filter((invoice) => invoice.status === "open");
  }
}

export const invoiceRepo = new InvoiceRepo("invoice");
