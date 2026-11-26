import { Table } from "../db";
import type { Invoice } from "../models/invoice";

const table = new Table<Invoice>("invoices");

export const invoiceRepo = {
  get: (id: string) => table.get(id),
  listForOrg: (orgId: string) => table.where((i) => i.orgId === orgId),
  insert: (invoice: Invoice) => table.insert(invoice),
  update: (id: string, patch: Partial<Invoice>) => table.update(id, patch),
};
