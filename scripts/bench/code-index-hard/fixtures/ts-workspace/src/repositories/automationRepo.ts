import { Table } from "../db";
import type { Automation } from "../models/automation";

const table = new Table<Automation>("automations");

export const automationRepo = {
  get: (id: string) => table.get(id),
  listForOrg: (orgId: string) => table.where((r) => r.orgId === orgId),
  insert: (row: Automation) => table.insert(row),
  update: (id: string, patch: Partial<Automation>) => table.update(id, patch),
  remove: (id: string) => table.remove(id),
};
