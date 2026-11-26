import { Table } from "../db";
import type { Dashboard } from "../models/dashboard";

const table = new Table<Dashboard>("dashboards");

export const dashboardRepo = {
  get: (id: string) => table.get(id),
  listForOrg: (orgId: string) => table.where((r) => r.orgId === orgId),
  insert: (row: Dashboard) => table.insert(row),
  update: (id: string, patch: Partial<Dashboard>) => table.update(id, patch),
  remove: (id: string) => table.remove(id),
};
