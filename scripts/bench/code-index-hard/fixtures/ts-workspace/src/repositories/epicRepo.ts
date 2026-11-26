import { Table } from "../db";
import type { Epic } from "../models/epic";

const table = new Table<Epic>("epics");

export const epicRepo = {
  get: (id: string) => table.get(id),
  listForOrg: (orgId: string) => table.where((r) => r.orgId === orgId),
  insert: (row: Epic) => table.insert(row),
  update: (id: string, patch: Partial<Epic>) => table.update(id, patch),
  remove: (id: string) => table.remove(id),
};
