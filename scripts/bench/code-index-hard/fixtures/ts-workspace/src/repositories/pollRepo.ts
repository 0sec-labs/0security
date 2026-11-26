import { Table } from "../db";
import type { Poll } from "../models/poll";

const table = new Table<Poll>("polls");

export const pollRepo = {
  get: (id: string) => table.get(id),
  listForOrg: (orgId: string) => table.where((r) => r.orgId === orgId),
  insert: (row: Poll) => table.insert(row),
  update: (id: string, patch: Partial<Poll>) => table.update(id, patch),
  remove: (id: string) => table.remove(id),
};
