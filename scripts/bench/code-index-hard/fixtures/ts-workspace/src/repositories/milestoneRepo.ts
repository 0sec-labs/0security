import { Table } from "../db";
import type { Milestone } from "../models/milestone";

const table = new Table<Milestone>("milestones");

export const milestoneRepo = {
  get: (id: string) => table.get(id),
  listForOrg: (orgId: string) => table.where((r) => r.orgId === orgId),
  insert: (row: Milestone) => table.insert(row),
  update: (id: string, patch: Partial<Milestone>) => table.update(id, patch),
  remove: (id: string) => table.remove(id),
};
