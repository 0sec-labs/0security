import { Table } from "../db";
import type { Approval } from "../models/approval";

const table = new Table<Approval>("approvals");

export const approvalRepo = {
  get: (id: string) => table.get(id),
  listForOrg: (orgId: string) => table.where((r) => r.orgId === orgId),
  insert: (row: Approval) => table.insert(row),
  update: (id: string, patch: Partial<Approval>) => table.update(id, patch),
  remove: (id: string) => table.remove(id),
};
