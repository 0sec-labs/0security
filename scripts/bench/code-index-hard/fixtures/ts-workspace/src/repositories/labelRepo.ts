import { Table } from "../db";
import type { Label } from "../models/label";

const table = new Table<Label>("labels");

export const labelRepo = {
  get: (id: string) => table.get(id),
  listForOrg: (orgId: string) => table.where((r) => r.orgId === orgId),
  insert: (row: Label) => table.insert(row),
  update: (id: string, patch: Partial<Label>) => table.update(id, patch),
  remove: (id: string) => table.remove(id),
};
