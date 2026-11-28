import { Table } from "../db";
import type { CustomField } from "../models/customField";

const table = new Table<CustomField>("custom_fields");

export const customFieldRepo = {
  get: (id: string) => table.get(id),
  listForOrg: (orgId: string) => table.where((r) => r.orgId === orgId),
  insert: (row: CustomField) => table.insert(row),
  update: (id: string, patch: Partial<CustomField>) => table.update(id, patch),
  remove: (id: string) => table.remove(id),
};
