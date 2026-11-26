import { Table } from "../db";
import type { Template } from "../models/template";

const table = new Table<Template>("templates");

export const templateRepo = {
  get: (id: string) => table.get(id),
  listForOrg: (orgId: string) => table.where((r) => r.orgId === orgId),
  insert: (row: Template) => table.insert(row),
  update: (id: string, patch: Partial<Template>) => table.update(id, patch),
  remove: (id: string) => table.remove(id),
};
