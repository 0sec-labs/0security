import { Table } from "../db";
import type { Release } from "../models/release";

const table = new Table<Release>("releases");

export const releaseRepo = {
  get: (id: string) => table.get(id),
  listForOrg: (orgId: string) => table.where((r) => r.orgId === orgId),
  insert: (row: Release) => table.insert(row),
  update: (id: string, patch: Partial<Release>) => table.update(id, patch),
  remove: (id: string) => table.remove(id),
};
