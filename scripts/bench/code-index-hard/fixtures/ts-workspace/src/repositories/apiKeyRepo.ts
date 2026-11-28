import { Table } from "../db";
import type { ApiKey } from "../models/apiKey";

const table = new Table<ApiKey>("api_keys");

export const apiKeyRepo = {
  get: (id: string) => table.get(id),
  listForOrg: (orgId: string) => table.where((r) => r.orgId === orgId),
  insert: (row: ApiKey) => table.insert(row),
  update: (id: string, patch: Partial<ApiKey>) => table.update(id, patch),
  remove: (id: string) => table.remove(id),
};
