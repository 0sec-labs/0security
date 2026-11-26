import { Table } from "../db";
import type { Component } from "../models/component";

const table = new Table<Component>("components");

export const componentRepo = {
  getInOrg(orgId: string, id: string) {
    const row = table.get(id);
    return row && row.orgId === orgId ? row : undefined;
  },
  listForOrg: (orgId: string) => table.where((r) => r.orgId === orgId),
  insert: (row: Component) => table.insert(row),
  updateInOrg(orgId: string, id: string, patch: Partial<Component>) {
    const row = table.get(id);
    return row && row.orgId === orgId ? table.update(id, patch) : undefined;
  },
  removeInOrg(orgId: string, id: string) {
    const row = table.get(id);
    return row && row.orgId === orgId ? table.remove(id) : false;
  },
};
