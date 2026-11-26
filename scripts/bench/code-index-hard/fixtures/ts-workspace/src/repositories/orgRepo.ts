import { Table } from "../db";
import type { Org } from "../models/org";

const table = new Table<Org>("orgs");

export const orgRepo = {
  get: (id: string) => table.get(id),
  all: () => table.all(),
  insert: (org: Org) => table.insert(org),
};
