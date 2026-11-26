import { Table } from "../db";
import type { Timesheet } from "../models/timesheet";

const table = new Table<Timesheet>("timesheets");

export const timesheetRepo = {
  get: (id: string) => table.get(id),
  listForOrg: (orgId: string) => table.where((r) => r.orgId === orgId),
  insert: (row: Timesheet) => table.insert(row),
  update: (id: string, patch: Partial<Timesheet>) => table.update(id, patch),
  remove: (id: string) => table.remove(id),
};
