import { Table } from "../db";
import type { Reminder } from "../models/reminder";

const table = new Table<Reminder>("reminders");

export const reminderRepo = {
  get: (id: string) => table.get(id),
  listForOrg: (orgId: string) => table.where((r) => r.orgId === orgId),
  insert: (row: Reminder) => table.insert(row),
  update: (id: string, patch: Partial<Reminder>) => table.update(id, patch),
  remove: (id: string) => table.remove(id),
};
