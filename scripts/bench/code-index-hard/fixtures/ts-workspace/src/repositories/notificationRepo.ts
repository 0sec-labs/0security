import { Table } from "../db";
import type { Notification } from "../models/notification";

const table = new Table<Notification>("notifications");

export const notificationRepo = {
  get: (id: string) => table.get(id),
  listForOrg: (orgId: string) => table.where((r) => r.orgId === orgId),
  insert: (row: Notification) => table.insert(row),
  update: (id: string, patch: Partial<Notification>) => table.update(id, patch),
  remove: (id: string) => table.remove(id),
};
