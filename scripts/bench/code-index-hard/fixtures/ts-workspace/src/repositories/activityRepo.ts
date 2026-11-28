import { Table } from "../db";
import type { Activity } from "../models/activity";

const table = new Table<Activity>("activity");

export const activityRepo = {
  all: () => table.all(),
  forEntity: (entity: string, entityId: string) => table.where((a) => a.entity === entity && a.entityId === entityId),
  insert: (entry: Activity) => table.insert(entry),
};
