import { Table } from "../db";
import type { TimeEntry } from "../models/timeEntry";

const table = new Table<TimeEntry>("time_entries");

export const timeEntryRepo = {
  forTask: (taskId: string) => table.where((t) => t.taskId === taskId),
  insert: (entry: TimeEntry) => table.insert(entry),
};
