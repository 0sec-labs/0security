import { Table } from "../db";
import type { Task } from "../models/task";

const table = new Table<Task>("tasks");

export const taskRepo = {
  get: (id: string) => table.get(id),
  listForProject: (projectId: string) => table.where((t) => t.projectId === projectId && !t.parentId),
  children: (parentId: string) => table.where((t) => t.parentId === parentId),
  search: (orgId: string, q: string) => table.where((t) => t.orgId === orgId && `${t.title} ${t.notes}`.toLowerCase().includes(q.toLowerCase())),
  insert: (task: Task) => table.insert(task),
  update: (id: string, patch: Partial<Task>) => table.update(id, patch),
  remove: (id: string) => table.remove(id),
};
