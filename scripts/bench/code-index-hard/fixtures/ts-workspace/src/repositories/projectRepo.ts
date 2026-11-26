import { Table } from "../db";
import type { Project } from "../models/project";

const table = new Table<Project>("projects");

export const projectRepo = {
  get: (id: string) => table.get(id),
  listForOrg: (orgId: string) => table.where((p) => p.orgId === orgId),
  search: (orgId: string, q: string) => table.where((p) => p.orgId === orgId && p.name.toLowerCase().includes(q.toLowerCase())),
  insert: (project: Project) => table.insert(project),
  update: (id: string, patch: Partial<Project>) => table.update(id, patch),
  remove: (id: string) => table.remove(id),
};
