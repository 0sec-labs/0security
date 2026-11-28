import { Table } from "../db";
import type { Note } from "../models/note";

const table = new Table<Note>("notes");

export const noteRepo = {
  get: (id: string) => table.get(id),
  listForOrg: (orgId: string) => table.where((r) => r.orgId === orgId),
  insert: (row: Note) => table.insert(row),
  update: (id: string, patch: Partial<Note>) => table.update(id, patch),
  remove: (id: string) => table.remove(id),
};
