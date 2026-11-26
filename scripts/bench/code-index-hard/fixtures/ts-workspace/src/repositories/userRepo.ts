import { Table } from "../db";
import type { User } from "../models/user";

const table = new Table<User>("users");

export const userRepo = {
  get: (id: string) => table.get(id),
  byEmail: (email: string) => table.where((u) => u.email === email.toLowerCase())[0],
  all: () => table.all(),
  forOrg: (orgId: string) => table.where((u) => u.orgId === orgId),
  insert: (user: User) => table.insert(user),
  update: (id: string, patch: Partial<User>) => table.update(id, patch),
};
