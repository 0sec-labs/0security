import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { forbidden, notFound } from "../lib/http";
import { noteRepo } from "../repositories/noteRepo";
import type { NoteInput } from "../validators/note";
import type { User } from "../models/user";

export const noteService = {
  require(user: User, id: string) {
    const row = noteRepo.get(id);
    if (!row || row.orgId !== user.orgId) throw notFound();
    return row;
  },

  requireWritable(user: User, id: string) {
    const row = noteService.require(user, id);
    if (row.ownerId !== user.id && user.role === "member") throw forbidden();
    return row;
  },

  list(user: User) {
    return noteRepo.listForOrg(user.orgId);
  },

  create(user: User, input: NoteInput) {
    return noteRepo.insert({ id: newId("note"), orgId: user.orgId, ownerId: user.id, ...input, archived: false, createdAt: now() });
  },

  update(user: User, id: string, input: NoteInput) {
    const row = noteService.requireWritable(user, id);
    return noteRepo.update(row.id, input);
  },

  remove(user: User, id: string) {
    const row = noteService.requireWritable(user, id);
    noteRepo.remove(row.id);
  },

  archive(user: User, id: string) {
    const row = noteService.requireWritable(user, id);
    return noteRepo.update(row.id, { archived: true });
  },
};
