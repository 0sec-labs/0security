import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { forbidden, notFound } from "../lib/http";
import { epicRepo } from "../repositories/epicRepo";
import type { EpicInput } from "../validators/epic";
import type { User } from "../models/user";

export const epicService = {
  require(user: User, id: string) {
    const row = epicRepo.get(id);
    if (!row || row.orgId !== user.orgId) throw notFound();
    return row;
  },

  requireWritable(user: User, id: string) {
    const row = epicService.require(user, id);
    if (row.ownerId !== user.id && user.role === "member") throw forbidden();
    return row;
  },

  list(user: User) {
    return epicRepo.listForOrg(user.orgId);
  },

  create(user: User, input: EpicInput) {
    return epicRepo.insert({ id: newId("epic"), orgId: user.orgId, ownerId: user.id, ...input, createdAt: now() });
  },

  update(user: User, id: string, input: EpicInput) {
    const row = epicService.requireWritable(user, id);
    return epicRepo.update(row.id, input);
  },

  remove(user: User, id: string) {
    const row = epicService.requireWritable(user, id);
    epicRepo.remove(row.id);
  },
};
