import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { forbidden, notFound } from "../lib/http";
import { labelRepo } from "../repositories/labelRepo";
import type { LabelInput } from "../validators/label";
import type { User } from "../models/user";

export const labelService = {
  require(user: User, id: string) {
    const row = labelRepo.get(id);
    if (!row || row.orgId !== user.orgId) throw notFound();
    return row;
  },

  requireWritable(user: User, id: string) {
    const row = labelService.require(user, id);
    if (row.ownerId !== user.id && user.role === "member") throw forbidden();
    return row;
  },

  list(user: User) {
    return labelRepo.listForOrg(user.orgId);
  },

  create(user: User, input: LabelInput) {
    return labelRepo.insert({ id: newId("label"), orgId: user.orgId, ownerId: user.id, ...input, createdAt: now() });
  },

  update(user: User, id: string, input: LabelInput) {
    const row = labelService.requireWritable(user, id);
    return labelRepo.update(row.id, input);
  },

  remove(user: User, id: string) {
    const row = labelService.requireWritable(user, id);
    labelRepo.remove(row.id);
  },
};
