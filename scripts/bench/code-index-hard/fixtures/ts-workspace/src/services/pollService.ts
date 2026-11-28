import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { forbidden, notFound } from "../lib/http";
import { pollRepo } from "../repositories/pollRepo";
import type { PollInput } from "../validators/poll";
import type { User } from "../models/user";

export const pollService = {
  require(user: User, id: string) {
    const row = pollRepo.get(id);
    if (!row || row.orgId !== user.orgId) throw notFound();
    return row;
  },

  requireWritable(user: User, id: string) {
    const row = pollService.require(user, id);
    if (row.ownerId !== user.id && user.role === "member") throw forbidden();
    return row;
  },

  list(user: User) {
    return pollRepo.listForOrg(user.orgId);
  },

  create(user: User, input: PollInput) {
    return pollRepo.insert({ id: newId("poll"), orgId: user.orgId, ownerId: user.id, ...input, createdAt: now() });
  },

  update(user: User, id: string, input: PollInput) {
    const row = pollService.requireWritable(user, id);
    return pollRepo.update(row.id, input);
  },

  remove(user: User, id: string) {
    const row = pollService.requireWritable(user, id);
    pollRepo.remove(row.id);
  },
};
