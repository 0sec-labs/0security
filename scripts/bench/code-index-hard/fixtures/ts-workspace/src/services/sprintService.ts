import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { forbidden, notFound } from "../lib/http";
import { sprintRepo } from "../repositories/sprintRepo";
import type { SprintInput } from "../validators/sprint";
import type { User } from "../models/user";

function requireManager(user: User) {
  if (user.role === "member") throw forbidden();
}

export const sprintService = {
  require(user: User, id: string) {
    const row = sprintRepo.getInOrg(user.orgId, id);
    if (!row) throw notFound();
    return row;
  },

  list(user: User) {
    return sprintRepo.listForOrg(user.orgId);
  },

  create(user: User, input: SprintInput) {
    requireManager(user);
    return sprintRepo.insert({ id: newId("sprint"), orgId: user.orgId, ownerId: user.id, ...input, createdAt: now() });
  },

  update(user: User, id: string, input: SprintInput) {
    requireManager(user);
    const row = sprintRepo.updateInOrg(user.orgId, id, input);
    if (!row) throw notFound();
    return row;
  },

  remove(user: User, id: string) {
    requireManager(user);
    if (!sprintRepo.removeInOrg(user.orgId, id)) throw notFound();
  },
};
