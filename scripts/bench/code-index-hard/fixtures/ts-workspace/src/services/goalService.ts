import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { forbidden, notFound } from "../lib/http";
import { goalRepo } from "../repositories/goalRepo";
import type { GoalInput } from "../validators/goal";
import type { User } from "../models/user";

function requireManager(user: User) {
  if (user.role === "member") throw forbidden();
}

export const goalService = {
  require(user: User, id: string) {
    const row = goalRepo.getInOrg(user.orgId, id);
    if (!row) throw notFound();
    return row;
  },

  list(user: User) {
    return goalRepo.listForOrg(user.orgId);
  },

  create(user: User, input: GoalInput) {
    requireManager(user);
    return goalRepo.insert({ id: newId("goal"), orgId: user.orgId, ownerId: user.id, ...input, archived: false, createdAt: now() });
  },

  update(user: User, id: string, input: GoalInput) {
    requireManager(user);
    const row = goalRepo.updateInOrg(user.orgId, id, input);
    if (!row) throw notFound();
    return row;
  },

  remove(user: User, id: string) {
    requireManager(user);
    if (!goalRepo.removeInOrg(user.orgId, id)) throw notFound();
  },

  archive(user: User, id: string) {
    requireManager(user);
    const row = goalRepo.updateInOrg(user.orgId, id, { archived: true });
    if (!row) throw notFound();
    return row;
  },
};
