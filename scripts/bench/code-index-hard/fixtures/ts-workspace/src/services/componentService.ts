import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { forbidden, notFound } from "../lib/http";
import { componentRepo } from "../repositories/componentRepo";
import type { ComponentInput } from "../validators/component";
import type { User } from "../models/user";

function requireManager(user: User) {
  if (user.role === "member") throw forbidden();
}

export const componentService = {
  require(user: User, id: string) {
    const row = componentRepo.getInOrg(user.orgId, id);
    if (!row) throw notFound();
    return row;
  },

  list(user: User) {
    return componentRepo.listForOrg(user.orgId);
  },

  create(user: User, input: ComponentInput) {
    requireManager(user);
    return componentRepo.insert({ id: newId("component"), orgId: user.orgId, ownerId: user.id, ...input, createdAt: now() });
  },

  update(user: User, id: string, input: ComponentInput) {
    requireManager(user);
    const row = componentRepo.updateInOrg(user.orgId, id, input);
    if (!row) throw notFound();
    return row;
  },

  remove(user: User, id: string) {
    requireManager(user);
    if (!componentRepo.removeInOrg(user.orgId, id)) throw notFound();
  },
};
