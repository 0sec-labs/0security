import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { forbidden, notFound } from "../lib/http";
import { checklistRepo } from "../repositories/checklistRepo";
import type { ChecklistInput } from "../validators/checklist";
import type { User } from "../models/user";

function requireManager(user: User) {
  if (user.role === "member") throw forbidden();
}

export const checklistService = {
  require(user: User, id: string) {
    const row = checklistRepo.getInOrg(user.orgId, id);
    if (!row) throw notFound();
    return row;
  },

  list(user: User) {
    return checklistRepo.listForOrg(user.orgId);
  },

  create(user: User, input: ChecklistInput) {
    requireManager(user);
    return checklistRepo.insert({ id: newId("checklist"), orgId: user.orgId, ownerId: user.id, ...input, archived: false, createdAt: now() });
  },

  update(user: User, id: string, input: ChecklistInput) {
    requireManager(user);
    const row = checklistRepo.updateInOrg(user.orgId, id, input);
    if (!row) throw notFound();
    return row;
  },

  remove(user: User, id: string) {
    requireManager(user);
    if (!checklistRepo.removeInOrg(user.orgId, id)) throw notFound();
  },

  archive(user: User, id: string) {
    requireManager(user);
    const row = checklistRepo.updateInOrg(user.orgId, id, { archived: true });
    if (!row) throw notFound();
    return row;
  },
};
