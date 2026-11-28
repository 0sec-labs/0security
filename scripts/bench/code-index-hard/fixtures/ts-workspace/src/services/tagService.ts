import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { forbidden, notFound } from "../lib/http";
import { tagRepo } from "../repositories/tagRepo";
import type { TagInput } from "../validators/tag";
import type { User } from "../models/user";

function requireManager(user: User) {
  if (user.role === "member") throw forbidden();
}

export const tagService = {
  require(user: User, id: string) {
    const row = tagRepo.getInOrg(user.orgId, id);
    if (!row) throw notFound();
    return row;
  },

  list(user: User) {
    return tagRepo.listForOrg(user.orgId);
  },

  create(user: User, input: TagInput) {
    requireManager(user);
    return tagRepo.insert({ id: newId("tag"), orgId: user.orgId, ownerId: user.id, ...input, archived: false, createdAt: now() });
  },

  update(user: User, id: string, input: TagInput) {
    requireManager(user);
    const row = tagRepo.updateInOrg(user.orgId, id, input);
    if (!row) throw notFound();
    return row;
  },

  remove(user: User, id: string) {
    requireManager(user);
    if (!tagRepo.removeInOrg(user.orgId, id)) throw notFound();
  },

  archive(user: User, id: string) {
    requireManager(user);
    const row = tagRepo.updateInOrg(user.orgId, id, { archived: true });
    if (!row) throw notFound();
    return row;
  },
};
