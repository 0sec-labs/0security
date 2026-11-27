import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { forbidden, notFound } from "../lib/http";
import { templateRepo } from "../repositories/templateRepo";
import type { TemplateInput } from "../validators/template";
import type { User } from "../models/user";

export const templateService = {
  require(user: User, id: string) {
    const row = templateRepo.get(id);
    if (!row || row.orgId !== user.orgId) throw notFound();
    return row;
  },

  requireWritable(user: User, id: string) {
    const row = templateService.require(user, id);
    if (row.ownerId !== user.id && user.role === "member") throw forbidden();
    return row;
  },

  list(user: User) {
    return templateRepo.listForOrg(user.orgId);
  },

  create(user: User, input: TemplateInput) {
    return templateRepo.insert({ id: newId("template"), orgId: user.orgId, ownerId: user.id, ...input, archived: false, createdAt: now() });
  },

  update(user: User, id: string, input: TemplateInput) {
    const row = templateService.requireWritable(user, id);
    return templateRepo.update(row.id, input);
  },

  remove(user: User, id: string) {
    const row = templateService.requireWritable(user, id);
    templateRepo.remove(row.id);
  },

  archive(user: User, id: string) {
    const row = templateService.requireWritable(user, id);
    return templateRepo.update(row.id, { archived: true });
  },
};
