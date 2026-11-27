import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { forbidden, notFound } from "../lib/http";
import { releaseRepo } from "../repositories/releaseRepo";
import type { ReleaseInput } from "../validators/release";
import type { User } from "../models/user";

export const releaseService = {
  require(user: User, id: string) {
    const row = releaseRepo.get(id);
    if (!row || row.orgId !== user.orgId) throw notFound();
    return row;
  },

  requireWritable(user: User, id: string) {
    const row = releaseService.require(user, id);
    if (row.ownerId !== user.id && user.role === "member") throw forbidden();
    return row;
  },

  list(user: User) {
    return releaseRepo.listForOrg(user.orgId);
  },

  create(user: User, input: ReleaseInput) {
    return releaseRepo.insert({ id: newId("release"), orgId: user.orgId, ownerId: user.id, ...input, archived: false, createdAt: now() });
  },

  update(user: User, id: string, input: ReleaseInput) {
    const row = releaseService.requireWritable(user, id);
    return releaseRepo.update(row.id, input);
  },

  remove(user: User, id: string) {
    const row = releaseService.requireWritable(user, id);
    releaseRepo.remove(row.id);
  },

  archive(user: User, id: string) {
    const row = releaseService.requireWritable(user, id);
    return releaseRepo.update(row.id, { archived: true });
  },
};
