import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { activityRepo } from "../repositories/activityRepo";
import type { User } from "../models/user";

export const activityService = {
  record(user: User, entity: string, entityId: string, action: string, detail = "") {
    return activityRepo.insert({ id: newId("act"), orgId: user.orgId, entity, entityId, actorId: user.id, action, detail, at: now() });
  },

  forEntity(entity: string, entityId: string) {
    return activityRepo.forEntity(entity, entityId).sort((a, b) => b.at.localeCompare(a.at));
  },
};
