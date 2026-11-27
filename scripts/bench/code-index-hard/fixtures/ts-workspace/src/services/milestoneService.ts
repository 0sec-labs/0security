import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { milestoneRepo } from "../repositories/milestoneRepo";
import type { Milestone } from "../models/milestone";
import type { MilestoneInput } from "../validators/milestone";

export const milestoneService = {
  list(orgId: string) {
    return milestoneRepo.listForOrg(orgId);
  },

  create(orgId: string, ownerId: string, input: MilestoneInput) {
    return milestoneRepo.insert({ id: newId("milestone"), orgId: orgId, ownerId: ownerId, ...input, archived: false, createdAt: now() });
  },

  update(row: Milestone, input: MilestoneInput) {
    return milestoneRepo.update(row.id, input);
  },

  remove(row: Milestone) {
    milestoneRepo.remove(row.id);
  },

  archive(row: Milestone) {
    return milestoneRepo.update(row.id, { archived: true });
  },
};
