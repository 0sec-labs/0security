import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { automationRepo } from "../repositories/automationRepo";
import type { Automation } from "../models/automation";
import type { AutomationInput } from "../validators/automation";

export const automationService = {
  list(orgId: string) {
    return automationRepo.listForOrg(orgId);
  },

  create(orgId: string, ownerId: string, input: AutomationInput) {
    return automationRepo.insert({ id: newId("automation"), orgId: orgId, ownerId: ownerId, ...input, createdAt: now() });
  },

  update(row: Automation, input: AutomationInput) {
    return automationRepo.update(row.id, input);
  },

  remove(row: Automation) {
    automationRepo.remove(row.id);
  },
};
