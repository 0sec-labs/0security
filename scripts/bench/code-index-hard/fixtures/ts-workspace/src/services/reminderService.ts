import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { reminderRepo } from "../repositories/reminderRepo";
import type { Reminder } from "../models/reminder";
import type { ReminderInput } from "../validators/reminder";

export const reminderService = {
  list(orgId: string) {
    return reminderRepo.listForOrg(orgId);
  },

  create(orgId: string, ownerId: string, input: ReminderInput) {
    return reminderRepo.insert({ id: newId("reminder"), orgId: orgId, ownerId: ownerId, ...input, createdAt: now() });
  },

  update(row: Reminder, input: ReminderInput) {
    return reminderRepo.update(row.id, input);
  },

  remove(row: Reminder) {
    reminderRepo.remove(row.id);
  },
};
