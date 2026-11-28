import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { notificationRepo } from "../repositories/notificationRepo";
import type { Notification } from "../models/notification";
import type { NotificationInput } from "../validators/notification";

export const notificationService = {
  list(orgId: string) {
    return notificationRepo.listForOrg(orgId);
  },

  create(orgId: string, ownerId: string, input: NotificationInput) {
    return notificationRepo.insert({ id: newId("notification"), orgId: orgId, ownerId: ownerId, ...input, archived: false, createdAt: now() });
  },

  update(row: Notification, input: NotificationInput) {
    return notificationRepo.update(row.id, input);
  },

  remove(row: Notification) {
    notificationRepo.remove(row.id);
  },

  archive(row: Notification) {
    return notificationRepo.update(row.id, { archived: true });
  },
};
