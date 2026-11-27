import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { customFieldRepo } from "../repositories/customFieldRepo";
import type { CustomField } from "../models/customField";
import type { CustomFieldInput } from "../validators/customField";

export const customFieldService = {
  list(orgId: string) {
    return customFieldRepo.listForOrg(orgId);
  },

  create(orgId: string, ownerId: string, input: CustomFieldInput) {
    return customFieldRepo.insert({ id: newId("custom-field"), orgId: orgId, ownerId: ownerId, ...input, archived: false, createdAt: now() });
  },

  update(row: CustomField, input: CustomFieldInput) {
    return customFieldRepo.update(row.id, input);
  },

  remove(row: CustomField) {
    customFieldRepo.remove(row.id);
  },

  archive(row: CustomField) {
    return customFieldRepo.update(row.id, { archived: true });
  },
};
