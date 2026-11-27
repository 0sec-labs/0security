import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { approvalRepo } from "../repositories/approvalRepo";
import type { Approval } from "../models/approval";
import type { ApprovalInput } from "../validators/approval";

export const approvalService = {
  list(orgId: string) {
    return approvalRepo.listForOrg(orgId);
  },

  create(orgId: string, ownerId: string, input: ApprovalInput) {
    return approvalRepo.insert({ id: newId("approval"), orgId: orgId, ownerId: ownerId, ...input, createdAt: now() });
  },

  update(row: Approval, input: ApprovalInput) {
    return approvalRepo.update(row.id, input);
  },

  remove(row: Approval) {
    approvalRepo.remove(row.id);
  },
};
