import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { forbidden, notFound } from "../lib/http";
import { apiKeyRepo } from "../repositories/apiKeyRepo";
import type { ApiKeyInput } from "../validators/apiKey";
import type { User } from "../models/user";

export const apiKeyService = {
  require(user: User, id: string) {
    const row = apiKeyRepo.get(id);
    if (!row || row.orgId !== user.orgId) throw notFound();
    return row;
  },

  requireWritable(user: User, id: string) {
    const row = apiKeyService.require(user, id);
    if (row.ownerId !== user.id && user.role === "member") throw forbidden();
    return row;
  },

  list(user: User) {
    return apiKeyRepo.listForOrg(user.orgId);
  },

  create(user: User, input: ApiKeyInput) {
    return apiKeyRepo.insert({ id: newId("api-key"), orgId: user.orgId, ownerId: user.id, ...input, createdAt: now() });
  },

  update(user: User, id: string, input: ApiKeyInput) {
    const row = apiKeyService.requireWritable(user, id);
    return apiKeyRepo.update(row.id, input);
  },

  remove(user: User, id: string) {
    const row = apiKeyService.requireWritable(user, id);
    apiKeyRepo.remove(row.id);
  },
};
