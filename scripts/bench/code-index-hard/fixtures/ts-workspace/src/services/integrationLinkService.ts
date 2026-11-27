import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { forbidden, notFound } from "../lib/http";
import { integrationLinkRepo } from "../repositories/integrationLinkRepo";
import type { IntegrationLinkInput } from "../validators/integrationLink";
import type { User } from "../models/user";

function requireManager(user: User) {
  if (user.role === "member") throw forbidden();
}

export const integrationLinkService = {
  require(user: User, id: string) {
    const row = integrationLinkRepo.getInOrg(user.orgId, id);
    if (!row) throw notFound();
    return row;
  },

  list(user: User) {
    return integrationLinkRepo.listForOrg(user.orgId);
  },

  create(user: User, input: IntegrationLinkInput) {
    requireManager(user);
    return integrationLinkRepo.insert({ id: newId("integration-link"), orgId: user.orgId, ownerId: user.id, ...input, createdAt: now() });
  },

  update(user: User, id: string, input: IntegrationLinkInput) {
    requireManager(user);
    const row = integrationLinkRepo.updateInOrg(user.orgId, id, input);
    if (!row) throw notFound();
    return row;
  },

  remove(user: User, id: string) {
    requireManager(user);
    if (!integrationLinkRepo.removeInOrg(user.orgId, id)) throw notFound();
  },
};
