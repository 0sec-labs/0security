import { randomBytes } from "node:crypto";
import { newId } from "../lib/ids";
import { notFound } from "../lib/http";
import { webhookRepo } from "../repositories/webhookRepo";
import type { User } from "../models/user";
import type { Webhook } from "../models/webhook";

const summary = (hook: Webhook) => ({ id: hook.id, url: hook.url, events: hook.events, active: hook.active });

export const webhookService = {
  require(user: User, id: string) {
    const hook = webhookRepo.get(id);
    if (!hook || hook.orgId !== user.orgId) throw notFound();
    return hook;
  },

  list(user: User) {
    return webhookRepo.listForOrg(user.orgId).map(summary);
  },

  deliveries(user: User, id: string) {
    const hook = webhookService.require(user, id);
    return webhookRepo.deliveriesFor(hook.id);
  },

  create(user: User, input: { url: string; events?: string[] }) {
    const hook = webhookRepo.insert({ id: newId("whk"), orgId: user.orgId, url: String(input.url), authToken: randomBytes(18).toString("hex"), events: input.events ?? ["task.created"], active: true });
    return { ...summary(hook), authToken: hook.authToken };
  },

  update(user: User, id: string, patch: { url?: string; events?: string[]; active?: boolean }) {
    const hook = webhookService.require(user, id);
    return summary(webhookRepo.update(hook.id, { url: patch.url ?? hook.url, events: patch.events ?? hook.events, active: patch.active ?? hook.active }) as Webhook);
  },

  remove(user: User, id: string) {
    webhookRepo.remove(webhookService.require(user, id).id);
  },

  rotate(user: User, id: string) {
    const hook = webhookService.require(user, id);
    const authToken = randomBytes(18).toString("hex");
    webhookRepo.update(hook.id, { authToken });
    return { id: hook.id, authToken };
  },
};
