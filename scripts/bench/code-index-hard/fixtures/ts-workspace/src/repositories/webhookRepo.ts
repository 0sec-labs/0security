import { Table } from "../db";
import type { Webhook, WebhookDelivery } from "../models/webhook";

const hooks = new Table<Webhook>("webhooks");
const deliveries = new Table<WebhookDelivery>("webhook_deliveries");

export const webhookRepo = {
  get: (id: string) => hooks.get(id),
  listForOrg: (orgId: string) => hooks.where((h) => h.orgId === orgId),
  insert: (hook: Webhook) => hooks.insert(hook),
  update: (id: string, patch: Partial<Webhook>) => hooks.update(id, patch),
  remove: (id: string) => hooks.remove(id),
  deliveriesFor: (webhookId: string) => deliveries.where((d) => d.webhookId === webhookId),
  addDelivery: (delivery: WebhookDelivery) => deliveries.insert(delivery),
};
