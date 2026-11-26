import { Router } from "express";
import type { Request } from "express";
import { notFound } from "../lib/errors";
import { webhookEndpointRepo } from "../repositories/financeRepos";
import type { WebhookEndpoint } from "../models/finance";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { newId, isoNow } from "../lib/ids";

const FIELDS = ["url", "events", "active"] as const;
const REQUIRED = ["url"] as const;

export const webhookEndpointsRouter = Router();

// Loads the record and checks that it belongs to the caller's organisation.
function load(req: Request): WebhookEndpoint {
  const record = webhookEndpointRepo.findById(req.params.id as string);
  if (!record || record.orgId !== req.user!.orgId) throw notFound("webhook endpoint");
  return record;
}

webhookEndpointsRouter.get("/", (req, res) => {
  res.json(webhookEndpointRepo.listForOrg(req.user!.orgId));
});

webhookEndpointsRouter.post("/", (req, res) => {
  const data = pick(req.body, FIELDS);
  requireFields(data, REQUIRED);
  const record = webhookEndpointRepo.insert({ ...data, id: newId("whe"), orgId: req.user!.orgId, createdAt: isoNow() } as WebhookEndpoint);
  res.status(201).json(record);
});

webhookEndpointsRouter.get("/:id", (req, res) => {
  res.json(load(req));
});

webhookEndpointsRouter.put("/:id", (req, res) => {
  res.json(webhookEndpointRepo.save({ ...load(req), ...pick(req.body, FIELDS) }));
});

webhookEndpointsRouter.delete("/:id", requireRole("admin"), (req, res) => {
  webhookEndpointRepo.remove(load(req).id);
  res.status(204).end();
});
