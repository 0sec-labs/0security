import { Router } from "express";
import { subscriptionRepo } from "../repositories/subscriptionRepo";
import { requireRole } from "../middleware/requireRole";

export const subscriptionsRouter = Router();

subscriptionsRouter.get("/", (req, res) => {
  res.json(subscriptionRepo.listForOrg(req.user!.orgId));
});

subscriptionsRouter.get("/:id", (req, res) => {
  const subscription = subscriptionRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!subscription) return res.status(404).json({ error: "subscription not found" });
  res.json(subscription);
});

subscriptionsRouter.post("/:id/cancel", requireRole("admin"), (req, res) => {
  const subscription = subscriptionRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!subscription) return res.status(404).json({ error: "subscription not found" });
  res.json(subscriptionRepo.save({ ...subscription, status: "cancelled" }));
});
