import { Router } from "express";
import { refundRepo } from "../repositories/billingRepos";
import { refundPolicy } from "../lib/policy";

export const refundsRouter = Router();

refundsRouter.get("/", (req, res) => {
  res.json(refundRepo.listForOrg(req.user!.orgId));
});

refundsRouter.get("/:id", (req, res) => {
  const refund = refundRepo.findById(req.params.id);
  if (!refund || !refundPolicy.canView(req.user!, refund)) return res.status(404).json({ error: "refund not found" });
  res.json(refund);
});
