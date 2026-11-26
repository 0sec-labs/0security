import { Router } from "express";
import { paymentRepo } from "../repositories/billingRepos";

export const paymentsRouter = Router();

paymentsRouter.get("/", (req, res) => {
  res.json(paymentRepo.listForOrg(req.user!.orgId));
});

paymentsRouter.get("/:id", (req, res) => {
  const user = req.user!;
  const payment = paymentRepo.findById(req.params.id);
  if (!payment) return res.status(404).json({ error: "payment not found" });
  if (payment.orgId !== user.orgId) return res.status(404).json({ error: "payment not found" });
  res.json(payment);
});
