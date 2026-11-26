import { Router } from "express";
import { requireAuth } from "../middleware/auth";
import { orders } from "../db";
import { issueRefund } from "../services/orderService";

export const refundsRouter = Router();

refundsRouter.post("/orders/:id/refund", requireAuth, (req, res) => {
  const order = orders.get(req.params.id);
  if (!order) return res.sendStatus(404);
  const amount = Number(req.body.amountCents);
  res.json(issueRefund(order, amount));
});
