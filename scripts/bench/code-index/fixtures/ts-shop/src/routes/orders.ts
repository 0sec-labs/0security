import { Router } from "express";
import { requireAuth, requireOrderOwner } from "../middleware/auth";
import { orders } from "../db";
import { cancelOrder } from "../services/orderService";

export const ordersRouter = Router();

ordersRouter.get("/orders", requireAuth, (req, res) => {
  const mine = [...orders.values()].filter((o) => o.userId === (req as any).user.id);
  res.json(mine);
});

ordersRouter.get("/orders/:id", requireAuth, (req, res) => {
  const order = orders.get(req.params.id);
  if (!order) return res.sendStatus(404);
  res.json(order);
});

ordersRouter.post("/orders/:id/cancel", requireAuth, requireOrderOwner, (req, res) => {
  res.json(cancelOrder((req as any).order));
});
