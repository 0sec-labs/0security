import { Router } from "express";
import { requireAuth } from "../middleware/auth";
import { users } from "../db";

export const profileRouter = Router();

profileRouter.put("/users/:id/profile", requireAuth, (req, res) => {
  const user = (req as any).user;
  if (user.id !== req.params.id) return res.sendStatus(403);
  const target = users.get(user.id)!;
  target.email = String(req.body.email);
  res.json(target);
});
