import { Router } from "express";
import { requireAuth, requireRole } from "../middleware/auth";
import { users } from "../db";

export const adminRouter = Router();

adminRouter.get("/admin/users", requireAuth, requireRole("admin"), (_req, res) => {
  res.json([...users.values()]);
});

adminRouter.post("/admin/users/:id/role", requireAuth, (req, res) => {
  const user = users.get(req.params.id);
  if (!user) return res.sendStatus(404);
  user.role = req.body.role;
  res.json(user);
});

adminRouter.delete("/admin/users/:id", requireAuth, requireRole("admin"), (req, res) => {
  users.delete(req.params.id);
  res.sendStatus(204);
});
