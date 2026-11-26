import { Router } from "express";
import { userRepo } from "../repositories/userRepo";

export const meRouter = Router();

meRouter.get("/", (req, res) => {
  const me = userRepo.findById(req.user!.id);
  if (!me) return res.status(404).json({ error: "user not found" });
  res.json({ id: me.id, orgId: me.orgId, email: me.email, name: me.name, role: me.role });
});

meRouter.put("/", (req, res) => {
  const me = userRepo.findById(req.user!.id);
  if (!me) return res.status(404).json({ error: "user not found" });
  const name = typeof req.body?.name === "string" ? req.body.name.slice(0, 80) : me.name;
  userRepo.save({ ...me, name });
  res.json({ id: me.id, name });
});
