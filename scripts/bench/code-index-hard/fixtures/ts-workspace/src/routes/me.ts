import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { userRepo } from "../repositories/userRepo";
import { cleanName } from "../lib/sanitize";

export const meRouter = Router();

meRouter.get("/", (req, res) => {
  const { id, orgId, name, email, role } = (req as AuthedRequest).user;
  res.json({ id, orgId, name, email, role });
});

meRouter.put("/", (req, res) => {
  const user = (req as AuthedRequest).user;
  const updated = userRepo.update(user.id, { name: cleanName(String(req.body?.name ?? user.name)) });
  res.json({ id: user.id, name: updated?.name });
});
