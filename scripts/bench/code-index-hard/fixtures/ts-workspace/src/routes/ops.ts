import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";

export const opsRouter = Router();

const flags = { betaBoards: true, newSearch: false };

opsRouter.get("/flags", (req, res) => {
  if ((req as AuthedRequest).user.role !== "admin") return res.status(403).json({ error: "forbidden" });
  res.json(flags);
});
