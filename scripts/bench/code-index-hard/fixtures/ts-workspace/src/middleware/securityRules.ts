import type { NextFunction, Request, Response } from "express";
import { urlRules } from "../config/security";
import type { AuthedRequest } from "./authenticate";

export function securityRules(req: Request, res: Response, next: NextFunction) {
  const path = req.originalUrl.split("?")[0];
  const rule = urlRules.find((candidate) => path.startsWith(candidate.prefix));
  if (rule && !rule.roles.includes((req as AuthedRequest).user.role)) {
    return res.status(403).json({ error: "forbidden" });
  }
  next();
}
