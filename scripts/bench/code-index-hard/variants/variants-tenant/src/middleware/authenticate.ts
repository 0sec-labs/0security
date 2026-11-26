import type { NextFunction, Request, Response } from "express";
import { verifyToken } from "../lib/token";
import { userRepo } from "../repositories/userRepo";

export function authenticate(req: Request, res: Response, next: NextFunction) {
  const match = /^Bearer (.+)$/.exec(req.headers.authorization ?? "");
  const claims = match ? verifyToken(match[1]) : null;
  if (!claims) return res.status(401).json({ error: "unauthenticated" });
  const user = userRepo.findById(claims.sub);
  if (!user || user.disabled) return res.status(401).json({ error: "unauthenticated" });
  req.user = { id: user.id, orgId: user.orgId, role: user.role };
  next();
}
