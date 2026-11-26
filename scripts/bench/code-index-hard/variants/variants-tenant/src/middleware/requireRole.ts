import type { NextFunction, Request, Response } from "express";
import type { Role } from "../models/base";

export function requireRole(...roles: Role[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user || !roles.includes(req.user.role)) return res.status(403).json({ error: "insufficient role" });
    next();
  };
}
