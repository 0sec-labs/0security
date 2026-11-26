import type { NextFunction, Request, Response } from "express";
import type { Role } from "../config/security";
import type { AuthedRequest } from "./authenticate";

const rank: Record<Role, number> = { member: 1, manager: 2, admin: 3 };

export function requireOrgRole(minimum: Role) {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = (req as AuthedRequest).user;
    if (rank[user.role] < rank[minimum]) return res.status(403).json({ error: "forbidden" });
    next();
  };
}
