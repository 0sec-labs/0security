import type { NextFunction, Request, Response } from "express";
import type { AuthedRequest } from "./authenticate";

// The active organisation is the caller's own unless a platform admin asks for another one.
export function resolveOrg(req: Request, res: Response, next: NextFunction) {
  const authed = req as AuthedRequest;
  const requested = req.get("x-org-id");
  if (requested && requested !== authed.user.orgId && authed.user.role !== "admin") {
    return res.status(403).json({ error: "not a member of that organisation" });
  }
  authed.org = requested ?? authed.user.orgId;
  next();
}
