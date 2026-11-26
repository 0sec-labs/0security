import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { orders, users } from "../db";

export function loadUser(req: Request, _res: Response, next: NextFunction) {
  const token = (req.get("authorization") || "").replace(/^Bearer /, "");
  try { (req as any).user = users.get((jwt.verify(token, process.env.JWT_SECRET as string) as any).sub); } catch { /* anonymous */ }
  next();
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (!(req as any).user) return res.sendStatus(401);
  next();
}

export function requireRole(role: "admin") {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!(req as any).user || (req as any).user.role !== role) return res.sendStatus(403);
    next();
  };
}

export function requireOrderOwner(req: Request, res: Response, next: NextFunction) {
  const order = orders.get(req.params.id);
  if (!order) return res.sendStatus(404);
  if (order.userId !== (req as any).user.id) return res.sendStatus(404);
  (req as any).order = order;
  next();
}
