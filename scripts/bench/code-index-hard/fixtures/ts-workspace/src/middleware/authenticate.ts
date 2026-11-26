import type { NextFunction, Request, Response } from "express";
import { readToken } from "../lib/tokens";
import { userRepo } from "../repositories/userRepo";
import type { User } from "../models/user";

export interface AuthedRequest extends Request {
  user: User;
  org: string;
}

export function authenticate(req: Request, res: Response, next: NextFunction) {
  const header = req.get("authorization") ?? "";
  const userId = header.startsWith("Bearer ") ? readToken(header.slice(7)) : null;
  const user = userId ? userRepo.get(userId) : undefined;
  if (!user) return res.status(401).json({ error: "unauthenticated" });
  (req as AuthedRequest).user = user;
  next();
}
