import { timingSafeEqual } from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import { env } from "../config/env";

export function requireServiceToken(req: Request, res: Response, next: NextFunction) {
  const given = Buffer.from(req.get("x-service-token") ?? "");
  const wanted = Buffer.from(env.serviceToken);
  if (given.length !== wanted.length || !timingSafeEqual(given, wanted)) {
    return res.status(401).json({ error: "service token required" });
  }
  next();
}
