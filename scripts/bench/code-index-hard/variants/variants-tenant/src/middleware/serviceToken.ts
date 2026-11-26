import type { NextFunction, Request, Response } from "express";
import { config } from "../lib/config";
import { safeEqual } from "../lib/hmac";

// Internal callers (billing workers, the support console) present a shared service token.
export function serviceToken(req: Request, res: Response, next: NextFunction) {
  const presented = String(req.headers["x-service-token"] ?? "");
  if (!presented || !safeEqual(presented, config.serviceToken)) return res.status(401).json({ error: "service token required" });
  next();
}
