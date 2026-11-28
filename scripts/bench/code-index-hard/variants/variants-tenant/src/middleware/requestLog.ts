import type { NextFunction, Request, Response } from "express";

export const accessLog: string[] = [];

export function requestLog(req: Request, res: Response, next: NextFunction) {
  res.on("finish", () => {
    accessLog.push(req.method + " " + req.path + " " + res.statusCode);
    if (accessLog.length > 500) accessLog.shift();
  });
  next();
}
