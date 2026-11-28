import { Router } from "express";
import { readShareToken } from "../lib/tokens";
import { notFound } from "../lib/http";
import { invoiceService } from "../services/invoiceService";

export const publicRouter = Router();

publicRouter.get("/status", (_req, res) => {
  res.json({ ok: true, version: "2.4.0" });
});

publicRouter.get("/invoices/:token", (req, res) => {
  const claim = readShareToken(req.params.token);
  if (!claim || claim.kind !== "invoice" || claim.expiresAt < Math.floor(Date.now() / 1000)) throw notFound();
  res.json(invoiceService.publicView(claim.id));
});
