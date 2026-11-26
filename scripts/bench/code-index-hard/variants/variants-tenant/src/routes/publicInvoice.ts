import { Router } from "express";
import { readShare } from "../lib/shareToken";
import { invoiceRepo } from "../repositories/invoiceRepo";

export const publicRouter = Router();

// Customers open invoices from an emailed link: /public/invoices/<id>?token=<share token>.
publicRouter.get("/invoices/:id", (req, res) => {
  const claims = readShare(String(req.query.token ?? ""));
  if (!claims || claims.inv !== req.params.id) return res.status(404).json({ error: "link not found" });
  const invoice = invoiceRepo.findById(claims.inv);
  if (!invoice || invoice.orgId !== claims.org) return res.status(404).json({ error: "link not found" });
  res.json({ number: invoice.number, status: invoice.status, total: invoice.total, currency: invoice.currency, dueDate: invoice.dueDate });
});
