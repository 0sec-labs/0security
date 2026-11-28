import { Router } from "express";
import { invoiceRepo } from "../repositories/invoiceRepo";

// Mounted behind the service token; used by the billing workers.
export const internalRouter = Router();

internalRouter.get("/invoices/:id", (req, res) => {
  const invoice = invoiceRepo.findById(req.params.id);
  if (!invoice) return res.status(404).json({ error: "invoice not found" });
  res.json(invoice);
});

internalRouter.get("/orgs/:orgId/usage", (req, res) => {
  res.json({ orgId: req.params.orgId, invoices: invoiceRepo.listForOrg(req.params.orgId).length });
});
