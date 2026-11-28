import { Router } from "express";
import { invoiceRepo } from "../repositories/invoiceRepo";
import { invoiceService } from "../services/invoiceService";
import { signShare } from "../lib/shareToken";
import { assertSameOrg } from "../lib/policy";
import { pick } from "../lib/validate";
import { requireRole } from "../middleware/requireRole";

export const invoicesRouter = Router();

invoicesRouter.get("/", (req, res) => {
  res.json(invoiceRepo.listForOrg(req.user!.orgId));
});

invoicesRouter.get("/:id", (req, res) => {
  const invoice = invoiceRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!invoice) return res.status(404).json({ error: "invoice not found" });
  res.json(invoice);
});

invoicesRouter.post("/", (req, res) => {
  res.status(201).json(invoiceService.create(req.user!, req.body));
});

invoicesRouter.put("/:id", (req, res) => {
  const invoice = invoiceRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!invoice) return res.status(404).json({ error: "invoice not found" });
  res.json(invoiceRepo.save({ ...invoice, ...pick(req.body, ["dueDate", "currency"] as const) }));
});

invoicesRouter.post("/:id/void", requireRole("admin", "manager"), (req, res) => {
  const invoice = invoiceRepo.findById(req.params.id);
  if (!invoice) return res.status(404).json({ error: "invoice not found" });
  assertSameOrg(req.user!, invoice, "invoice");
  res.json(invoiceRepo.save({ ...invoice, status: "void" }));
});

invoicesRouter.post("/:id/share", (req, res) => {
  const invoice = invoiceRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!invoice) return res.status(404).json({ error: "invoice not found" });
  res.json({ token: signShare(invoice.id, invoice.orgId, 7 * 24 * 3600) });
});
