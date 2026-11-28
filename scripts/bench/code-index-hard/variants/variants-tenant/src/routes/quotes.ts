import { Router } from "express";
import { quoteRepo } from "../repositories/quoteRepo";
import { customerRepo } from "../repositories/customerRepo";
import type { Quote } from "../models/billing";

export const quotesRouter = Router();

function renderQuote(quote: Quote, customerName: string): string {
  const rows = quote.lines.map((line) => line.qty + " x " + line.description + " @ " + line.unitPrice);
  return ["QUOTE " + quote.id, quote.title, "For: " + customerName, ...rows, "Total: " + quote.total, "Valid until " + quote.validUntil, "Notes: " + quote.internalNotes].join("\n");
}

quotesRouter.get("/", (req, res) => {
  res.json(quoteRepo.listForOrg(req.user!.orgId));
});

quotesRouter.get("/:id", (req, res) => {
  const quote = quoteRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!quote) return res.status(404).json({ error: "quote not found" });
  res.json(quote);
});

quotesRouter.get("/:id/pdf", (req, res) => {
  const quote = quoteRepo.findById(req.params.id);
  if (!quote) return res.status(404).json({ error: "quote not found" });
  const customer = customerRepo.findForOrg(quote.orgId, quote.customerId);
  res.type("text/plain").send(renderQuote(quote, customer?.name ?? "unknown customer"));
});
