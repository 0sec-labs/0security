import { Router } from "express";
import { verifyTimestampSignature } from "./signature";
import { integrationRepo } from "../repositories/integrationRepo";
import { invoiceRepo } from "../repositories/invoiceRepo";

export const paymentWebhook = Router();

paymentWebhook.post("/", (req, res) => {
  const timestamp = String(req.headers["x-pay-timestamp"] ?? "");
  const signature = String(req.headers["x-pay-signature"] ?? "");
  if (!verifyTimestampSignature(timestamp, signature)) return res.status(401).json({ error: "bad signature" });

  const { event, accountId, invoiceId, reference } = req.body ?? {};
  const account = integrationRepo.findByExternal("payments", String(accountId ?? ""));
  if (!account) return res.status(404).json({ error: "unknown account" });
  if (event !== "payment.settled") return res.json({ received: true });

  const invoice = invoiceRepo.findById(String(invoiceId ?? ""));
  if (!invoice) return res.status(404).json({ error: "invoice not found" });
  invoiceRepo.save({ ...invoice, status: "paid", paidReference: String(reference ?? "") });
  res.json({ received: true, invoice: { id: invoice.id, number: invoice.number, total: invoice.total, currency: invoice.currency, status: "paid" } });
});
