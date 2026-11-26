import { Router } from "express";
import { verifyBodySignature } from "./signature";
import { integrationRepo } from "../repositories/integrationRepo";
import { shipmentRepo } from "../repositories/shipmentRepo";

export const carrierWebhook = Router();

carrierWebhook.post("/", (req, res) => {
  const timestamp = String(req.headers["x-carrier-timestamp"] ?? "");
  const signature = String(req.headers["x-carrier-signature"] ?? "");
  if (!verifyBodySignature(timestamp, req.body, signature)) return res.status(401).json({ error: "bad signature" });

  const { accountId, shipmentId, status } = req.body ?? {};
  const account = integrationRepo.findByExternal("carrier", String(accountId ?? ""));
  if (!account) return res.status(404).json({ error: "unknown account" });
  const shipment = shipmentRepo.getForOrg(account.orgId, String(shipmentId ?? ""));
  if (!shipment) return res.status(404).json({ error: "shipment not found" });
  const next = String(status ?? "").slice(0, 40);
  shipmentRepo.save({ ...shipment, status: next, events: [...shipment.events, { status: next, at: new Date().toISOString() }] });
  res.json({ received: true });
});
