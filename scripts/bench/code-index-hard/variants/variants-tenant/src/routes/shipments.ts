import { Router } from "express";
import { shipmentRepo } from "../repositories/shipmentRepo";

export const shipmentsRouter = Router();

shipmentsRouter.get("/", (req, res) => {
  res.json(shipmentRepo.forOrg(req.user!.orgId));
});

shipmentsRouter.get("/:id", (req, res) => {
  const shipment = shipmentRepo.getForOrg(req.user!.orgId, req.params.id);
  if (!shipment) return res.status(404).json({ error: "shipment not found" });
  res.json(shipment);
});
