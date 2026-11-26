import { Router } from "express";
import { carrierTotals, shipmentCostReport, shipmentTimeline } from "../services/reportService";

export const reportsRouter = Router();

reportsRouter.get("/carriers", (req, res) => {
  res.json(carrierTotals(req.user!.orgId));
});

reportsRouter.get("/shipments/:id/costs", (req, res) => {
  res.json(shipmentCostReport(req.params.id));
});

reportsRouter.get("/shipments/:id/timeline", (req, res) => {
  res.json(shipmentTimeline(req.user!.orgId, req.params.id));
});
