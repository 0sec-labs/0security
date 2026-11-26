import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { dashboardService } from "../services/dashboardService";
import { parseDashboardInput } from "../validators/dashboard";

export const dashboardsRouter = Router();
const who = (req: unknown) => (req as AuthedRequest).user;

dashboardsRouter.get("/", (req, res) => {
  res.json(dashboardService.list(who(req)));
});

dashboardsRouter.post("/", (req, res) => {
  res.status(201).json(dashboardService.create(who(req), parseDashboardInput(req.body)));
});

dashboardsRouter.get("/:id", (req, res) => {
  res.json(dashboardService.require(who(req), req.params.id));
});

dashboardsRouter.put("/:id", (req, res) => {
  res.json(dashboardService.update(who(req), req.params.id, parseDashboardInput(req.body)));
});

dashboardsRouter.delete("/:id", (req, res) => {
  dashboardService.remove(who(req), req.params.id);
  res.sendStatus(204);
});
