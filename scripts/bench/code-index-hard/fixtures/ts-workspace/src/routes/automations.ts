import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { automationRepo } from "../repositories/automationRepo";
import { automationService } from "../services/automationService";
import { parseAutomationInput } from "../validators/automation";
import type { Automation } from "../models/automation";
import type { User } from "../models/user";

export const automationsRouter = Router();
const canWrite = (user: User, row: Automation) => row.ownerId === user.id || user.role !== "member";

automationsRouter.param("id", (req, res, next, id) => {
  const row = automationRepo.get(id);
  if (!row || row.orgId !== (req as AuthedRequest).org) return res.sendStatus(404);
  res.locals.row = row;
  next();
});

automationsRouter.get("/", (req, res) => {
  res.json(automationService.list((req as AuthedRequest).org));
});

automationsRouter.post("/", (req, res) => {
  const authed = req as AuthedRequest;
  res.status(201).json(automationService.create(authed.org, authed.user.id, parseAutomationInput(req.body)));
});

automationsRouter.get("/:id", (_req, res) => {
  res.json(res.locals.row);
});

automationsRouter.put("/:id", (req, res) => {
  if (!canWrite((req as AuthedRequest).user, res.locals.row)) return res.sendStatus(403);
  res.json(automationService.update(res.locals.row, parseAutomationInput(req.body)));
});

automationsRouter.delete("/:id", (req, res) => {
  if (!canWrite((req as AuthedRequest).user, res.locals.row)) return res.sendStatus(403);
  automationService.remove(res.locals.row);
  res.sendStatus(204);
});
