import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { milestoneRepo } from "../repositories/milestoneRepo";
import { milestoneService } from "../services/milestoneService";
import { parseMilestoneInput } from "../validators/milestone";
import type { Milestone } from "../models/milestone";
import type { User } from "../models/user";

export const milestonesRouter = Router();
const canWrite = (user: User, row: Milestone) => row.ownerId === user.id || user.role !== "member";

milestonesRouter.param("id", (req, res, next, id) => {
  const row = milestoneRepo.get(id);
  if (!row || row.orgId !== (req as AuthedRequest).org) return res.sendStatus(404);
  res.locals.row = row;
  next();
});

milestonesRouter.get("/", (req, res) => {
  res.json(milestoneService.list((req as AuthedRequest).org));
});

milestonesRouter.post("/", (req, res) => {
  const authed = req as AuthedRequest;
  res.status(201).json(milestoneService.create(authed.org, authed.user.id, parseMilestoneInput(req.body)));
});

milestonesRouter.get("/:id", (_req, res) => {
  res.json(res.locals.row);
});

milestonesRouter.put("/:id", (req, res) => {
  if (!canWrite((req as AuthedRequest).user, res.locals.row)) return res.sendStatus(403);
  res.json(milestoneService.update(res.locals.row, parseMilestoneInput(req.body)));
});

milestonesRouter.delete("/:id", (req, res) => {
  if (!canWrite((req as AuthedRequest).user, res.locals.row)) return res.sendStatus(403);
  milestoneService.remove(res.locals.row);
  res.sendStatus(204);
});

milestonesRouter.post("/:id/archive", (req, res) => {
  if (!canWrite((req as AuthedRequest).user, res.locals.row)) return res.sendStatus(403);
  res.json(milestoneService.archive(res.locals.row));
});
