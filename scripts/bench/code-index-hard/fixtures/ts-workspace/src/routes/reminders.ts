import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { reminderRepo } from "../repositories/reminderRepo";
import { reminderService } from "../services/reminderService";
import { parseReminderInput } from "../validators/reminder";
import type { Reminder } from "../models/reminder";
import type { User } from "../models/user";

export const remindersRouter = Router();
const canWrite = (user: User, row: Reminder) => row.ownerId === user.id || user.role !== "member";

remindersRouter.param("id", (req, res, next, id) => {
  const row = reminderRepo.get(id);
  if (!row || row.orgId !== (req as AuthedRequest).org) return res.sendStatus(404);
  res.locals.row = row;
  next();
});

remindersRouter.get("/", (req, res) => {
  res.json(reminderService.list((req as AuthedRequest).org));
});

remindersRouter.post("/", (req, res) => {
  const authed = req as AuthedRequest;
  res.status(201).json(reminderService.create(authed.org, authed.user.id, parseReminderInput(req.body)));
});

remindersRouter.get("/:id", (_req, res) => {
  res.json(res.locals.row);
});

remindersRouter.put("/:id", (req, res) => {
  if (!canWrite((req as AuthedRequest).user, res.locals.row)) return res.sendStatus(403);
  res.json(reminderService.update(res.locals.row, parseReminderInput(req.body)));
});

remindersRouter.delete("/:id", (req, res) => {
  if (!canWrite((req as AuthedRequest).user, res.locals.row)) return res.sendStatus(403);
  reminderService.remove(res.locals.row);
  res.sendStatus(204);
});
