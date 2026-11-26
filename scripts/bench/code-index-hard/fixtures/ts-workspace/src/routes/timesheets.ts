import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { timesheetRepo } from "../repositories/timesheetRepo";
import { timesheetService } from "../services/timesheetService";
import { parseTimesheetInput } from "../validators/timesheet";
import type { Timesheet } from "../models/timesheet";
import type { User } from "../models/user";

export const timesheetsRouter = Router();
const canWrite = (user: User, row: Timesheet) => row.ownerId === user.id || user.role !== "member";

timesheetsRouter.param("id", (req, res, next, id) => {
  const row = timesheetRepo.get(id);
  if (!row || row.orgId !== (req as AuthedRequest).org) return res.sendStatus(404);
  res.locals.row = row;
  next();
});

timesheetsRouter.get("/", (req, res) => {
  res.json(timesheetService.list((req as AuthedRequest).org));
});

timesheetsRouter.post("/", (req, res) => {
  const authed = req as AuthedRequest;
  res.status(201).json(timesheetService.create(authed.org, authed.user.id, parseTimesheetInput(req.body)));
});

timesheetsRouter.get("/:id", (_req, res) => {
  res.json(res.locals.row);
});

timesheetsRouter.put("/:id", (req, res) => {
  if (!canWrite((req as AuthedRequest).user, res.locals.row)) return res.sendStatus(403);
  res.json(timesheetService.update(res.locals.row, parseTimesheetInput(req.body)));
});

timesheetsRouter.delete("/:id", (req, res) => {
  if (!canWrite((req as AuthedRequest).user, res.locals.row)) return res.sendStatus(403);
  timesheetService.remove(res.locals.row);
  res.sendStatus(204);
});
