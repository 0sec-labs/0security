import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { notificationRepo } from "../repositories/notificationRepo";
import { notificationService } from "../services/notificationService";
import { parseNotificationInput } from "../validators/notification";
import type { Notification } from "../models/notification";
import type { User } from "../models/user";

export const notificationsRouter = Router();
const canWrite = (user: User, row: Notification) => row.ownerId === user.id || user.role !== "member";

notificationsRouter.param("id", (req, res, next, id) => {
  const row = notificationRepo.get(id);
  if (!row || row.orgId !== (req as AuthedRequest).org) return res.sendStatus(404);
  res.locals.row = row;
  next();
});

notificationsRouter.get("/", (req, res) => {
  res.json(notificationService.list((req as AuthedRequest).org));
});

notificationsRouter.post("/", (req, res) => {
  const authed = req as AuthedRequest;
  res.status(201).json(notificationService.create(authed.org, authed.user.id, parseNotificationInput(req.body)));
});

notificationsRouter.get("/:id", (_req, res) => {
  res.json(res.locals.row);
});

notificationsRouter.put("/:id", (req, res) => {
  if (!canWrite((req as AuthedRequest).user, res.locals.row)) return res.sendStatus(403);
  res.json(notificationService.update(res.locals.row, parseNotificationInput(req.body)));
});

notificationsRouter.delete("/:id", (req, res) => {
  if (!canWrite((req as AuthedRequest).user, res.locals.row)) return res.sendStatus(403);
  notificationService.remove(res.locals.row);
  res.sendStatus(204);
});

notificationsRouter.post("/:id/archive", (req, res) => {
  if (!canWrite((req as AuthedRequest).user, res.locals.row)) return res.sendStatus(403);
  res.json(notificationService.archive(res.locals.row));
});
