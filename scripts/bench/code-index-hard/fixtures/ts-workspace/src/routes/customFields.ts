import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { customFieldRepo } from "../repositories/customFieldRepo";
import { customFieldService } from "../services/customFieldService";
import { parseCustomFieldInput } from "../validators/customField";
import type { CustomField } from "../models/customField";
import type { User } from "../models/user";

export const customFieldsRouter = Router();
const canWrite = (user: User, row: CustomField) => row.ownerId === user.id || user.role !== "member";

customFieldsRouter.param("id", (req, res, next, id) => {
  const row = customFieldRepo.get(id);
  if (!row || row.orgId !== (req as AuthedRequest).org) return res.sendStatus(404);
  res.locals.row = row;
  next();
});

customFieldsRouter.get("/", (req, res) => {
  res.json(customFieldService.list((req as AuthedRequest).org));
});

customFieldsRouter.post("/", (req, res) => {
  const authed = req as AuthedRequest;
  res.status(201).json(customFieldService.create(authed.org, authed.user.id, parseCustomFieldInput(req.body)));
});

customFieldsRouter.get("/:id", (_req, res) => {
  res.json(res.locals.row);
});

customFieldsRouter.put("/:id", (req, res) => {
  if (!canWrite((req as AuthedRequest).user, res.locals.row)) return res.sendStatus(403);
  res.json(customFieldService.update(res.locals.row, parseCustomFieldInput(req.body)));
});

customFieldsRouter.delete("/:id", (req, res) => {
  if (!canWrite((req as AuthedRequest).user, res.locals.row)) return res.sendStatus(403);
  customFieldService.remove(res.locals.row);
  res.sendStatus(204);
});

customFieldsRouter.post("/:id/archive", (req, res) => {
  if (!canWrite((req as AuthedRequest).user, res.locals.row)) return res.sendStatus(403);
  res.json(customFieldService.archive(res.locals.row));
});
