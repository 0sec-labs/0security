import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { approvalRepo } from "../repositories/approvalRepo";
import { approvalService } from "../services/approvalService";
import { parseApprovalInput } from "../validators/approval";
import type { Approval } from "../models/approval";
import type { User } from "../models/user";

export const approvalsRouter = Router();
const canWrite = (user: User, row: Approval) => row.ownerId === user.id || user.role !== "member";

approvalsRouter.param("id", (req, res, next, id) => {
  const row = approvalRepo.get(id);
  if (!row || row.orgId !== (req as AuthedRequest).org) return res.sendStatus(404);
  res.locals.row = row;
  next();
});

approvalsRouter.get("/", (req, res) => {
  res.json(approvalService.list((req as AuthedRequest).org));
});

approvalsRouter.post("/", (req, res) => {
  const authed = req as AuthedRequest;
  res.status(201).json(approvalService.create(authed.org, authed.user.id, parseApprovalInput(req.body)));
});

approvalsRouter.get("/:id", (_req, res) => {
  res.json(res.locals.row);
});

approvalsRouter.put("/:id", (req, res) => {
  if (!canWrite((req as AuthedRequest).user, res.locals.row)) return res.sendStatus(403);
  res.json(approvalService.update(res.locals.row, parseApprovalInput(req.body)));
});

approvalsRouter.delete("/:id", (req, res) => {
  if (!canWrite((req as AuthedRequest).user, res.locals.row)) return res.sendStatus(403);
  approvalService.remove(res.locals.row);
  res.sendStatus(204);
});
