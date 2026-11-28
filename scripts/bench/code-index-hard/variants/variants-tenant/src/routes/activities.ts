import { Router } from "express";
import type { Request } from "express";
import { notFound } from "../lib/errors";
import { activityRepo } from "../repositories/crmRepos";
import type { Activity } from "../models/crm";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { newId, isoNow } from "../lib/ids";

const FIELDS = ["kind", "summary", "dueOn"] as const;
const REQUIRED = ["kind"] as const;

export const activitiesRouter = Router();

// Loads the record and checks that it belongs to the caller's organisation.
function load(req: Request): Activity {
  const record = activityRepo.findById(req.params.id as string);
  if (!record || record.orgId !== req.user!.orgId) throw notFound("activity");
  return record;
}

activitiesRouter.get("/", (req, res) => {
  res.json(activityRepo.listForOrg(req.user!.orgId));
});

activitiesRouter.post("/", (req, res) => {
  const data = pick(req.body, FIELDS);
  requireFields(data, REQUIRED);
  const record = activityRepo.insert({ ...data, id: newId("act"), orgId: req.user!.orgId, createdAt: isoNow() } as Activity);
  res.status(201).json(record);
});

activitiesRouter.get("/:id", (req, res) => {
  res.json(load(req));
});

activitiesRouter.put("/:id", (req, res) => {
  res.json(activityRepo.save({ ...load(req), ...pick(req.body, FIELDS) }));
});

activitiesRouter.delete("/:id", requireRole("admin"), (req, res) => {
  activityRepo.remove(load(req).id);
  res.status(204).end();
});
