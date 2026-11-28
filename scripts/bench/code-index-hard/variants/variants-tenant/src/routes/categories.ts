import { Router } from "express";
import type { Request } from "express";
import { notFound } from "../lib/errors";
import { categoryRepo } from "../repositories/financeRepos";
import type { Category } from "../models/finance";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { newId, isoNow } from "../lib/ids";

const FIELDS = ["name", "parentId"] as const;
const REQUIRED = ["name"] as const;

export const categoriesRouter = Router();

// Loads the record and checks that it belongs to the caller's organisation.
function load(req: Request): Category {
  const record = categoryRepo.findById(req.params.id as string);
  if (!record || record.orgId !== req.user!.orgId) throw notFound("category");
  return record;
}

categoriesRouter.get("/", (req, res) => {
  res.json(categoryRepo.listForOrg(req.user!.orgId));
});

categoriesRouter.post("/", (req, res) => {
  const data = pick(req.body, FIELDS);
  requireFields(data, REQUIRED);
  const record = categoryRepo.insert({ ...data, id: newId("cat"), orgId: req.user!.orgId, createdAt: isoNow() } as Category);
  res.status(201).json(record);
});

categoriesRouter.get("/:id", (req, res) => {
  res.json(load(req));
});

categoriesRouter.put("/:id", (req, res) => {
  res.json(categoryRepo.save({ ...load(req), ...pick(req.body, FIELDS) }));
});

categoriesRouter.delete("/:id", requireRole("admin"), (req, res) => {
  categoryRepo.remove(load(req).id);
  res.status(204).end();
});
