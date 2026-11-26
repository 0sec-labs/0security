import { Router } from "express";
import type { Request } from "express";
import { notFound } from "../lib/errors";
import { warehouseRepo } from "../repositories/opsRepos";
import type { Warehouse } from "../models/ops";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { newId, isoNow } from "../lib/ids";

const FIELDS = ["name", "city", "capacity"] as const;
const REQUIRED = ["name"] as const;

export const warehousesRouter = Router();

// Loads the record and checks that it belongs to the caller's organisation.
function load(req: Request): Warehouse {
  const record = warehouseRepo.findById(req.params.id as string);
  if (!record || record.orgId !== req.user!.orgId) throw notFound("warehouse");
  return record;
}

warehousesRouter.get("/", (req, res) => {
  res.json(warehouseRepo.listForOrg(req.user!.orgId));
});

warehousesRouter.post("/", (req, res) => {
  const data = pick(req.body, FIELDS);
  requireFields(data, REQUIRED);
  const record = warehouseRepo.insert({ ...data, id: newId("wh"), orgId: req.user!.orgId, createdAt: isoNow() } as Warehouse);
  res.status(201).json(record);
});

warehousesRouter.get("/:id", (req, res) => {
  res.json(load(req));
});

warehousesRouter.put("/:id", (req, res) => {
  res.json(warehouseRepo.save({ ...load(req), ...pick(req.body, FIELDS) }));
});

warehousesRouter.delete("/:id", requireRole("admin"), (req, res) => {
  warehouseRepo.remove(load(req).id);
  res.status(204).end();
});
