import { Router } from "express";
import { supplierRepo } from "../repositories/opsRepos";
import type { Supplier } from "../models/ops";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { newId, isoNow } from "../lib/ids";

const FIELDS = ["name", "email", "terms"] as const;
const REQUIRED = ["name"] as const;

export const suppliersRouter = Router();

suppliersRouter.get("/", (req, res) => {
  res.json(supplierRepo.listForOrg(req.user!.orgId));
});

suppliersRouter.get("/:id", (req, res) => {
  const record = supplierRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!record) return res.status(404).json({ error: "supplier not found" });
  res.json(record);
});

suppliersRouter.post("/", (req, res) => {
  const data = pick(req.body, FIELDS);
  requireFields(data, REQUIRED);
  const record = supplierRepo.insert({ ...data, id: newId("sup"), orgId: req.user!.orgId, createdAt: isoNow() } as Supplier);
  res.status(201).json(record);
});

suppliersRouter.put("/:id", (req, res) => {
  const record = supplierRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!record) return res.status(404).json({ error: "supplier not found" });
  res.json(supplierRepo.save({ ...record, ...pick(req.body, FIELDS) }));
});

suppliersRouter.delete("/:id", requireRole("admin", "manager"), (req, res) => {
  const record = supplierRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!record) return res.status(404).json({ error: "supplier not found" });
  supplierRepo.remove(record.id);
  res.status(204).end();
});
