import { Router } from "express";
import { purchaseOrderRepo } from "../repositories/opsRepos";
import type { PurchaseOrder } from "../models/ops";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { newId, isoNow } from "../lib/ids";

const FIELDS = ["supplierId", "reference", "amount", "status"] as const;
const REQUIRED = ["supplierId"] as const;

export const purchaseOrdersRouter = Router();

// Resolve :id once per request, inside the caller's organisation.
purchaseOrdersRouter.param("id", (req, res, next, id) => {
  const record = purchaseOrderRepo.findForOrg(req.user!.orgId, id);
  if (!record) return res.status(404).json({ error: "purchase order not found" });
  res.locals.record = record;
  next();
});

purchaseOrdersRouter.get("/", (req, res) => {
  const rows = purchaseOrderRepo.listForOrg(req.user!.orgId);
  res.json({ count: rows.length, rows });
});

purchaseOrdersRouter.post("/", (req, res) => {
  const data = pick(req.body, FIELDS);
  requireFields(data, REQUIRED);
  const record = purchaseOrderRepo.insert({ ...data, id: newId("po"), orgId: req.user!.orgId, createdAt: isoNow() } as PurchaseOrder);
  res.status(201).json(record);
});

purchaseOrdersRouter.get("/:id", (_req, res) => {
  res.json(res.locals.record);
});

purchaseOrdersRouter.put("/:id", (req, res) => {
  const updated = purchaseOrderRepo.save({ ...(res.locals.record as PurchaseOrder), ...pick(req.body, FIELDS) });
  res.json(updated);
});

purchaseOrdersRouter.delete("/:id", requireRole("admin"), (_req, res) => {
  purchaseOrderRepo.remove((res.locals.record as PurchaseOrder).id);
  res.status(204).end();
});
