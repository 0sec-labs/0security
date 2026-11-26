import { Router } from "express";
import { dealRepo } from "../repositories/crmRepos";
import type { Deal } from "../models/crm";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { newId, isoNow } from "../lib/ids";

const FIELDS = ["title", "amount", "stage", "customerId"] as const;
const REQUIRED = ["title"] as const;

export const dealsRouter = Router();

// Resolve :id once per request, inside the caller's organisation.
dealsRouter.param("id", (req, res, next, id) => {
  const record = dealRepo.findForOrg(req.user!.orgId, id);
  if (!record) return res.status(404).json({ error: "deal not found" });
  res.locals.record = record;
  next();
});

dealsRouter.get("/", (req, res) => {
  const rows = dealRepo.listForOrg(req.user!.orgId);
  res.json({ count: rows.length, rows });
});

dealsRouter.post("/", (req, res) => {
  const data = pick(req.body, FIELDS);
  requireFields(data, REQUIRED);
  const record = dealRepo.insert({ ...data, id: newId("dl"), orgId: req.user!.orgId, createdAt: isoNow() } as Deal);
  res.status(201).json(record);
});

dealsRouter.get("/:id", (_req, res) => {
  res.json(res.locals.record);
});

dealsRouter.put("/:id", (req, res) => {
  const updated = dealRepo.save({ ...(res.locals.record as Deal), ...pick(req.body, FIELDS) });
  res.json(updated);
});

dealsRouter.delete("/:id", requireRole("admin"), (_req, res) => {
  dealRepo.remove((res.locals.record as Deal).id);
  res.status(204).end();
});
