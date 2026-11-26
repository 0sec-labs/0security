import { Router } from "express";
import { priceListRepo } from "../repositories/financeRepos";
import type { PriceList } from "../models/finance";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { newId, isoNow } from "../lib/ids";

const FIELDS = ["name", "currency"] as const;
const REQUIRED = ["name"] as const;

export const priceListsRouter = Router();

// Resolve :id once per request, inside the caller's organisation.
priceListsRouter.param("id", (req, res, next, id) => {
  const record = priceListRepo.findForOrg(req.user!.orgId, id);
  if (!record) return res.status(404).json({ error: "price list not found" });
  res.locals.record = record;
  next();
});

priceListsRouter.get("/", (req, res) => {
  const rows = priceListRepo.listForOrg(req.user!.orgId);
  res.json({ count: rows.length, rows });
});

priceListsRouter.post("/", (req, res) => {
  const data = pick(req.body, FIELDS);
  requireFields(data, REQUIRED);
  const record = priceListRepo.insert({ ...data, id: newId("pl"), orgId: req.user!.orgId, createdAt: isoNow() } as PriceList);
  res.status(201).json(record);
});

priceListsRouter.get("/:id", (_req, res) => {
  res.json(res.locals.record);
});

priceListsRouter.put("/:id", (req, res) => {
  const updated = priceListRepo.save({ ...(res.locals.record as PriceList), ...pick(req.body, FIELDS) });
  res.json(updated);
});

priceListsRouter.delete("/:id", requireRole("admin"), (_req, res) => {
  priceListRepo.remove((res.locals.record as PriceList).id);
  res.status(204).end();
});
