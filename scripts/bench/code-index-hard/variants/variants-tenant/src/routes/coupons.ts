import { Router } from "express";
import { couponRepo } from "../repositories/financeRepos";
import type { Coupon } from "../models/finance";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { newId, isoNow } from "../lib/ids";

const FIELDS = ["code", "percentOff", "active"] as const;
const REQUIRED = ["code"] as const;

export const couponsRouter = Router();

couponsRouter.get("/", (req, res) => {
  res.json(couponRepo.listForOrg(req.user!.orgId));
});

couponsRouter.get("/:id", (req, res) => {
  const record = couponRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!record) return res.status(404).json({ error: "coupon not found" });
  res.json(record);
});

couponsRouter.post("/", (req, res) => {
  const data = pick(req.body, FIELDS);
  requireFields(data, REQUIRED);
  const record = couponRepo.insert({ ...data, id: newId("cpn"), orgId: req.user!.orgId, createdAt: isoNow() } as Coupon);
  res.status(201).json(record);
});

couponsRouter.put("/:id", (req, res) => {
  const record = couponRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!record) return res.status(404).json({ error: "coupon not found" });
  res.json(couponRepo.save({ ...record, ...pick(req.body, FIELDS) }));
});

couponsRouter.delete("/:id", requireRole("admin", "manager"), (req, res) => {
  const record = couponRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!record) return res.status(404).json({ error: "coupon not found" });
  couponRepo.remove(record.id);
  res.status(204).end();
});
