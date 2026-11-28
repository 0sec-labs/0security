import { Router } from "express";
import { tagRepo } from "../repositories/crmRepos";
import type { Tag } from "../models/crm";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { newId, isoNow } from "../lib/ids";

const FIELDS = ["label", "color"] as const;
const REQUIRED = ["label"] as const;

export const tagsRouter = Router();

// Resolve :id once per request, inside the caller's organisation.
tagsRouter.param("id", (req, res, next, id) => {
  const record = tagRepo.findForOrg(req.user!.orgId, id);
  if (!record) return res.status(404).json({ error: "tag not found" });
  res.locals.record = record;
  next();
});

tagsRouter.get("/", (req, res) => {
  const rows = tagRepo.listForOrg(req.user!.orgId);
  res.json({ count: rows.length, rows });
});

tagsRouter.post("/", (req, res) => {
  const data = pick(req.body, FIELDS);
  requireFields(data, REQUIRED);
  const record = tagRepo.insert({ ...data, id: newId("tg"), orgId: req.user!.orgId, createdAt: isoNow() } as Tag);
  res.status(201).json(record);
});

tagsRouter.get("/:id", (_req, res) => {
  res.json(res.locals.record);
});

tagsRouter.put("/:id", (req, res) => {
  const updated = tagRepo.save({ ...(res.locals.record as Tag), ...pick(req.body, FIELDS) });
  res.json(updated);
});

tagsRouter.delete("/:id", requireRole("admin"), (_req, res) => {
  tagRepo.remove((res.locals.record as Tag).id);
  res.status(204).end();
});
