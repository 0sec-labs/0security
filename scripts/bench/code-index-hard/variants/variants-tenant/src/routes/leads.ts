import { Router } from "express";
import type { Request } from "express";
import { leadRepo } from "../repositories/crmRepos";
import type { Lead } from "../models/crm";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { newId, isoNow } from "../lib/ids";

const FIELDS = ["name", "email", "source", "score"] as const;
const REQUIRED = ["name"] as const;

export const leadsRouter = Router();

const owned = (req: Request) => leadRepo.findForOrg(req.user!.orgId, req.params.id as string);

leadsRouter
  .route("/")
  .get((req, res) => {
    res.json(leadRepo.listForOrg(req.user!.orgId));
  })
  .post((req, res) => {
    const data = pick(req.body, FIELDS);
    requireFields(data, REQUIRED);
    const record = leadRepo.insert({ ...data, id: newId("ld"), orgId: req.user!.orgId, createdAt: isoNow() } as Lead);
    res.status(201).json(record);
  });

leadsRouter
  .route("/:id")
  .get((req, res) => {
    const record = owned(req);
    if (!record) return res.status(404).json({ error: "lead not found" });
    res.json(record);
  })
  .put((req, res) => {
    const record = owned(req);
    if (!record) return res.status(404).json({ error: "lead not found" });
    res.json(leadRepo.save({ ...record, ...pick(req.body, FIELDS) }));
  })
  .delete(requireRole("admin", "manager"), (req, res) => {
    const record = owned(req);
    if (!record) return res.status(404).json({ error: "lead not found" });
    leadRepo.remove(record.id);
    res.status(204).end();
  });
