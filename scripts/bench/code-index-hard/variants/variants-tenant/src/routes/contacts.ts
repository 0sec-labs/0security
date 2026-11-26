import { Router } from "express";
import { contactRepo } from "../repositories/crmRepos";
import type { Contact } from "../models/crm";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { newId, isoNow } from "../lib/ids";

const FIELDS = ["name", "email", "phone", "title"] as const;
const REQUIRED = ["name"] as const;

export const contactsRouter = Router();

contactsRouter.get("/", (req, res) => {
  res.json(contactRepo.listForOrg(req.user!.orgId));
});

contactsRouter.get("/:id", (req, res) => {
  const record = contactRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!record) return res.status(404).json({ error: "contact not found" });
  res.json(record);
});

contactsRouter.post("/", (req, res) => {
  const data = pick(req.body, FIELDS);
  requireFields(data, REQUIRED);
  const record = contactRepo.insert({ ...data, id: newId("cnt"), orgId: req.user!.orgId, createdAt: isoNow() } as Contact);
  res.status(201).json(record);
});

contactsRouter.put("/:id", (req, res) => {
  const record = contactRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!record) return res.status(404).json({ error: "contact not found" });
  res.json(contactRepo.save({ ...record, ...pick(req.body, FIELDS) }));
});

contactsRouter.delete("/:id", requireRole("admin", "manager"), (req, res) => {
  const record = contactRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!record) return res.status(404).json({ error: "contact not found" });
  contactRepo.remove(record.id);
  res.status(204).end();
});
