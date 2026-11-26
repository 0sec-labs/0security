import { Router } from "express";
import { noteRepo } from "../repositories/crmRepos";
import type { Note } from "../models/crm";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { newId, isoNow } from "../lib/ids";

const FIELDS = ["subject", "body"] as const;
const REQUIRED = ["subject"] as const;

export const notesRouter = Router();

notesRouter.get("/", (req, res) => {
  res.json(noteRepo.listForOrg(req.user!.orgId));
});

notesRouter.get("/:id", (req, res) => {
  const record = noteRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!record) return res.status(404).json({ error: "note not found" });
  res.json(record);
});

notesRouter.post("/", (req, res) => {
  const data = pick(req.body, FIELDS);
  requireFields(data, REQUIRED);
  const record = noteRepo.insert({ ...data, id: newId("nt"), orgId: req.user!.orgId, createdAt: isoNow() } as Note);
  res.status(201).json(record);
});

notesRouter.put("/:id", (req, res) => {
  const record = noteRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!record) return res.status(404).json({ error: "note not found" });
  res.json(noteRepo.save({ ...record, ...pick(req.body, FIELDS) }));
});

notesRouter.delete("/:id", requireRole("admin", "manager"), (req, res) => {
  const record = noteRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!record) return res.status(404).json({ error: "note not found" });
  noteRepo.remove(record.id);
  res.status(204).end();
});
