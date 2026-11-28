import { Router } from "express";
import type { Request } from "express";
import { documentRepo } from "../repositories/opsRepos";
import type { Document } from "../models/ops";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { newId, isoNow } from "../lib/ids";

const FIELDS = ["title", "kind", "url"] as const;
const REQUIRED = ["title"] as const;

export const documentsRouter = Router();

const owned = (req: Request) => documentRepo.findForOrg(req.user!.orgId, req.params.id as string);

documentsRouter
  .route("/")
  .get((req, res) => {
    res.json(documentRepo.listForOrg(req.user!.orgId));
  })
  .post((req, res) => {
    const data = pick(req.body, FIELDS);
    requireFields(data, REQUIRED);
    const record = documentRepo.insert({ ...data, id: newId("doc"), orgId: req.user!.orgId, createdAt: isoNow() } as Document);
    res.status(201).json(record);
  });

documentsRouter
  .route("/:id")
  .get((req, res) => {
    const record = owned(req);
    if (!record) return res.status(404).json({ error: "document not found" });
    res.json(record);
  })
  .put((req, res) => {
    const record = owned(req);
    if (!record) return res.status(404).json({ error: "document not found" });
    res.json(documentRepo.save({ ...record, ...pick(req.body, FIELDS) }));
  })
  .delete(requireRole("admin", "manager"), (req, res) => {
    const record = owned(req);
    if (!record) return res.status(404).json({ error: "document not found" });
    documentRepo.remove(record.id);
    res.status(204).end();
  });
