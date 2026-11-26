import { Router } from "express";
import type { Request } from "express";
import { taxRateRepo } from "../repositories/financeRepos";
import type { TaxRate } from "../models/finance";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { newId, isoNow } from "../lib/ids";

const FIELDS = ["name", "ratePercent", "region"] as const;
const REQUIRED = ["name"] as const;

export const taxRatesRouter = Router();

const owned = (req: Request) => taxRateRepo.findForOrg(req.user!.orgId, req.params.id as string);

taxRatesRouter
  .route("/")
  .get((req, res) => {
    res.json(taxRateRepo.listForOrg(req.user!.orgId));
  })
  .post((req, res) => {
    const data = pick(req.body, FIELDS);
    requireFields(data, REQUIRED);
    const record = taxRateRepo.insert({ ...data, id: newId("tax"), orgId: req.user!.orgId, createdAt: isoNow() } as TaxRate);
    res.status(201).json(record);
  });

taxRatesRouter
  .route("/:id")
  .get((req, res) => {
    const record = owned(req);
    if (!record) return res.status(404).json({ error: "tax rate not found" });
    res.json(record);
  })
  .put((req, res) => {
    const record = owned(req);
    if (!record) return res.status(404).json({ error: "tax rate not found" });
    res.json(taxRateRepo.save({ ...record, ...pick(req.body, FIELDS) }));
  })
  .delete(requireRole("admin", "manager"), (req, res) => {
    const record = owned(req);
    if (!record) return res.status(404).json({ error: "tax rate not found" });
    taxRateRepo.remove(record.id);
    res.status(204).end();
  });
