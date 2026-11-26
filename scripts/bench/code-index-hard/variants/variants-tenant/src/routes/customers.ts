import { Router } from "express";
import { customerRepo } from "../repositories/customerRepo";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { isoNow, newId } from "../lib/ids";
import type { Customer } from "../models/billing";

const FIELDS = ["name", "email", "billingAddress"] as const;

export const customersRouter = Router();

customersRouter.get("/", (req, res) => {
  res.json(customerRepo.listForOrg(req.user!.orgId));
});

customersRouter.post("/", (req, res) => {
  const data = pick(req.body, FIELDS);
  requireFields(data, ["name", "email"]);
  const customer = customerRepo.insert({ ...data, id: newId("cus"), orgId: req.user!.orgId, createdAt: isoNow() } as Customer);
  res.status(201).json(customer);
});

customersRouter
  .route("/:id")
  .get((req, res) => {
    const customer = customerRepo.findForOrg(req.user!.orgId, req.params.id);
    if (!customer) return res.status(404).json({ error: "customer not found" });
    res.json(customer);
  })
  .put((req, res) => {
    const customer = customerRepo.findForOrg(req.user!.orgId, req.params.id);
    if (!customer) return res.status(404).json({ error: "customer not found" });
    res.json(customerRepo.save({ ...customer, ...pick(req.body, FIELDS) }));
  })
  .delete(requireRole("admin", "manager"), (req, res) => {
    const customer = customerRepo.findForOrg(req.user!.orgId, req.params.id);
    if (!customer) return res.status(404).json({ error: "customer not found" });
    customerRepo.remove(customer.id);
    res.status(204).end();
  });
