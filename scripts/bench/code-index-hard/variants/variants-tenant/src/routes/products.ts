import { Router } from "express";
import { productRepo } from "../repositories/productRepo";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { newId } from "../lib/ids";
import type { Product } from "../models/catalog";

const FIELDS = ["sku", "name", "unitPrice", "unitCost", "active"] as const;

export const productsRouter = Router();

productsRouter.get("/", (req, res) => {
  res.json(productRepo.listForOrg(req.user!.orgId));
});

productsRouter.post("/", requireRole("admin", "manager"), (req, res) => {
  const data = pick(req.body, FIELDS);
  requireFields(data, ["sku", "name", "unitPrice"]);
  res.status(201).json(productRepo.insert({ unitCost: 0, active: true, ...data, id: newId("prd"), orgId: req.user!.orgId } as Product));
});

productsRouter.get("/:id", (req, res) => {
  const product = productRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!product) return res.status(404).json({ error: "product not found" });
  res.json(product);
});

productsRouter.put("/:id", requireRole("admin", "manager"), (req, res) => {
  const product = productRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!product) return res.status(404).json({ error: "product not found" });
  res.json(productRepo.save({ ...product, ...pick(req.body, FIELDS) }));
});

productsRouter.delete("/:id", requireRole("admin"), (req, res) => {
  const product = productRepo.findForOrg(req.user!.orgId, req.params.id);
  if (!product) return res.status(404).json({ error: "product not found" });
  productRepo.remove(product.id);
  res.status(204).end();
});
