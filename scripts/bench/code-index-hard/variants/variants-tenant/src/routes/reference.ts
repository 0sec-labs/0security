import { Router } from "express";
import { countryRepo, currencyRepo, planRepo } from "../repositories/referenceRepos";

export const referenceRouter = Router();

referenceRouter.get("/currencies", (_req, res) => {
  res.json(currencyRepo.list());
});

referenceRouter.get("/currencies/:id", (req, res) => {
  const currency = currencyRepo.findById(req.params.id.toUpperCase());
  if (!currency) return res.status(404).json({ error: "currency not found" });
  res.json(currency);
});

referenceRouter.get("/countries/:id", (req, res) => {
  const country = countryRepo.findById(req.params.id.toUpperCase());
  if (!country) return res.status(404).json({ error: "country not found" });
  res.json(country);
});

referenceRouter.get("/plans/:id", (req, res) => {
  const plan = planRepo.findById(req.params.id);
  if (!plan) return res.status(404).json({ error: "plan not found" });
  res.json(plan);
});
