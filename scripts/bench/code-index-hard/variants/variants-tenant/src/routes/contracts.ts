import { Router } from "express";
import { contractService } from "../services/contractService";
import { jobQueue } from "../jobs/queue";
import { pick } from "../lib/validate";
import { contractRepo } from "../repositories/contractRepo";

export const contractsRouter = Router();

contractsRouter.get("/", (req, res) => {
  res.json(contractService.list(req.user!.orgId));
});

contractsRouter.get("/:id", (req, res) => {
  res.json(contractService.get(req.params.id));
});

contractsRouter.get("/:id/summary", (req, res) => {
  res.json(contractService.summarize(contractService.get(req.params.id)));
});

contractsRouter.put("/:id", (req, res) => {
  const contract = contractService.getForOrg(req.user!.orgId, req.params.id);
  res.json(contractRepo.save({ ...contract, ...pick(req.body, ["title", "terms", "endsOn"] as const) }));
});

contractsRouter.post("/:id/renewal-notice", (req, res) => {
  const job = jobQueue.enqueue("contract-renewal", { contractId: req.params.id }, req.user!);
  res.status(202).json({ jobId: job.id, status: job.status });
});
