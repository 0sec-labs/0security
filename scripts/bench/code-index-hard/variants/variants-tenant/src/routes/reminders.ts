import { Router } from "express";
import { badRequest, notFound } from "../lib/errors";
import { jobQueue } from "../jobs/queue";

export const remindersRouter = Router();

// Send a payment reminder for an invoice to the given address right away.
remindersRouter.post("/", (req, res) => {
  const { invoiceId, to } = req.body ?? {};
  if (typeof invoiceId !== "string" || typeof to !== "string" || !/^[^@\s]+@[^@\s]+$/.test(to)) {
    throw badRequest("invoiceId and a valid recipient are required");
  }
  const job = jobQueue.enqueue("invoice-reminder", { invoiceId, to }, req.user!);
  res.status(202).json({ jobId: job.id, status: job.status });
});

remindersRouter.get("/jobs/:jobId", (req, res) => {
  const job = jobQueue.get(req.params.jobId);
  if (!job || job.orgId !== req.user!.orgId) throw notFound("job");
  res.json({ id: job.id, status: job.status, result: job.result, error: job.error });
});
