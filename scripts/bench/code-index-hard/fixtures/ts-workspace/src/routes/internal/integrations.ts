import { Router } from "express";
import { badRequest, notFound } from "../../lib/http";
import { commentService } from "../../services/commentService";
import { taskRepo } from "../../repositories/taskRepo";
import { userRepo } from "../../repositories/userRepo";

export const integrationsRouter = Router();

integrationsRouter.post("/slack/comments", (req, res) => {
  const task = taskRepo.get(String(req.body?.taskId));
  const author = userRepo.byEmail(String(req.body?.authorEmail ?? ""));
  if (!task) throw notFound();
  if (!author || author.orgId !== task.orgId) throw badRequest("unknown author");
  res.status(201).json(commentService.add({ orgId: task.orgId, taskId: task.id, authorId: author.id, body: String(req.body?.text ?? "") }));
});
