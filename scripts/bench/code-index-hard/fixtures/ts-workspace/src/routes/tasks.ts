import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { taskService } from "../services/taskService";
import { commentService } from "../services/commentService";
import { attachmentService } from "../services/attachmentService";
import { timeEntryService } from "../services/timeEntryService";
import { activityService } from "../services/activityService";

export const tasksRouter = Router();
const who = (req: unknown) => (req as AuthedRequest).user;

tasksRouter.get("/", (req, res) => {
  res.json(taskService.listForProject(who(req), String(req.query.projectId ?? "")));
});

tasksRouter.post("/", (req, res) => {
  res.status(201).json(taskService.create(who(req), req.body ?? {}));
});

tasksRouter.get("/:id", (req, res) => {
  res.json(taskService.require(who(req), req.params.id));
});

tasksRouter.put("/:id", (req, res) => {
  res.json(taskService.update(who(req), req.params.id, req.body ?? {}));
});

tasksRouter.delete("/:id", (req, res) => {
  taskService.remove(who(req), req.params.id);
  res.sendStatus(204);
});

tasksRouter.get("/:id/comments", (req, res) => {
  res.json(commentService.list(who(req), req.params.id));
});

tasksRouter.post("/:id/comments", (req, res) => {
  const user = who(req);
  const task = taskService.require(user, req.params.id);
  res.status(201).json(commentService.add({ authorId: user.id, ...req.body, taskId: task.id, orgId: task.orgId }));
});

tasksRouter.get("/:id/attachments", (req, res) => {
  res.json(attachmentService.list(who(req), req.params.id));
});

tasksRouter.post("/:id/attachments", (req, res) => {
  res.status(201).json(attachmentService.upload(who(req), req.params.id, req.body ?? {}));
});

tasksRouter.get("/:id/watchers", (req, res) => {
  res.json(taskService.watchers(who(req), req.params.id));
});

tasksRouter.post("/:id/watchers", (req, res) => {
  res.json(taskService.watch(who(req), req.params.id));
});

tasksRouter.get("/:id/subtasks", (req, res) => {
  res.json(taskService.subtasks(who(req), req.params.id));
});

tasksRouter.get("/:id/time", (req, res) => {
  res.json(timeEntryService.list(who(req), req.params.id));
});

tasksRouter.get("/:id/history", (req, res) => {
  res.json(activityService.forEntity("task", req.params.id));
});

tasksRouter.post("/:id/move", (req, res) => {
  res.json(taskService.move(who(req), req.params.id, String(req.body?.projectId ?? "")));
});
