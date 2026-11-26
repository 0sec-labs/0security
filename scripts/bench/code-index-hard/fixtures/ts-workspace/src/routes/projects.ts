import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { projectService } from "../services/projectService";
import { taskService } from "../services/taskService";

export const projectsRouter = Router();
const who = (req: unknown) => (req as AuthedRequest).user;

projectsRouter.get("/", (req, res) => {
  res.json(projectService.list(who(req)));
});

projectsRouter.post("/", (req, res) => {
  res.status(201).json(projectService.create(who(req), req.body ?? {}));
});

projectsRouter.get("/:id", (req, res) => {
  res.json(projectService.require(who(req), req.params.id));
});

projectsRouter.put("/:id", (req, res) => {
  res.json(projectService.update(who(req), req.params.id, req.body ?? {}));
});

projectsRouter.delete("/:id", (req, res) => {
  projectService.remove(who(req), req.params.id);
  res.sendStatus(204);
});

projectsRouter.get("/:id/tasks", (req, res) => {
  res.json(taskService.listForProject(who(req), req.params.id));
});

projectsRouter.get("/:id/export", (req, res) => {
  res.json(projectService.exportFor(who(req), req.params.id));
});
