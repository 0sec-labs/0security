import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { sprintService } from "../services/sprintService";
import { parseSprintInput } from "../validators/sprint";

export const sprintsRouter = Router();
const who = (req: unknown) => (req as AuthedRequest).user;

sprintsRouter.get("/", (req, res) => {
  res.json(sprintService.list(who(req)));
});

sprintsRouter.post("/", (req, res) => {
  res.status(201).json(sprintService.create(who(req), parseSprintInput(req.body)));
});

sprintsRouter.get("/:id", (req, res) => {
  res.json(sprintService.require(who(req), req.params.id));
});

sprintsRouter.put("/:id", (req, res) => {
  res.json(sprintService.update(who(req), req.params.id, parseSprintInput(req.body)));
});

sprintsRouter.delete("/:id", (req, res) => {
  sprintService.remove(who(req), req.params.id);
  res.sendStatus(204);
});
