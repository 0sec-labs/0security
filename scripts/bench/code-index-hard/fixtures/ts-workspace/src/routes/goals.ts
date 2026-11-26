import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { goalService } from "../services/goalService";
import { parseGoalInput } from "../validators/goal";

export const goalsRouter = Router();
const who = (req: unknown) => (req as AuthedRequest).user;

goalsRouter.get("/", (req, res) => {
  res.json(goalService.list(who(req)));
});

goalsRouter.post("/", (req, res) => {
  res.status(201).json(goalService.create(who(req), parseGoalInput(req.body)));
});

goalsRouter.get("/:id", (req, res) => {
  res.json(goalService.require(who(req), req.params.id));
});

goalsRouter.put("/:id", (req, res) => {
  res.json(goalService.update(who(req), req.params.id, parseGoalInput(req.body)));
});

goalsRouter.delete("/:id", (req, res) => {
  goalService.remove(who(req), req.params.id);
  res.sendStatus(204);
});

goalsRouter.post("/:id/archive", (req, res) => {
  res.json(goalService.archive(who(req), req.params.id));
});
