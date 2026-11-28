import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { checklistService } from "../services/checklistService";
import { parseChecklistInput } from "../validators/checklist";

export const checklistsRouter = Router();
const who = (req: unknown) => (req as AuthedRequest).user;

checklistsRouter.get("/", (req, res) => {
  res.json(checklistService.list(who(req)));
});

checklistsRouter.post("/", (req, res) => {
  res.status(201).json(checklistService.create(who(req), parseChecklistInput(req.body)));
});

checklistsRouter.get("/:id", (req, res) => {
  res.json(checklistService.require(who(req), req.params.id));
});

checklistsRouter.put("/:id", (req, res) => {
  res.json(checklistService.update(who(req), req.params.id, parseChecklistInput(req.body)));
});

checklistsRouter.delete("/:id", (req, res) => {
  checklistService.remove(who(req), req.params.id);
  res.sendStatus(204);
});

checklistsRouter.post("/:id/archive", (req, res) => {
  res.json(checklistService.archive(who(req), req.params.id));
});
