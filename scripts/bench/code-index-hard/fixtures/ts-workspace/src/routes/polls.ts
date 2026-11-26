import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { pollService } from "../services/pollService";
import { parsePollInput } from "../validators/poll";

export const pollsRouter = Router();
const who = (req: unknown) => (req as AuthedRequest).user;

pollsRouter.get("/", (req, res) => {
  res.json(pollService.list(who(req)));
});

pollsRouter.post("/", (req, res) => {
  res.status(201).json(pollService.create(who(req), parsePollInput(req.body)));
});

pollsRouter.get("/:id", (req, res) => {
  res.json(pollService.require(who(req), req.params.id));
});

pollsRouter.put("/:id", (req, res) => {
  res.json(pollService.update(who(req), req.params.id, parsePollInput(req.body)));
});

pollsRouter.delete("/:id", (req, res) => {
  pollService.remove(who(req), req.params.id);
  res.sendStatus(204);
});
