import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { componentService } from "../services/componentService";
import { parseComponentInput } from "../validators/component";

export const componentsRouter = Router();
const who = (req: unknown) => (req as AuthedRequest).user;

componentsRouter.get("/", (req, res) => {
  res.json(componentService.list(who(req)));
});

componentsRouter.post("/", (req, res) => {
  res.status(201).json(componentService.create(who(req), parseComponentInput(req.body)));
});

componentsRouter.get("/:id", (req, res) => {
  res.json(componentService.require(who(req), req.params.id));
});

componentsRouter.put("/:id", (req, res) => {
  res.json(componentService.update(who(req), req.params.id, parseComponentInput(req.body)));
});

componentsRouter.delete("/:id", (req, res) => {
  componentService.remove(who(req), req.params.id);
  res.sendStatus(204);
});
