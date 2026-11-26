import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { labelService } from "../services/labelService";
import { parseLabelInput } from "../validators/label";

export const labelsRouter = Router();
const who = (req: unknown) => (req as AuthedRequest).user;

labelsRouter.get("/", (req, res) => {
  res.json(labelService.list(who(req)));
});

labelsRouter.post("/", (req, res) => {
  res.status(201).json(labelService.create(who(req), parseLabelInput(req.body)));
});

labelsRouter.get("/:id", (req, res) => {
  res.json(labelService.require(who(req), req.params.id));
});

labelsRouter.put("/:id", (req, res) => {
  res.json(labelService.update(who(req), req.params.id, parseLabelInput(req.body)));
});

labelsRouter.delete("/:id", (req, res) => {
  labelService.remove(who(req), req.params.id);
  res.sendStatus(204);
});
