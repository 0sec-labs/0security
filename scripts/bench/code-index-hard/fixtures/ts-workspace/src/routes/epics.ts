import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { epicService } from "../services/epicService";
import { parseEpicInput } from "../validators/epic";

export const epicsRouter = Router();
const who = (req: unknown) => (req as AuthedRequest).user;

epicsRouter.get("/", (req, res) => {
  res.json(epicService.list(who(req)));
});

epicsRouter.post("/", (req, res) => {
  res.status(201).json(epicService.create(who(req), parseEpicInput(req.body)));
});

epicsRouter.get("/:id", (req, res) => {
  res.json(epicService.require(who(req), req.params.id));
});

epicsRouter.put("/:id", (req, res) => {
  res.json(epicService.update(who(req), req.params.id, parseEpicInput(req.body)));
});

epicsRouter.delete("/:id", (req, res) => {
  epicService.remove(who(req), req.params.id);
  res.sendStatus(204);
});
