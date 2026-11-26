import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { templateService } from "../services/templateService";
import { parseTemplateInput } from "../validators/template";

export const templatesRouter = Router();
const who = (req: unknown) => (req as AuthedRequest).user;

templatesRouter.get("/", (req, res) => {
  res.json(templateService.list(who(req)));
});

templatesRouter.post("/", (req, res) => {
  res.status(201).json(templateService.create(who(req), parseTemplateInput(req.body)));
});

templatesRouter.get("/:id", (req, res) => {
  res.json(templateService.require(who(req), req.params.id));
});

templatesRouter.put("/:id", (req, res) => {
  res.json(templateService.update(who(req), req.params.id, parseTemplateInput(req.body)));
});

templatesRouter.delete("/:id", (req, res) => {
  templateService.remove(who(req), req.params.id);
  res.sendStatus(204);
});

templatesRouter.post("/:id/archive", (req, res) => {
  res.json(templateService.archive(who(req), req.params.id));
});
