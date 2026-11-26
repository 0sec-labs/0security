import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { tagService } from "../services/tagService";
import { parseTagInput } from "../validators/tag";

export const tagsRouter = Router();
const who = (req: unknown) => (req as AuthedRequest).user;

tagsRouter.get("/", (req, res) => {
  res.json(tagService.list(who(req)));
});

tagsRouter.post("/", (req, res) => {
  res.status(201).json(tagService.create(who(req), parseTagInput(req.body)));
});

tagsRouter.get("/:id", (req, res) => {
  res.json(tagService.require(who(req), req.params.id));
});

tagsRouter.put("/:id", (req, res) => {
  res.json(tagService.update(who(req), req.params.id, parseTagInput(req.body)));
});

tagsRouter.delete("/:id", (req, res) => {
  tagService.remove(who(req), req.params.id);
  res.sendStatus(204);
});

tagsRouter.post("/:id/archive", (req, res) => {
  res.json(tagService.archive(who(req), req.params.id));
});
