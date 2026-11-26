import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { releaseService } from "../services/releaseService";
import { parseReleaseInput } from "../validators/release";

export const releasesRouter = Router();
const who = (req: unknown) => (req as AuthedRequest).user;

releasesRouter.get("/", (req, res) => {
  res.json(releaseService.list(who(req)));
});

releasesRouter.post("/", (req, res) => {
  res.status(201).json(releaseService.create(who(req), parseReleaseInput(req.body)));
});

releasesRouter.get("/:id", (req, res) => {
  res.json(releaseService.require(who(req), req.params.id));
});

releasesRouter.put("/:id", (req, res) => {
  res.json(releaseService.update(who(req), req.params.id, parseReleaseInput(req.body)));
});

releasesRouter.delete("/:id", (req, res) => {
  releaseService.remove(who(req), req.params.id);
  res.sendStatus(204);
});

releasesRouter.post("/:id/archive", (req, res) => {
  res.json(releaseService.archive(who(req), req.params.id));
});
