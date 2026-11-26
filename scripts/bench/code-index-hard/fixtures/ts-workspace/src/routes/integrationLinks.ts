import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { integrationLinkService } from "../services/integrationLinkService";
import { parseIntegrationLinkInput } from "../validators/integrationLink";

export const integrationLinksRouter = Router();
const who = (req: unknown) => (req as AuthedRequest).user;

integrationLinksRouter.get("/", (req, res) => {
  res.json(integrationLinkService.list(who(req)));
});

integrationLinksRouter.post("/", (req, res) => {
  res.status(201).json(integrationLinkService.create(who(req), parseIntegrationLinkInput(req.body)));
});

integrationLinksRouter.get("/:id", (req, res) => {
  res.json(integrationLinkService.require(who(req), req.params.id));
});

integrationLinksRouter.put("/:id", (req, res) => {
  res.json(integrationLinkService.update(who(req), req.params.id, parseIntegrationLinkInput(req.body)));
});

integrationLinksRouter.delete("/:id", (req, res) => {
  integrationLinkService.remove(who(req), req.params.id);
  res.sendStatus(204);
});
