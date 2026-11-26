import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { requireOrgRole } from "../middleware/requireOrgRole";
import { webhookService } from "../services/webhookService";

export const webhooksRouter = Router();
const who = (req: unknown) => (req as AuthedRequest).user;

webhooksRouter.get("/", (req, res) => {
  res.json(webhookService.list(who(req)));
});

webhooksRouter.get("/:id/deliveries", (req, res) => {
  res.json(webhookService.deliveries(who(req), req.params.id));
});

webhooksRouter.use(requireOrgRole("manager"));

webhooksRouter.post("/", (req, res) => {
  res.status(201).json(webhookService.create(who(req), req.body ?? {}));
});

webhooksRouter.put("/:id", (req, res) => {
  res.json(webhookService.update(who(req), req.params.id, req.body ?? {}));
});

webhooksRouter.delete("/:id", (req, res) => {
  webhookService.remove(who(req), req.params.id);
  res.sendStatus(204);
});

webhooksRouter.post("/:id/rotate", (req, res) => {
  res.json(webhookService.rotate(who(req), req.params.id));
});
