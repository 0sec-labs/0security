import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { apiKeyService } from "../services/apiKeyService";
import { parseApiKeyInput } from "../validators/apiKey";

export const apiKeysRouter = Router();
const who = (req: unknown) => (req as AuthedRequest).user;

apiKeysRouter.get("/", (req, res) => {
  res.json(apiKeyService.list(who(req)));
});

apiKeysRouter.post("/", (req, res) => {
  res.status(201).json(apiKeyService.create(who(req), parseApiKeyInput(req.body)));
});

apiKeysRouter.get("/:id", (req, res) => {
  res.json(apiKeyService.require(who(req), req.params.id));
});

apiKeysRouter.put("/:id", (req, res) => {
  res.json(apiKeyService.update(who(req), req.params.id, parseApiKeyInput(req.body)));
});

apiKeysRouter.delete("/:id", (req, res) => {
  apiKeyService.remove(who(req), req.params.id);
  res.sendStatus(204);
});
