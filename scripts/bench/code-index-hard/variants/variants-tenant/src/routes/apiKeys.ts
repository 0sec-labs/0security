import { Router } from "express";
import { notFound } from "../lib/errors";
import type { AuthUser } from "../models/base";
import { apiKeyRepo } from "../repositories/financeRepos";
import type { ApiKeyRecord } from "../models/finance";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { newId, isoNow } from "../lib/ids";

const FIELDS = ["label", "prefix", "scopes"] as const;
const REQUIRED = ["label"] as const;

export const apiKeysRouter = Router();

const service = {
  list(user: AuthUser): ApiKeyRecord[] {
    return apiKeyRepo.listForOrg(user.orgId);
  },
  get(user: AuthUser, id: string): ApiKeyRecord {
    const record = apiKeyRepo.findForOrg(user.orgId, id);
    if (!record) throw notFound("api key record");
    return record;
  },
  create(user: AuthUser, body: unknown): ApiKeyRecord {
    const data = pick(body, FIELDS);
    requireFields(data, REQUIRED);
    return apiKeyRepo.insert({ ...data, id: newId("key"), orgId: user.orgId, createdAt: isoNow() } as ApiKeyRecord);
  },
  update(user: AuthUser, id: string, body: unknown): ApiKeyRecord {
    return apiKeyRepo.save({ ...service.get(user, id), ...pick(body, FIELDS) });
  },
  remove(user: AuthUser, id: string): void {
    apiKeyRepo.remove(service.get(user, id).id);
  },
};

apiKeysRouter.get("/", (req, res) => {
  res.json(service.list(req.user!));
});

apiKeysRouter.post("/", (req, res) => {
  res.status(201).json(service.create(req.user!, req.body));
});

apiKeysRouter.get("/:id", (req, res) => {
  res.json(service.get(req.user!, req.params.id));
});

apiKeysRouter.put("/:id", (req, res) => {
  res.json(service.update(req.user!, req.params.id, req.body));
});

apiKeysRouter.delete("/:id", requireRole("admin", "manager", "member"), (req, res) => {
  service.remove(req.user!, req.params.id);
  res.status(204).end();
});
