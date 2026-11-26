import { Router } from "express";
import { notFound } from "../lib/errors";
import type { AuthUser } from "../models/base";
import { campaignRepo } from "../repositories/crmRepos";
import type { Campaign } from "../models/crm";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { newId, isoNow } from "../lib/ids";

const FIELDS = ["name", "channel", "budget", "active"] as const;
const REQUIRED = ["name"] as const;

export const campaignsRouter = Router();

const service = {
  list(user: AuthUser): Campaign[] {
    return campaignRepo.listForOrg(user.orgId);
  },
  get(user: AuthUser, id: string): Campaign {
    const record = campaignRepo.findForOrg(user.orgId, id);
    if (!record) throw notFound("campaign");
    return record;
  },
  create(user: AuthUser, body: unknown): Campaign {
    const data = pick(body, FIELDS);
    requireFields(data, REQUIRED);
    return campaignRepo.insert({ ...data, id: newId("cmp"), orgId: user.orgId, createdAt: isoNow() } as Campaign);
  },
  update(user: AuthUser, id: string, body: unknown): Campaign {
    return campaignRepo.save({ ...service.get(user, id), ...pick(body, FIELDS) });
  },
  remove(user: AuthUser, id: string): void {
    campaignRepo.remove(service.get(user, id).id);
  },
};

campaignsRouter.get("/", (req, res) => {
  res.json(service.list(req.user!));
});

campaignsRouter.post("/", (req, res) => {
  res.status(201).json(service.create(req.user!, req.body));
});

campaignsRouter.get("/:id", (req, res) => {
  res.json(service.get(req.user!, req.params.id));
});

campaignsRouter.put("/:id", (req, res) => {
  res.json(service.update(req.user!, req.params.id, req.body));
});

campaignsRouter.delete("/:id", requireRole("admin", "manager", "member"), (req, res) => {
  service.remove(req.user!, req.params.id);
  res.status(204).end();
});
