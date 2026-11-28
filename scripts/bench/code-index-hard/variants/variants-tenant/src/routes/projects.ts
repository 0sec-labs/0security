import { Router } from "express";
import { notFound } from "../lib/errors";
import type { AuthUser } from "../models/base";
import { projectRepo } from "../repositories/opsRepos";
import type { Project } from "../models/ops";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { newId, isoNow } from "../lib/ids";

const FIELDS = ["name", "status", "budget"] as const;
const REQUIRED = ["name"] as const;

export const projectsRouter = Router();

const service = {
  list(user: AuthUser): Project[] {
    return projectRepo.listForOrg(user.orgId);
  },
  get(user: AuthUser, id: string): Project {
    const record = projectRepo.findForOrg(user.orgId, id);
    if (!record) throw notFound("project");
    return record;
  },
  create(user: AuthUser, body: unknown): Project {
    const data = pick(body, FIELDS);
    requireFields(data, REQUIRED);
    return projectRepo.insert({ ...data, id: newId("prj"), orgId: user.orgId, createdAt: isoNow() } as Project);
  },
  update(user: AuthUser, id: string, body: unknown): Project {
    return projectRepo.save({ ...service.get(user, id), ...pick(body, FIELDS) });
  },
  remove(user: AuthUser, id: string): void {
    projectRepo.remove(service.get(user, id).id);
  },
};

projectsRouter.get("/", (req, res) => {
  res.json(service.list(req.user!));
});

projectsRouter.post("/", (req, res) => {
  res.status(201).json(service.create(req.user!, req.body));
});

projectsRouter.get("/:id", (req, res) => {
  res.json(service.get(req.user!, req.params.id));
});

projectsRouter.put("/:id", (req, res) => {
  res.json(service.update(req.user!, req.params.id, req.body));
});

projectsRouter.delete("/:id", requireRole("admin", "manager", "member"), (req, res) => {
  service.remove(req.user!, req.params.id);
  res.status(204).end();
});
