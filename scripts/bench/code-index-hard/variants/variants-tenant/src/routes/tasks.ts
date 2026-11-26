import { Router } from "express";
import type { Request } from "express";
import { taskRepo } from "../repositories/opsRepos";
import type { Task } from "../models/ops";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { newId, isoNow } from "../lib/ids";

const FIELDS = ["title", "done", "dueOn", "assigneeId"] as const;
const REQUIRED = ["title"] as const;

export const tasksRouter = Router();

const owned = (req: Request) => taskRepo.findForOrg(req.user!.orgId, req.params.id as string);

tasksRouter
  .route("/")
  .get((req, res) => {
    res.json(taskRepo.listForOrg(req.user!.orgId));
  })
  .post((req, res) => {
    const data = pick(req.body, FIELDS);
    requireFields(data, REQUIRED);
    const record = taskRepo.insert({ ...data, id: newId("tsk"), orgId: req.user!.orgId, createdAt: isoNow() } as Task);
    res.status(201).json(record);
  });

tasksRouter
  .route("/:id")
  .get((req, res) => {
    const record = owned(req);
    if (!record) return res.status(404).json({ error: "task not found" });
    res.json(record);
  })
  .put((req, res) => {
    const record = owned(req);
    if (!record) return res.status(404).json({ error: "task not found" });
    res.json(taskRepo.save({ ...record, ...pick(req.body, FIELDS) }));
  })
  .delete(requireRole("admin", "manager"), (req, res) => {
    const record = owned(req);
    if (!record) return res.status(404).json({ error: "task not found" });
    taskRepo.remove(record.id);
    res.status(204).end();
  });
