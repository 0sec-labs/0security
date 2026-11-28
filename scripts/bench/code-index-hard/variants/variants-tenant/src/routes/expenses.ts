import { Router } from "express";
import { notFound } from "../lib/errors";
import type { AuthUser } from "../models/base";
import { expenseRepo } from "../repositories/opsRepos";
import type { Expense } from "../models/ops";
import { requireRole } from "../middleware/requireRole";
import { pick, requireFields } from "../lib/validate";
import { newId, isoNow } from "../lib/ids";

const FIELDS = ["description", "amount", "category", "incurredOn"] as const;
const REQUIRED = ["description"] as const;

export const expensesRouter = Router();

const service = {
  list(user: AuthUser): Expense[] {
    return expenseRepo.listForOrg(user.orgId);
  },
  get(user: AuthUser, id: string): Expense {
    const record = expenseRepo.findForOrg(user.orgId, id);
    if (!record) throw notFound("expense");
    return record;
  },
  create(user: AuthUser, body: unknown): Expense {
    const data = pick(body, FIELDS);
    requireFields(data, REQUIRED);
    return expenseRepo.insert({ ...data, id: newId("exp"), orgId: user.orgId, createdAt: isoNow() } as Expense);
  },
  update(user: AuthUser, id: string, body: unknown): Expense {
    return expenseRepo.save({ ...service.get(user, id), ...pick(body, FIELDS) });
  },
  remove(user: AuthUser, id: string): void {
    expenseRepo.remove(service.get(user, id).id);
  },
};

expensesRouter.get("/", (req, res) => {
  res.json(service.list(req.user!));
});

expensesRouter.post("/", (req, res) => {
  res.status(201).json(service.create(req.user!, req.body));
});

expensesRouter.get("/:id", (req, res) => {
  res.json(service.get(req.user!, req.params.id));
});

expensesRouter.put("/:id", (req, res) => {
  res.json(service.update(req.user!, req.params.id, req.body));
});

expensesRouter.delete("/:id", requireRole("admin", "manager", "member"), (req, res) => {
  service.remove(req.user!, req.params.id);
  res.status(204).end();
});
