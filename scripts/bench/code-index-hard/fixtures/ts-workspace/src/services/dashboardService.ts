import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { forbidden, notFound } from "../lib/http";
import { dashboardRepo } from "../repositories/dashboardRepo";
import type { DashboardInput } from "../validators/dashboard";
import type { User } from "../models/user";

export const dashboardService = {
  require(user: User, id: string) {
    const row = dashboardRepo.get(id);
    if (!row || row.orgId !== user.orgId) throw notFound();
    return row;
  },

  requireWritable(user: User, id: string) {
    const row = dashboardService.require(user, id);
    if (row.ownerId !== user.id && user.role === "member") throw forbidden();
    return row;
  },

  list(user: User) {
    return dashboardRepo.listForOrg(user.orgId);
  },

  create(user: User, input: DashboardInput) {
    return dashboardRepo.insert({ id: newId("dashboard"), orgId: user.orgId, ownerId: user.id, ...input, createdAt: now() });
  },

  update(user: User, id: string, input: DashboardInput) {
    const row = dashboardService.requireWritable(user, id);
    return dashboardRepo.update(row.id, input);
  },

  remove(user: User, id: string) {
    const row = dashboardService.requireWritable(user, id);
    dashboardRepo.remove(row.id);
  },
};
