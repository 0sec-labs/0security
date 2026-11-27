import { orgRepo } from "../repositories/orgRepo";
import { userRepo } from "../repositories/userRepo";
import { activityRepo } from "../repositories/activityRepo";
import { notFound } from "../lib/http";
import type { Role } from "../config/security";

export const adminService = {
  listUsers() {
    return userRepo.all().map((u) => ({ id: u.id, orgId: u.orgId, name: u.name, email: u.email, role: u.role }));
  },

  setRole(userId: string, role: Role) {
    const user = userRepo.update(userId, { role });
    if (!user) throw notFound();
    return { id: user.id, role: user.role };
  },

  listOrgs() {
    return orgRepo.all();
  },

  auditLog() {
    return activityRepo.all();
  },
};
