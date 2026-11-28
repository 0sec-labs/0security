import { newId } from "../lib/ids";
import { forbidden, notFound } from "../lib/http";
import { projectRepo } from "../repositories/projectRepo";
import { activityService } from "./activityService";
import { exportService } from "./exportService";
import type { User } from "../models/user";

export const projectService = {
  require(user: User, id: string) {
    const project = projectRepo.get(id);
    if (!project || project.orgId !== user.orgId) throw notFound();
    return project;
  },

  list(user: User) {
    return projectRepo.listForOrg(user.orgId);
  },

  create(user: User, input: { name: string }) {
    const project = projectRepo.insert({ id: newId("prj"), orgId: user.orgId, ownerId: user.id, name: String(input.name ?? "").slice(0, 80), archived: false });
    activityService.record(user, "project", project.id, "created", project.name);
    return project;
  },

  update(user: User, id: string, patch: { name?: string; archived?: boolean }) {
    const project = projectService.require(user, id);
    if (project.ownerId !== user.id && user.role === "member") throw forbidden();
    return projectRepo.update(project.id, { name: patch.name ?? project.name, archived: patch.archived ?? project.archived });
  },

  remove(user: User, id: string) {
    const project = projectService.require(user, id);
    if (user.role === "member") throw forbidden();
    projectRepo.remove(project.id);
  },

  exportFor(user: User, id: string) {
    const project = projectService.require(user, id);
    return exportService.exportProject(project.id);
  },
};
