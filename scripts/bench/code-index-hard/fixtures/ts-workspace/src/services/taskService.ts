import { newId } from "../lib/ids";
import { forbidden, notFound } from "../lib/http";
import { taskRepo } from "../repositories/taskRepo";
import { projectRepo } from "../repositories/projectRepo";
import { activityService } from "./activityService";
import { projectService } from "./projectService";
import type { User } from "../models/user";

export const taskService = {
  require(user: User, id: string) {
    const task = taskRepo.get(id);
    if (!task || task.orgId !== user.orgId) throw notFound();
    return task;
  },

  requireWritable(user: User, id: string) {
    const task = taskService.require(user, id);
    if (task.ownerId !== user.id && user.role === "member") throw forbidden();
    return task;
  },

  listForProject(user: User, projectId: string) {
    const project = projectService.require(user, projectId);
    return taskRepo.listForProject(project.id);
  },

  create(user: User, input: { projectId: string; title: string; notes?: string; parentId?: string }) {
    const project = projectService.require(user, input.projectId);
    if (input.parentId) taskService.require(user, input.parentId);
    const task = taskRepo.insert({
      id: newId("tsk"),
      orgId: project.orgId,
      projectId: project.id,
      ownerId: user.id,
      parentId: input.parentId,
      title: String(input.title ?? "").slice(0, 200),
      notes: String(input.notes ?? ""),
      visibility: "private",
      watchers: [user.id],
      status: "open",
    });
    activityService.record(user, "task", task.id, "created", task.title);
    return task;
  },

  update(user: User, id: string, patch: { title?: string; notes?: string; status?: "open" | "done"; visibility?: "public" | "private" }) {
    const task = taskService.requireWritable(user, id);
    const next = taskRepo.update(task.id, {
      title: patch.title ?? task.title,
      notes: patch.notes ?? task.notes,
      status: patch.status ?? task.status,
      visibility: patch.visibility ?? task.visibility,
    });
    activityService.record(user, "task", task.id, "updated", Object.keys(patch).join(","));
    return next;
  },

  remove(user: User, id: string) {
    const task = taskService.requireWritable(user, id);
    taskRepo.remove(task.id);
    activityService.record(user, "task", task.id, "deleted", task.title);
  },

  subtasks(user: User, id: string) {
    const task = taskService.require(user, id);
    return taskRepo.children(task.id);
  },

  watchers(user: User, id: string) {
    return taskService.require(user, id).watchers;
  },

  watch(user: User, id: string) {
    const task = taskService.require(user, id);
    if (!task.watchers.includes(user.id)) taskRepo.update(task.id, { watchers: [...task.watchers, user.id] });
    return taskRepo.get(task.id)?.watchers ?? [];
  },

  move(user: User, id: string, projectId: string) {
    const task = taskService.requireWritable(user, id);
    const target = projectRepo.get(projectId);
    if (!target) throw notFound();
    const moved = taskRepo.update(task.id, { projectId: target.id, orgId: target.orgId });
    activityService.record(user, "task", task.id, "moved", target.id);
    return moved;
  },
};
