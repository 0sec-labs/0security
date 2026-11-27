import { commentRepo } from "../repositories/commentRepo";
import { projectRepo } from "../repositories/projectRepo";
import { taskRepo } from "../repositories/taskRepo";
import type { User } from "../models/user";

export const searchService = {
  search(user: User, query: string) {
    const q = query.trim();
    if (q.length < 2) return { tasks: [], projects: [], comments: [] };
    return {
      tasks: taskRepo.search(user.orgId, q).map((t) => ({ id: t.id, title: t.title })),
      projects: projectRepo.search(user.orgId, q).map((p) => ({ id: p.id, name: p.name })),
      comments: commentRepo.search(q).map((c) => ({ id: c.id, taskId: c.taskId, body: c.body.slice(0, 160) })),
    };
  },
};
