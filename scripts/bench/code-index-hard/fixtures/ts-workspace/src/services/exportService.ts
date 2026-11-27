import { notFound } from "../lib/http";
import { safeSegment } from "../lib/sanitize";
import { projectRepo } from "../repositories/projectRepo";
import { taskRepo } from "../repositories/taskRepo";

export const exportService = {
  /** Full export of one project. Callers are expected to have authorised access to the project. */
  exportProject(projectId: string) {
    const project = projectRepo.get(projectId);
    if (!project) throw notFound();
    return {
      filename: `${safeSegment(project.name)}.json`,
      project: { id: project.id, name: project.name },
      tasks: taskRepo.listForProject(project.id).map((t) => ({ id: t.id, title: t.title, notes: t.notes, status: t.status, visibility: t.visibility })),
    };
  },
};
