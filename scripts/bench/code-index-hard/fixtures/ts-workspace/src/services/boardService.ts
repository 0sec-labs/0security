import { notFound } from "../lib/http";
import { boardRepo } from "../repositories/boardRepo";
import { projectRepo } from "../repositories/projectRepo";
import { taskRepo } from "../repositories/taskRepo";

export const boardService = {
  published(slug: string) {
    const board = boardRepo.bySlug(slug);
    if (!board || !board.published) throw notFound();
    return board;
  },

  publicView(slug: string) {
    const board = boardService.published(slug);
    const project = projectRepo.get(board.projectId);
    const tasks = taskRepo.listForProject(board.projectId).filter((t) => t.visibility === "public");
    return { name: project?.name ?? slug, tasks: tasks.map((t) => ({ title: t.title, status: t.status })) };
  },
};
