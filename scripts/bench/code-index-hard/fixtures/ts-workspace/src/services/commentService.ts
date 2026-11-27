import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { cleanName } from "../lib/sanitize";
import { commentRepo } from "../repositories/commentRepo";
import { userRepo } from "../repositories/userRepo";
import { taskService } from "./taskService";
import type { User } from "../models/user";

export interface CommentInput {
  orgId: string;
  taskId: string;
  authorId: string;
  body: string;
}

export const commentService = {
  add(input: CommentInput) {
    return commentRepo.insert({ ...input, id: newId("cmt"), createdAt: now() });
  },

  list(user: User, taskId: string) {
    const task = taskService.require(user, taskId);
    return commentRepo.forTask(task.id).map((comment) => ({
      ...comment,
      authorName: cleanName(userRepo.get(comment.authorId)?.name ?? "unknown"),
    }));
  },
};
