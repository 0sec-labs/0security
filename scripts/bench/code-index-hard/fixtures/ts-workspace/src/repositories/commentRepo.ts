import { Table } from "../db";
import type { Comment } from "../models/comment";

const table = new Table<Comment>("comments");

export const commentRepo = {
  get: (id: string) => table.get(id),
  forTask: (taskId: string) => table.where((c) => c.taskId === taskId),
  search: (q: string) => table.where((c) => c.body.toLowerCase().includes(q.toLowerCase())),
  insert: (comment: Comment) => table.insert(comment),
};
