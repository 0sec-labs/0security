import { Table } from "../db";
import type { Attachment } from "../models/attachment";

const table = new Table<Attachment>("attachments");

export const attachmentRepo = {
  get: (id: string) => table.get(id),
  forTask: (taskId: string) => table.where((a) => a.taskId === taskId),
  insert: (attachment: Attachment) => table.insert(attachment),
};
