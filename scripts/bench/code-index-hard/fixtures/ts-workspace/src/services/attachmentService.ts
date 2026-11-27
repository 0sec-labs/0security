import { newId } from "../lib/ids";
import { forbidden, notFound } from "../lib/http";
import { cleanName } from "../lib/sanitize";
import { storage } from "../lib/storage";
import { attachmentRepo } from "../repositories/attachmentRepo";
import { taskService } from "./taskService";
import type { User } from "../models/user";

export const attachmentService = {
  list(user: User, taskId: string) {
    const task = taskService.require(user, taskId);
    return attachmentRepo.forTask(task.id);
  },

  upload(user: User, taskId: string, input: { filename: string; content: string }) {
    const task = taskService.require(user, taskId);
    const name = cleanName(String(input.filename ?? ""));
    if (!name) throw forbidden();
    const key = storage.put(`${task.orgId}/${task.id}/${name}`, String(input.content ?? ""));
    return attachmentRepo.insert({ id: newId("att"), orgId: task.orgId, taskId: task.id, uploaderId: user.id, filename: name, storageKey: key });
  },

  download(user: User, id: string) {
    const attachment = attachmentRepo.get(id);
    if (!attachment || attachment.orgId !== user.orgId) throw notFound();
    return { filename: attachment.filename, body: storage.read(attachment.storageKey) };
  },
};
