import { timeEntryRepo } from "../repositories/timeEntryRepo";
import { taskService } from "./taskService";
import type { User } from "../models/user";

export const timeEntryService = {
  list(user: User, taskId: string) {
    const task = taskService.require(user, taskId);
    return timeEntryRepo.forTask(task.id);
  },
};
