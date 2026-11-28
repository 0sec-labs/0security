import { newId } from "../lib/ids";
import { now } from "../lib/clock";
import { timesheetRepo } from "../repositories/timesheetRepo";
import type { Timesheet } from "../models/timesheet";
import type { TimesheetInput } from "../validators/timesheet";

export const timesheetService = {
  list(orgId: string) {
    return timesheetRepo.listForOrg(orgId);
  },

  create(orgId: string, ownerId: string, input: TimesheetInput) {
    return timesheetRepo.insert({ id: newId("timesheet"), orgId: orgId, ownerId: ownerId, ...input, createdAt: now() });
  },

  update(row: Timesheet, input: TimesheetInput) {
    return timesheetRepo.update(row.id, input);
  },

  remove(row: Timesheet) {
    timesheetRepo.remove(row.id);
  },
};
