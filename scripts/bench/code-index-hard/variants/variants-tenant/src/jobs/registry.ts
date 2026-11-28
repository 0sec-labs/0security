import { jobQueue } from "./queue";
import { invoiceReminder } from "./reminderJob";
import { contractRenewal } from "./renewalJob";

export function registerJobs(): void {
  jobQueue.register("invoice-reminder", invoiceReminder);
  jobQueue.register("contract-renewal", contractRenewal);
}
