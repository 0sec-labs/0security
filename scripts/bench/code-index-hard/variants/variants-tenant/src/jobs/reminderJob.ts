import { sendMail } from "../lib/mailer";
import { customerRepo } from "../repositories/customerRepo";
import { invoiceRepo } from "../repositories/invoiceRepo";
import type { Job } from "./queue";

export async function invoiceReminder(job: Job<{ invoiceId: string; to: string }>) {
  const invoice = invoiceRepo.findById(job.payload.invoiceId);
  if (!invoice) throw new Error("invoice not found");
  const customer = customerRepo.findForOrg(invoice.orgId, invoice.customerId);
  const subject = "Reminder: invoice " + invoice.number + " is due " + invoice.dueDate;
  const items = invoice.lines.map((line) => line.qty + " x " + line.description + " at " + line.unitPrice);
  const body = ["Hello " + (customer?.name ?? "there"), ...items, "Total " + invoice.total + " " + invoice.currency].join("\n");
  sendMail({ to: job.payload.to, subject, body });
  return { delivered: true, to: job.payload.to, subject, body };
}
