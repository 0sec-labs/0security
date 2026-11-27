import { notFound } from "../lib/http";
import { safeSegment } from "../lib/sanitize";
import { invoiceRepo } from "../repositories/invoiceRepo";

export const pdfService = {
  render(invoiceId: string) {
    const invoice = invoiceRepo.get(invoiceId);
    if (!invoice) throw notFound();
    const lines = invoice.lines.map((line) => `${line.description.padEnd(40)} ${(line.amountCents / 100).toFixed(2)}`);
    return {
      filename: `invoice-${safeSegment(invoice.number)}.txt`,
      body: [`Invoice ${invoice.number}`, `Customer: ${invoice.customer}`, "", ...lines, "", `Total ${(invoice.amountCents / 100).toFixed(2)}`, invoice.internalNote].join("\n"),
    };
  },
};
