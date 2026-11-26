export interface Invoice {
  id: string;
  orgId: string;
  number: string;
  customer: string;
  amountCents: number;
  status: "draft" | "sent" | "paid";
  lines: Array<{ description: string; amountCents: number }>;
  internalNote: string;
}
