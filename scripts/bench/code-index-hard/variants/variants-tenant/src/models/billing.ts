import type { OrgRecord } from "./base";

export interface Customer extends OrgRecord {
  name: string;
  email: string;
  billingAddress?: string;
  createdAt: string;
}

export interface InvoiceLine {
  description: string;
  qty: number;
  unitPrice: number;
}

export interface Invoice extends OrgRecord {
  customerId: string;
  number: string;
  status: "draft" | "open" | "paid" | "void";
  currency: string;
  lines: InvoiceLine[];
  total: number;
  dueDate: string;
  paidReference?: string;
  createdAt: string;
}

export interface Payment extends OrgRecord {
  invoiceId: string;
  amount: number;
  method: string;
  receivedAt: string;
}

export interface CreditNote extends OrgRecord {
  invoiceId: string;
  amount: number;
  reason: string;
}

export interface Refund extends OrgRecord {
  paymentId: string;
  amount: number;
  status: string;
}

export interface Subscription extends OrgRecord {
  customerId: string;
  planId: string;
  status: "active" | "paused" | "cancelled";
  seats: number;
  currentPeriodEnd: string;
  monthlyAmount: number;
  paymentMethodLast4: string;
}

export interface Contract extends OrgRecord {
  customerId: string;
  title: string;
  terms: string;
  value: number;
  startsOn: string;
  endsOn: string;
  status: "draft" | "active" | "expired";
}

export interface Quote extends OrgRecord {
  customerId: string;
  title: string;
  lines: InvoiceLine[];
  total: number;
  validUntil: string;
  status: "draft" | "sent" | "accepted";
  internalNotes: string;
}
