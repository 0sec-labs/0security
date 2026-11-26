import type { OrgRecord } from "./base";

export interface Task extends OrgRecord {
  title: string;
  done?: boolean;
  dueOn?: string;
  assigneeId?: string;
  createdAt: string;
}

export interface Project extends OrgRecord {
  name: string;
  status?: string;
  budget?: number;
  createdAt: string;
}

export interface Warehouse extends OrgRecord {
  name: string;
  city?: string;
  capacity?: number;
  createdAt: string;
}

export interface Supplier extends OrgRecord {
  name: string;
  email?: string;
  terms?: string;
  createdAt: string;
}

export interface PurchaseOrder extends OrgRecord {
  supplierId: string;
  reference?: string;
  amount?: number;
  status?: string;
  createdAt: string;
}

export interface Document extends OrgRecord {
  title: string;
  kind?: string;
  url?: string;
  createdAt: string;
}

export interface Expense extends OrgRecord {
  description: string;
  amount?: number;
  category?: string;
  incurredOn?: string;
  createdAt: string;
}
