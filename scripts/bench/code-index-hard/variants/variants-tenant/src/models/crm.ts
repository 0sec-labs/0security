import type { OrgRecord } from "./base";

export interface Contact extends OrgRecord {
  name: string;
  email?: string;
  phone?: string;
  title?: string;
  createdAt: string;
}

export interface Deal extends OrgRecord {
  title: string;
  amount?: number;
  stage?: string;
  customerId?: string;
  createdAt: string;
}

export interface Lead extends OrgRecord {
  name: string;
  email?: string;
  source?: string;
  score?: number;
  createdAt: string;
}

export interface Campaign extends OrgRecord {
  name: string;
  channel?: string;
  budget?: number;
  active?: boolean;
  createdAt: string;
}

export interface Activity extends OrgRecord {
  kind: string;
  summary?: string;
  dueOn?: string;
  createdAt: string;
}

export interface Note extends OrgRecord {
  subject: string;
  body?: string;
  createdAt: string;
}

export interface Tag extends OrgRecord {
  label: string;
  color?: string;
  createdAt: string;
}
