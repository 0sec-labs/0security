import type { OrgRecord } from "./base";

export interface Category extends OrgRecord {
  name: string;
  parentId?: string;
  createdAt: string;
}

export interface Coupon extends OrgRecord {
  code: string;
  percentOff?: number;
  active?: boolean;
  createdAt: string;
}

export interface PriceList extends OrgRecord {
  name: string;
  currency?: string;
  createdAt: string;
}

export interface TaxRate extends OrgRecord {
  name: string;
  ratePercent?: number;
  region?: string;
  createdAt: string;
}

export interface ApiKeyRecord extends OrgRecord {
  label: string;
  prefix?: string;
  scopes?: string;
  createdAt: string;
}

export interface WebhookEndpoint extends OrgRecord {
  url: string;
  events?: string;
  active?: boolean;
  createdAt: string;
}
