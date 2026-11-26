import type { OrgRecord } from "./base";

export interface Product extends OrgRecord {
  sku: string;
  name: string;
  unitPrice: number;
  unitCost: number;
  active: boolean;
}

export interface ShipmentEvent {
  status: string;
  at: string;
}

export interface Shipment extends OrgRecord {
  orderRef: string;
  carrier: string;
  trackingNo: string;
  status: string;
  cost: number;
  billedAmount: number;
  destination: string;
  events: ShipmentEvent[];
}

export interface IntegrationAccount extends OrgRecord {
  provider: "payments" | "carrier";
  externalAccountId: string;
}

export interface Currency {
  id: string;
  name: string;
  symbol: string;
}

export interface Country {
  id: string;
  name: string;
}

export interface Plan {
  id: string;
  name: string;
  monthlyAmount: number;
  seatLimit: number;
}
