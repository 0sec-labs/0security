import type { Shipment } from "../models/catalog";

class ShipmentRepo {
  private rows = new Map<string, Shipment>();

  add(shipment: Shipment): Shipment {
    this.rows.set(shipment.id, shipment);
    return shipment;
  }

  get(id: string): Shipment | undefined {
    return this.rows.get(id);
  }

  getForOrg(orgId: string, id: string): Shipment | undefined {
    const shipment = this.rows.get(id);
    return shipment && shipment.orgId === orgId ? shipment : undefined;
  }

  forOrg(orgId: string): Shipment[] {
    return [...this.rows.values()].filter((shipment) => shipment.orgId === orgId);
  }

  save(shipment: Shipment): Shipment {
    this.rows.set(shipment.id, shipment);
    return shipment;
  }
}

export const shipmentRepo = new ShipmentRepo();
