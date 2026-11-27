import { notFound } from "../lib/errors";
import { shipmentRepo } from "../repositories/shipmentRepo";

export function shipmentCostReport(shipmentId: string) {
  const shipment = shipmentRepo.get(shipmentId);
  if (!shipment) throw notFound("shipment");
  return {
    id: shipment.id,
    orderRef: shipment.orderRef,
    carrier: shipment.carrier,
    destination: shipment.destination,
    cost: shipment.cost,
    billedAmount: shipment.billedAmount,
    margin: shipment.billedAmount - shipment.cost,
  };
}

export function shipmentTimeline(orgId: string, shipmentId: string) {
  const shipment = shipmentRepo.getForOrg(orgId, shipmentId);
  if (!shipment) throw notFound("shipment");
  return { id: shipment.id, status: shipment.status, events: shipment.events };
}

export function carrierTotals(orgId: string) {
  const totals: Record<string, { shipments: number; cost: number }> = {};
  for (const shipment of shipmentRepo.forOrg(orgId)) {
    const entry = (totals[shipment.carrier] ??= { shipments: 0, cost: 0 });
    entry.shipments += 1;
    entry.cost += shipment.cost;
  }
  return totals;
}
