import { Order } from "../db";

export function cancelOrder(order: Order) {
  if (order.status === "cancelled") return order;
  order.status = "cancelled";
  return order;
}

export function issueRefund(order: Order, amountCents: number) {
  order.refundedCents += amountCents;
  return { orderId: order.id, refundedCents: order.refundedCents };
}
