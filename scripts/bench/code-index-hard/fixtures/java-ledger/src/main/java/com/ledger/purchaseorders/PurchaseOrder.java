package com.ledger.purchaseorders;

public record PurchaseOrder(String id, String tenantId, String ownerId,
        String number, String vendorRef, long totalCents,
        String status) {
}
