package com.ledger.purchaseorders;

public record PurchaseOrderDto(String id,
        String number, String vendorRef, long totalCents,
        String status) {
}
