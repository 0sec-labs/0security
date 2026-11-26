package com.ledger.perdiems;

public record PerDiem(String id, String tenantId, String ownerId,
        String destination, int days, long rateCents) {
}
