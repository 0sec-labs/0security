package com.ledger.taxrates;

public record TaxRate(String id, String tenantId, String ownerId,
        String name, int percentBp, String region) {
}
