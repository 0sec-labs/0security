package com.ledger.currencies;

public record Currency(String id, String tenantId, String ownerId,
        String code, String symbol, long rateMicros) {
}
