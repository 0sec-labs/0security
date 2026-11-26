package com.ledger.reports;

public record Report(String id, String tenantId, String ownerId,
        String title, String kind, String parameters) {
}
