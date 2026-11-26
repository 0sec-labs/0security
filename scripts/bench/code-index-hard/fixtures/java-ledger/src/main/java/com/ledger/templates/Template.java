package com.ledger.templates;

public record Template(String id, String tenantId, String ownerId,
        String name, String kind, String body) {
}
