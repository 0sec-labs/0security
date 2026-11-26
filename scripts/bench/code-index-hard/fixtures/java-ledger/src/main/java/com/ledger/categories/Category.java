package com.ledger.categories;

public record Category(String id, String tenantId, String ownerId,
        String name, String color, boolean archived) {
}
