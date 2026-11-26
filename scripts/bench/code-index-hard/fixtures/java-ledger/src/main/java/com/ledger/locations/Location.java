package com.ledger.locations;

public record Location(String id, String tenantId, String ownerId,
        String name, String city, String country) {
}
