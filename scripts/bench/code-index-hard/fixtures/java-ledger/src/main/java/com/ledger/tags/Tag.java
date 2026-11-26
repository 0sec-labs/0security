package com.ledger.tags;

public record Tag(String id, String tenantId, String ownerId,
        String label, String color) {
}
