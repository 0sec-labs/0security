package com.ledger.savedfilters;

public record SavedFilter(String id, String tenantId, String ownerId,
        String name, String query) {
}
