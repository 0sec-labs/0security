package com.ledger.preferences;

public record Preference(String id, String tenantId, String ownerId,
        String locale, String timezone, boolean digest) {
}
