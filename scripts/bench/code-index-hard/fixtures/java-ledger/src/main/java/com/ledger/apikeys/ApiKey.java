package com.ledger.apikeys;

public record ApiKey(String id, String tenantId, String ownerId,
        String label, String prefix, String scope) {
}
