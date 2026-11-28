package com.ledger.webhooks;

public record Webhook(String id, String tenantId, String ownerId,
        String url, String event, boolean active) {
}
