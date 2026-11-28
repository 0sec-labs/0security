package com.ledger.webhooks;

public record WebhookDto(String id,
        String url, String event, boolean active) {
}
