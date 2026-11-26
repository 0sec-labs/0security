package com.ledger.notifications;

public record Notification(String id, String tenantId, String ownerId,
        String subject, String body, boolean read) {
}
