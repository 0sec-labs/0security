package com.ledger.notifications;

public record NotificationDto(String id,
        String subject, String body, boolean read) {
}
