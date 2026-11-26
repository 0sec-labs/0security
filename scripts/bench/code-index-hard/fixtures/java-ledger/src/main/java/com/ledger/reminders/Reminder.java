package com.ledger.reminders;

import java.time.LocalDate;

public record Reminder(String id, String tenantId, String ownerId,
        String title, LocalDate dueOn, boolean done) {
}
