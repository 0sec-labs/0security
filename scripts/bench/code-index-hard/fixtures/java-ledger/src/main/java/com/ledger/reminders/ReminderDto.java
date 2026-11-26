package com.ledger.reminders;

import java.time.LocalDate;

public record ReminderDto(String id,
        String title, LocalDate dueOn, boolean done) {
}
