package com.ledger.contracts;

import java.time.LocalDate;

public record Contract(String id, String tenantId, String ownerId,
        String title, String counterparty, LocalDate startsOn,
        LocalDate endsOn, long valueCents) {
}
