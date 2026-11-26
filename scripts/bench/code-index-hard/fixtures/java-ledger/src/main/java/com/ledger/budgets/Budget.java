package com.ledger.budgets;

import java.time.LocalDate;

public record Budget(String id, String tenantId, String ownerId,
        String name, LocalDate periodStart, long limitCents,
        long spentCents) {
}
