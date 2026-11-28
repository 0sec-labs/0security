package com.ledger.budgets;

import java.time.LocalDate;

public record BudgetDto(String id,
        String name, LocalDate periodStart, long limitCents,
        long spentCents) {
}
