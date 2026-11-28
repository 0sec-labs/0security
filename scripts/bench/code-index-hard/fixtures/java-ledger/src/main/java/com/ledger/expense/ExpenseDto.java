package com.ledger.expense;

import java.time.LocalDate;

public record ExpenseDto(String id, String projectId, String vendorId, String description, long amountCents,
                         String currency, String status, LocalDate incurredOn) {
}
