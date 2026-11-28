package com.ledger.expense;

import java.time.LocalDate;

public record Expense(String id, String tenantId, String ownerId, String projectId, String vendorId, String description,
                      long amountCents, String currency, String status, LocalDate incurredOn) {

    public Expense withProject(String newProjectId) {
        return new Expense(id, tenantId, ownerId, newProjectId, vendorId, description, amountCents, currency, status, incurredOn);
    }

    public Expense withStatus(String newStatus) {
        return new Expense(id, tenantId, ownerId, projectId, vendorId, description, amountCents, currency, newStatus, incurredOn);
    }
}
