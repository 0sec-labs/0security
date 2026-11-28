package com.ledger.notes;

public record Note(String id, String tenantId, String ownerId,
        String body, String linkedExpenseId) {
}
