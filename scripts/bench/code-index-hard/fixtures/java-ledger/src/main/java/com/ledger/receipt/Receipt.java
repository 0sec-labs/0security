package com.ledger.receipt;

public record Receipt(String id, String tenantId, String expenseId, String fileName, String contentType, byte[] content,
                      String uploadedBy) {
}
