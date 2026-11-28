package com.ledger.receipt;

public record ReceiptMeta(String id, String expenseId, String fileName, String contentType, int size) {
}
