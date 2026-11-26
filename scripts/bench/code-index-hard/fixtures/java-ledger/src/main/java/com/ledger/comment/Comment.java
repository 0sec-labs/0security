package com.ledger.comment;

import java.time.Instant;

public record Comment(String id, String tenantId, String expenseId, String authorId, String body, Instant createdAt) {
}
