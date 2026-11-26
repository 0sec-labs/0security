package com.ledger.comment;

public record CommentInput(String tenantId, String expenseId, String authorId, String body) {

    public CommentInput forExpense(String newTenantId, String newExpenseId) {
        return new CommentInput(newTenantId, newExpenseId, authorId, body);
    }
}
