package com.ledger.approval;

public record Approval(String id, String tenantId, String expenseId, String requesterId, String status, String decidedBy) {

    public Approval decided(String newStatus, String approverId) {
        return new Approval(id, tenantId, expenseId, requesterId, newStatus, approverId);
    }
}
