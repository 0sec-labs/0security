package com.ledger.auditentries;

public record AuditEntry(String id, String tenantId, String ownerId,
        String action, String subject, String detail) {
}
