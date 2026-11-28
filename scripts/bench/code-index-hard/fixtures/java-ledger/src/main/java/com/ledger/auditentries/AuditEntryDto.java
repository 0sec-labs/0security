package com.ledger.auditentries;

public record AuditEntryDto(String id,
        String action, String subject, String detail) {
}
