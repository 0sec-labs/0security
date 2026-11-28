package com.ledger.departments;

public record Department(String id, String tenantId, String ownerId,
        String name, String code, int headcount) {
}
