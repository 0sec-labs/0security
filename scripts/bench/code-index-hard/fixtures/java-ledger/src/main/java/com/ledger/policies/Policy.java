package com.ledger.policies;

public record Policy(String id, String tenantId, String ownerId,
        String name, String ruleKind, long limitCents,
        boolean active) {
}
