package com.ledger.policies;

public record PolicyDto(String id,
        String name, String ruleKind, long limitCents,
        boolean active) {
}
