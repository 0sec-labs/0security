package com.ledger.cards;

public record Card(String id, String tenantId, String ownerId,
        String nickname, String last4, long limitCents,
        boolean frozen) {
}
