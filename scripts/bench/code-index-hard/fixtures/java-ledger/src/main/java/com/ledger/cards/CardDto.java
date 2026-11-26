package com.ledger.cards;

public record CardDto(String id,
        String nickname, String last4, long limitCents,
        boolean frozen) {
}
