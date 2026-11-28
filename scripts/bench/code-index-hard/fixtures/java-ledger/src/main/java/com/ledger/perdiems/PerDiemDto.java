package com.ledger.perdiems;

public record PerDiemDto(String id,
        String destination, int days, long rateCents) {
}
