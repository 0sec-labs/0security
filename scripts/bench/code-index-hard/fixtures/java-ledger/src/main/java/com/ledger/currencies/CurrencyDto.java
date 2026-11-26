package com.ledger.currencies;

public record CurrencyDto(String id,
        String code, String symbol, long rateMicros) {
}
