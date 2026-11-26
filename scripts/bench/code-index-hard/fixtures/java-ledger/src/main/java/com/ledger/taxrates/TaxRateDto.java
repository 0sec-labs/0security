package com.ledger.taxrates;

public record TaxRateDto(String id,
        String name, int percentBp, String region) {
}
