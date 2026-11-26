package com.ledger.apikeys;

public record ApiKeyDto(String id,
        String label, String prefix, String scope) {
}
