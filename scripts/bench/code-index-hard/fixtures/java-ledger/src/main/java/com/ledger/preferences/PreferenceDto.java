package com.ledger.preferences;

public record PreferenceDto(String id,
        String locale, String timezone, boolean digest) {
}
