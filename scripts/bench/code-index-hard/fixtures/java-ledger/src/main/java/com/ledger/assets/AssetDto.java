package com.ledger.assets;

import java.time.LocalDate;

public record AssetDto(String id,
        String label, String serialNumber, LocalDate purchasedOn,
        long valueCents) {
}
