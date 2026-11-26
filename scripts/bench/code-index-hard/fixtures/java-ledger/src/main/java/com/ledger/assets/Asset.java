package com.ledger.assets;

import java.time.LocalDate;

public record Asset(String id, String tenantId, String ownerId,
        String label, String serialNumber, LocalDate purchasedOn,
        long valueCents) {
}
