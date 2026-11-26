package com.ledger.mileage;

import java.time.LocalDate;

public record MileageEntry(String id, String tenantId, String ownerId,
        String purpose, LocalDate tripDate, int distanceKm) {
}
