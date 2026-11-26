package com.ledger.mileage;

import java.time.LocalDate;

public record MileageEntryDto(String id,
        String purpose, LocalDate tripDate, int distanceKm) {
}
