package com.ledger.contracts;

import java.time.LocalDate;

public record ContractDto(String id,
        String title, String counterparty, LocalDate startsOn,
        LocalDate endsOn, long valueCents) {
}
