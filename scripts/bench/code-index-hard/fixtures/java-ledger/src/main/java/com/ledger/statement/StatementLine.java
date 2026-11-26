package com.ledger.statement;

import java.time.LocalDate;

public record StatementLine(LocalDate date, String description, long amountCents) {
}
