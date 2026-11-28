package com.ledger.statement;

import java.util.List;

public record StatementView(String id, String period, long openingCents, long closingCents, List<StatementLine> lines) {
}
