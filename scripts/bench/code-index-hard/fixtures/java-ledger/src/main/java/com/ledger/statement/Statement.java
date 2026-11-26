package com.ledger.statement;

import java.util.List;

public record Statement(String id, String tenantId, String ownerId, String period, long openingCents, long closingCents,
                        List<StatementLine> lines) {
}
