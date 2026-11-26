package com.ledger.billing;

import java.time.LocalDate;

public record Invoice(String id, String tenantId, String number, long amountCents, String status, LocalDate issuedOn) {
}
