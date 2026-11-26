package com.ledger.billing;

import java.time.LocalDate;

public record Subscription(String tenantId, String plan, int seats, LocalDate renewsOn) {
}
