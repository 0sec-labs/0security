package com.ledger.tenant;

public record Tenant(String id, String name, String plan, int maxUsers, int maxExpensesPerMonth) {

    public Tenant withLimits(int newMaxUsers, int newMaxExpensesPerMonth) {
        return new Tenant(id, name, plan, newMaxUsers, newMaxExpensesPerMonth);
    }
}
