package com.ledger.vendor;

public record Vendor(String id, String tenantId, String name, String category, String taxId, String status, BankDetails bank) {

    public Vendor withStatus(String newStatus) {
        return new Vendor(id, tenantId, name, category, taxId, newStatus, bank);
    }

    public Vendor withBank(BankDetails newBank) {
        return new Vendor(id, tenantId, name, category, taxId, status, newBank);
    }
}
