package com.ledger.costcenters;

public record CostCenter(String id, String tenantId, String ownerId,
        String code, String name, String parentCode) {
}
