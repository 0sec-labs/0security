package com.ledger.costcenters;

public record CostCenterDto(String id,
        String code, String name, String parentCode) {
}
