package com.ledger.export;

public record ExportJob(String id, String tenantId, String ownerId, String name, String path, int rows) {
}
