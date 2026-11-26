package com.ledger.user;

public record ProfileDto(String id, String email, String displayName, String role, String tenantId) {
}
