package com.ledger.security;

public record AuthUser(String id, String tenantId, Role role) {

    public boolean isManager() {
        return role == Role.MANAGER || role == Role.ADMIN;
    }
}
