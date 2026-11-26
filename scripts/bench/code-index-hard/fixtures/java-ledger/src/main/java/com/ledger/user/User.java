package com.ledger.user;

import com.ledger.security.Role;

public record User(String id, String tenantId, String email, String displayName, Role role, boolean active) {

    public User withRole(Role newRole) {
        return new User(id, tenantId, email, displayName, newRole, active);
    }

    public User withActive(boolean newActive) {
        return new User(id, tenantId, email, displayName, role, newActive);
    }

    public User withDisplayName(String newName) {
        return new User(id, tenantId, email, newName, role, active);
    }
}
