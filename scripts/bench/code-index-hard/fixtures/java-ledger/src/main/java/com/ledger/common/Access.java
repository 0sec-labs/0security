package com.ledger.common;

import com.ledger.security.AuthUser;

/**
 * Small guards shared by the services. Not found is used for another tenant's records so ids do not leak.
 */
public final class Access {

    private Access() {
    }

    public static void requireTenant(AuthUser user, String tenantId) {
        if (tenantId == null || !tenantId.equals(user.tenantId())) {
            throw new NotFoundException("record");
        }
    }

    public static void requireOwnerOrManager(AuthUser user, String ownerId) {
        if (!user.isManager() && !user.id().equals(ownerId)) {
            throw new ForbiddenException("not allowed");
        }
    }

    public static void requireOwner(AuthUser user, String ownerId) {
        if (!user.id().equals(ownerId)) {
            throw new ForbiddenException("not allowed");
        }
    }

    public static void requireManager(AuthUser user) {
        if (!user.isManager()) {
            throw new ForbiddenException("manager role required");
        }
    }
}
