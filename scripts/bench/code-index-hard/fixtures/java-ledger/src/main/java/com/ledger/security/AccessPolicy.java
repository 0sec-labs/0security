package com.ledger.security;

import org.springframework.stereotype.Component;

/**
 * Named policy checks used from method security expressions as @access.
 */
@Component("access")
public class AccessPolicy {

    public boolean canManage(String tenantId) {
        AuthUser user = CurrentUser.get();
        return user != null && user.isManager() && user.tenantId().equals(tenantId);
    }

    public boolean sameTenant(String tenantId) {
        AuthUser user = CurrentUser.get();
        return user != null && user.tenantId().equals(tenantId);
    }

    public boolean isManager() {
        AuthUser user = CurrentUser.get();
        return user != null && user.isManager();
    }
}
