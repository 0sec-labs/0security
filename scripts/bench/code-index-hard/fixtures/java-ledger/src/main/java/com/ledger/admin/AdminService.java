package com.ledger.admin;

import com.ledger.common.Access;
import com.ledger.common.NotFoundException;
import com.ledger.expense.ExpenseRepository;
import com.ledger.security.AuthUser;
import com.ledger.security.Role;
import com.ledger.tenant.Tenant;
import com.ledger.tenant.TenantRepository;
import com.ledger.user.User;
import com.ledger.user.UserRepository;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class AdminService {

    private final UserRepository users;
    private final TenantRepository tenants;
    private final ExpenseRepository expenses;

    public AdminService(UserRepository users, TenantRepository tenants, ExpenseRepository expenses) {
        this.users = users;
        this.tenants = tenants;
        this.expenses = expenses;
    }

    public List<User> listUsers(AuthUser actor) {
        return users.findByTenant(actor.tenantId());
    }

    public User changeRole(AuthUser actor, String userId, Role role) {
        User target = users.findById(userId).orElseThrow(() -> new NotFoundException("user"));
        Access.requireTenant(actor, target.tenantId());
        return users.save(target.withRole(role));
    }

    public User deactivate(AuthUser actor, String userId) {
        User target = users.findById(userId).orElseThrow(() -> new NotFoundException("user"));
        Access.requireTenant(actor, target.tenantId());
        return users.save(target.withActive(false));
    }

    public List<Tenant> listTenants(AuthUser actor) {
        return tenants.findById(actor.tenantId()).map(List::of).orElse(List.of());
    }

    public Tenant updateLimits(AuthUser actor, String tenantId, TenantLimits limits) {
        Access.requireTenant(actor, tenantId);
        Tenant tenant = tenants.findById(tenantId).orElseThrow(() -> new NotFoundException("tenant"));
        return tenants.save(tenant.withLimits(limits.maxUsers(), limits.maxExpensesPerMonth()));
    }

    public Map<String, Integer> stats(AuthUser actor) {
        return Map.of("users", users.findByTenant(actor.tenantId()).size(),
                "expenses", expenses.findByTenant(actor.tenantId()).size());
    }
}
