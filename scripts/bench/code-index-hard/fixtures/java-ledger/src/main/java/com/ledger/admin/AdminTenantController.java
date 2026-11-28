package com.ledger.admin;

import com.ledger.security.AuthUser;
import com.ledger.tenant.Tenant;
import java.util.List;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/tenants")
public class AdminTenantController {

    private final AdminService service;

    public AdminTenantController(AdminService service) {
        this.service = service;
    }

    @GetMapping
    public List<Tenant> list(@AuthenticationPrincipal AuthUser user) {
        return service.listTenants(user);
    }

    @PutMapping("/{id}/limits")
    public Tenant updateLimits(@AuthenticationPrincipal AuthUser user, @PathVariable String id, @RequestBody TenantLimits limits) {
        return service.updateLimits(user, id, limits);
    }
}
