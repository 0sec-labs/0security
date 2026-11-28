package com.ledger.billing;

import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/billing")
public class BillingController {

    private final BillingService service;

    public BillingController(BillingService service) {
        this.service = service;
    }

    @GetMapping("/plan")
    public Subscription plan(@RequestHeader("X-Tenant-Id") String tenantId) {
        return service.plan(tenantId);
    }

    @GetMapping("/invoices")
    public List<Invoice> invoices(@RequestHeader("X-Tenant-Id") String tenantId) {
        return service.invoices(tenantId);
    }
}
