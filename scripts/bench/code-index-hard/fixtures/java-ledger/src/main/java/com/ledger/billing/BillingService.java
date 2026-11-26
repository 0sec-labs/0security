package com.ledger.billing;

import com.ledger.common.NotFoundException;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class BillingService {

    private final BillingRepository repository;

    public BillingService(BillingRepository repository) {
        this.repository = repository;
    }

    public Subscription plan(String tenantId) {
        return repository.subscriptionOf(tenantId).orElseThrow(() -> new NotFoundException("subscription"));
    }

    public List<Invoice> invoices(String tenantId) {
        return repository.invoicesOf(tenantId);
    }
}
