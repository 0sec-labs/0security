package com.ledger.billing;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

@Repository
public class BillingRepository {

    private final Map<String, Subscription> subscriptions = new ConcurrentHashMap<>();
    private final Map<String, Invoice> invoices = new ConcurrentHashMap<>();

    public Subscription save(Subscription subscription) {
        subscriptions.put(subscription.tenantId(), subscription);
        return subscription;
    }

    public Invoice save(Invoice invoice) {
        invoices.put(invoice.id(), invoice);
        return invoice;
    }

    public Optional<Subscription> subscriptionOf(String tenantId) {
        return Optional.ofNullable(subscriptions.get(tenantId));
    }

    public List<Invoice> invoicesOf(String tenantId) {
        return invoices.values().stream()
                .filter(i -> i.tenantId().equals(tenantId))
                .sorted(Comparator.comparing(Invoice::number))
                .toList();
    }
}
